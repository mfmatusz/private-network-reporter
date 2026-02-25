package security

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// AdminRateLimiter provides rate limiting for admin operations
// Separate from scan rate limiter to allow different policies
type AdminRateLimiter struct {
	enabled    bool
	limiters   map[string]*rateLimitConfig
	limitersMu sync.Mutex
}

type rateLimitConfig struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// AdminEndpointLimits defines rate limits for different admin operations
type AdminEndpointLimits struct {
	Scan           float64 // requests per minute for /admin/scan (nmap execution)
	Repair         float64 // requests per minute for /admin/repair (VACUUM)
	ReportGenerate float64 // requests per minute for /admin/report/generate
	Rescan         float64 // requests per minute for /admin/rescan
}

// DefaultAdminLimits provides sensible defaults for admin operations
var DefaultAdminLimits = AdminEndpointLimits{
	Scan:           10.0, // 10 requests per minute (nmap execution is resource-intensive)
	Repair:         1.0,  // 1 request per minute (VACUUM is expensive)
	ReportGenerate: 2.0,  // 2 requests per minute (10 per 5 min, report generation is expensive)
	Rescan:         20.0, // 20 requests per minute (queue operations are cheap)
}

// NewAdminRateLimiter creates a new admin rate limiter
func NewAdminRateLimiter(enabled bool) *AdminRateLimiter {
	return &AdminRateLimiter{
		enabled:  enabled,
		limiters: make(map[string]*rateLimitConfig),
	}
}

// Allow checks if request from given IP should be allowed for specific limit
func (arl *AdminRateLimiter) Allow(ip string, perMinute float64) bool {
	if !arl.enabled {
		return true
	}

	limiter := arl.getLimiter(ip, perMinute)
	return limiter.Allow()
}

// Reserve reserves a token and returns delay until available
func (arl *AdminRateLimiter) Reserve(ip string, perMinute float64) time.Duration {
	limiter := arl.getLimiter(ip, perMinute)
	return limiter.Reserve().Delay()
}

// getLimiter returns a rate limiter for the given IP and rate
func (arl *AdminRateLimiter) getLimiter(ip string, perMinute float64) *rate.Limiter {
	arl.limitersMu.Lock()
	defer arl.limitersMu.Unlock()

	// Cleanup old limiters (prevent memory leak)
	now := time.Now()
	if len(arl.limiters) > 500 {
		for k, cfg := range arl.limiters {
			// Remove limiters unused for >10 minutes
			if now.Sub(cfg.lastUsed) > 10*time.Minute {
				delete(arl.limiters, k)
			}
		}
		log.Printf("admin-rate-limiter: cleaned up old limiters, remaining: %d", len(arl.limiters))
	}

	key := fmt.Sprintf("%s:%.4f", ip, perMinute)
	cfg, exists := arl.limiters[key]
	if !exists {
		// Create new limiter: perMinute requests per minute
		rps := rate.Limit(perMinute / 60.0)
		burst := max(1, int(perMinute))
		limiter := rate.NewLimiter(rps, burst)
		// Reserve burst tokens at past time so first request is allowed immediately
		// This fixes the issue where rate.Limiter starts with empty bucket for low rps
		limiter.ReserveN(time.Now().Add(-time.Hour), burst)
		cfg = &rateLimitConfig{
			limiter:  limiter,
			lastUsed: now,
		}
		arl.limiters[key] = cfg
	}

	cfg.lastUsed = now
	return cfg.limiter
}

// Middleware returns HTTP middleware for admin rate limiting
func (arl *AdminRateLimiter) Middleware(perMinute float64, operation string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !arl.enabled {
				next(w, r)
				return
			}

			// Extract IP from RemoteAddr
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr // Fallback if no port
			}

			if !arl.Allow(ip, perMinute) {
				retryAfter := arl.Reserve(ip, perMinute)
				log.Printf("admin-rate-limit: blocked %s from %s (limit: %.2f/min)", operation, ip, perMinute)

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"error":"rate limit exceeded for %s","limit_per_min":%.2f,"retry_after_ms":%d}`,
					operation,
					perMinute,
					retryAfter.Milliseconds())
				return
			}

			next(w, r)
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
