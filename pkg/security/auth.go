// Package security provides authentication and rate limiting
package security

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Authenticator handles token-based authentication
type Authenticator struct {
	adminToken string
	eventToken string

	// Replay protection for RouterOS webhooks
	lastTimestampMu sync.Mutex
	lastTimestamp   map[string]string // RouterOS IP -> last seen timestamp
}

// NewAuthenticator creates a new authenticator with given tokens
func NewAuthenticator(adminToken, eventToken string) *Authenticator {
	return &Authenticator{
		adminToken:    adminToken,
		eventToken:    eventToken,
		lastTimestamp: make(map[string]string),
	}
}

// ValidateAdminToken checks if the X-Admin-Token header matches
func (a *Authenticator) ValidateAdminToken(r *http.Request) bool {
	if a.adminToken == "" {
		return false
	}
	token := r.Header.Get("X-Admin-Token")
	return subtle.ConstantTimeCompare([]byte(token), []byte(a.adminToken)) == 1
}

// ValidateSHA512Signature verifies RouterOS webhook signature
// RouterOS sends: SHA512(body + secret + timestamp)
func (a *Authenticator) ValidateSHA512Signature(r *http.Request, body []byte) bool {
	if a.eventToken == "" {
		return false
	}

	// Extract signature and timestamp from headers
	receivedSig := r.Header.Get("X-Auth-Signature")
	timestampStr := r.Header.Get("X-Auth-Timestamp")

	if receivedSig == "" || timestampStr == "" {
		return false
	}

	// Parse RouterOS timestamp (duration format from Unix epoch)
	timestamp, err := parseRouterOSTimestamp(timestampStr)
	if err != nil {
		log.Printf("security: failed to parse timestamp %q: %v", timestampStr, err)
		return false
	}

	// Check timestamp is within acceptable range (not older than 1 minute, not from future (30 seconds drift permitted))
	now := time.Now().Unix()
	age := now - timestamp
	if age > 60 || age < -30 {
		log.Printf("security: timestamp out of range (age: %ds, max=60s)", age)
		return false
	}

	// Replay protection: ensure timestamp is newer than last seen from this IP
	routerIP, _, _ := net.SplitHostPort(r.RemoteAddr) // Extract IP only, ignore port
	if routerIP == "" {
		routerIP = r.RemoteAddr // Fallback if no port in address
	}
	a.lastTimestampMu.Lock()
	lastSeen, exists := a.lastTimestamp[routerIP]
	if exists && timestampStr <= lastSeen {
		a.lastTimestampMu.Unlock()
		log.Printf("security: replay detected from %s (timestamp: %s <= %s)", routerIP, timestampStr, lastSeen)
		return false
	}
	a.lastTimestamp[routerIP] = timestampStr
	a.lastTimestampMu.Unlock()

	// Compute expected signature: SHA512(body + secret + timestamp)
	data := string(body) + a.eventToken + timestampStr
	hash := sha512.Sum512([]byte(data))
	expectedSig := hex.EncodeToString(hash[:])

	// Constant-time comparison
	return subtle.ConstantTimeCompare([]byte(receivedSig), []byte(expectedSig)) == 1
}

// parseRouterOSTimestamp parses RouterOS [:timestamp] format
// Format: [weeks]w[days]d[hours]:[minutes]:[seconds].[nanoseconds]
// Example: "2915w1d09:10:02.449936265" or "2925w13:38:18.048259327"
// Returns Unix timestamp in seconds
func parseRouterOSTimestamp(ts string) (int64, error) {
	var weeks, days, hours, mins int64
	var secFloat float64

	// Try different format variants - use fresh variables each time to avoid pollution
	var n int

	// Try: weeks + days + time (e.g., "2925w1d15:00:43.633")
	w1, d1, h1, m1, s1 := int64(0), int64(0), int64(0), int64(0), float64(0)
	if n, _ = fmt.Sscanf(ts, "%dw%dd%d:%d:%f", &w1, &d1, &h1, &m1, &s1); n == 5 {
		weeks, days, hours, mins, secFloat = w1, d1, h1, m1, s1
	} else {
		// Try: weeks + time without days (e.g., "2925w15:00:43.633")
		w2, h2, m2, s2 := int64(0), int64(0), int64(0), float64(0)
		if n, _ = fmt.Sscanf(ts, "%dw%d:%d:%f", &w2, &h2, &m2, &s2); n == 4 {
			weeks, days, hours, mins, secFloat = w2, 0, h2, m2, s2
		} else {
			// Try: days + time without weeks (e.g., "1d15:00:43.633")
			d3, h3, m3, s3 := int64(0), int64(0), int64(0), float64(0)
			if n, _ = fmt.Sscanf(ts, "%dd%d:%d:%f", &d3, &h3, &m3, &s3); n == 4 {
				weeks, days, hours, mins, secFloat = 0, d3, h3, m3, s3
			} else {
				// Try: just time (e.g., "15:00:43.633")
				h4, m4, s4 := int64(0), int64(0), float64(0)
				if n, _ = fmt.Sscanf(ts, "%d:%d:%f", &h4, &m4, &s4); n == 3 {
					weeks, days, hours, mins, secFloat = 0, 0, h4, m4, s4
				} else {
					return 0, fmt.Errorf("cannot parse RouterOS timestamp format: %q", ts)
				}
			}
		}
	}

	secs := int64(secFloat)

	// Convert to seconds from epoch
	totalSecs := weeks*7*24*3600 + days*24*3600 + hours*3600 + mins*60 + secs
	return totalSecs, nil
}
