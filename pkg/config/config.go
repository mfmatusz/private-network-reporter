// Package config handles application configuration with validation
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Runtime
	Enabled    bool          // Global scan enable switch
	Addr       string        // Listen address (e.g., :8080)
	EventToken string        // SHA512 shared secret for /events and /arp/harvest (RouterOS)
	AdminToken string        // Token for /admin/* endpoints (X-Admin-Token header)
	DBPath     string        // SQLite database path (e.g., /data/nmap.db)
	TZ         string        // Timezone (e.g., Europe/Warsaw)
	MaxWorkers int           // Number of concurrent scan workers (default: 2)
	QueueSize  int           // Scan queue buffer size (default: 512)
	Cooldown   time.Duration // Minimum interval between scans per-MAC (e.g., 20m)
	// TLS/HTTPS
	TLSEnabled  bool   // Enable HTTPS instead of HTTP
	TLSCertPath string // Path to cert.pem (auto-generate if missing)
	TLSKeyPath  string // Path to key.pem (auto-generate if missing)

	// Rate Limiting
	RateLimitEnabled bool // Enable rate limiting for all admin endpoints

	// Scan
	ScanMode      string        // "raw" (sS) or "basic" (sT)
	AutoScanLevel string        // Auto-scan depth: "basic" (fast), "deep" (NSE), "deepsafe" (safe scripts), "custom" - affects timeout
	HostPorts     []string      // Default port list to scan
	TimeoutBasic  time.Duration // Timeout for basic scans (default: 60s)
	TimeoutDeep   time.Duration // Timeout for deep/deepsafe scans (default: 300s)
	TimeoutCustom time.Duration // Timeout for custom scans (default: 300s)
	CustomScripts string        // NSE scripts for "custom" scan level (e.g., "http-title,ssh-hostkey")

	// Reports
	DailyReportTime string        // Time for daily report generation (HH:MM format)
	ReportWindow    time.Duration // Time window for report data collection (e.g., 24h, 48h, 7d)
	ReportDetail    string        // Report detail level: "summary" or "detailed"
	SMTPHost        string        // SMTP server hostname
	SMTPPort        string        // SMTP server port
	SMTPUser        string        // SMTP username
	SMTPPass        string        // SMTP password
	SMTPFrom        string        // Email sender address
	SMTPTo          []string      // Email recipient addresses
	SMTPStartTLS    bool          // Use STARTTLS for SMTP

	// Discovery
	ARPHarvestAllow     bool          // Allow /arp/harvest endpoint (RouterOS push)
	ARPIngesterEnabled  bool          // Enable local ARP table monitoring (/proc/net/arp)
	ARPIngesterInterval time.Duration // Interval for ARP table parsing (default: 1 minute)
}

// Load reads configuration from environment variables with sensible defaults
func Load() (*Config, error) {
	portsCSV := getenv("HOST_PORTS", "22,80,443,445,3389")
	ports := parseCSVPorts(portsCSV, []string{"22", "80", "443"})

	cfg := &Config{
		// Runtime
		Enabled:    getbool("ENABLED", true),
		Addr:       ":" + getenv("PORT", "8080"),
		EventToken: getenv("EVENT_TOKEN", ""),
		AdminToken: getenv("ADMIN_TOKEN", ""),
		DBPath:     getenv("DB_PATH", "/data/nmap.db"),
		TZ:         getenv("TZ", "Europe/Warsaw"),
		MaxWorkers: getint("MAX_WORKERS", 2),
		QueueSize:  getint("QUEUE_SIZE", 512),
		Cooldown:   getdur("COOLDOWN", 20*time.Minute),

		// TLS
		// for thesis purposes, TLS is enabled by default - in production it depends on user preference
		TLSEnabled:  getbool("TLS_ENABLED", true),
		TLSCertPath: getenv("TLS_CERT_PATH", "/data/cert.pem"),
		TLSKeyPath:  getenv("TLS_KEY_PATH", "/data/key.pem"),

		// Rate Limiting
		RateLimitEnabled: getbool("RATE_LIMIT_ENABLED", true),

		// Scan
		ScanMode:      getenv("SCAN_MODE", "basic"),
		AutoScanLevel: getenv("AUTO_SCAN_LEVEL", "basic"),
		HostPorts:     ports,
		TimeoutBasic:  getdur("TIMEOUT_BASIC", 60*time.Second),
		TimeoutDeep:   getdur("TIMEOUT_DEEP", 300*time.Second),
		TimeoutCustom: getdur("TIMEOUT_CUSTOM", 300*time.Second),
		CustomScripts: getenv("CUSTOM_SCRIPTS", ""),

		// Reports
		DailyReportTime: getenv("DAILY_REPORT_TIME", "23:59"),
		ReportWindow:    getdur("REPORT_WINDOW", 24*time.Hour),
		ReportDetail:    getenv("REPORT_DETAIL", "summary"),
		SMTPHost:        getenv("SMTP_HOST", ""),
		SMTPPort:        getenv("SMTP_PORT", ""),
		SMTPUser:        getenv("SMTP_USER", ""),
		SMTPPass:        getenv("SMTP_PASS", ""),
		SMTPFrom:        getenv("SMTP_FROM", ""),
		SMTPTo:          splitCSV(getenv("SMTP_TO", "")),
		// for thesis puproses, Google SMTP is used which requires STARTTLS (it enforces STARTTLS, so "false" is ignored)
		SMTPStartTLS: getbool("SMTP_STARTTLS", false),

		// Discovery
		ARPHarvestAllow:     getbool("ARP_HARVEST_ALLOW", true),
		ARPIngesterEnabled:  getbool("ARP_INGESTER_ENABLED", false),
		ARPIngesterInterval: getdur("ARP_INGESTER_INTERVAL", 1*time.Minute),
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate checks configuration for correctness
func (c *Config) Validate() error {
	// Security: tokens must be set and long enough
	if c.AdminToken == "" {
		return fmt.Errorf("ADMIN_TOKEN is required but not set")
	}
	if len(c.AdminToken) < 16 {
		return fmt.Errorf("ADMIN_TOKEN must be at least 16 characters long, got %d", len(c.AdminToken))
	}
	if c.EventToken != "" && len(c.EventToken) < 16 {
		return fmt.Errorf("EVENT_TOKEN must be at least 16 characters long, got %d", len(c.EventToken))
	}

	// Runtime limits
	if c.MaxWorkers < 1 || c.MaxWorkers > 16 {
		return fmt.Errorf("MAX_WORKERS must be between 1 and 16, got %d", c.MaxWorkers)
	}
	if c.QueueSize < 16 || c.QueueSize > 4096 {
		return fmt.Errorf("QUEUE_SIZE must be between 16 and 4096, got %d", c.QueueSize)
	}
	if c.Cooldown < 0 {
		return fmt.Errorf("COOLDOWN cannot be negative, got %s", c.Cooldown)
	}

	// Scan mode
	if c.ScanMode != "raw" && c.ScanMode != "basic" {
		return fmt.Errorf("SCAN_MODE must be 'raw' or 'basic', got %q", c.ScanMode)
	}
	if c.AutoScanLevel != "basic" && c.AutoScanLevel != "deep" && c.AutoScanLevel != "deepsafe" {
		return fmt.Errorf("AUTO_SCAN_LEVEL must be 'basic', 'deep', or 'deepsafe', got %q", c.AutoScanLevel)
	}

	// Report detail
	if c.ReportDetail != "summary" && c.ReportDetail != "detailed" {
		return fmt.Errorf("REPORT_DETAIL must be 'summary' or 'detailed', got %q", c.ReportDetail)
	}

	// Daily report time format
	if len(c.DailyReportTime) != 5 || c.DailyReportTime[2] != ':' {
		return fmt.Errorf("DAILY_REPORT_TIME must be in HH:MM format, got %q", c.DailyReportTime)
	}

	// Report window validation
	if c.ReportWindow < 1*time.Hour {
		return fmt.Errorf("REPORT_WINDOW must be at least 1 hour, got %s", c.ReportWindow)
	}
	if c.ReportWindow > 30*24*time.Hour {
		return fmt.Errorf("REPORT_WINDOW cannot exceed 30 days, got %s", c.ReportWindow)
	}

	return nil
}

// Helper functions for environment variable parsing

func getenv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getbool(key string, defaultValue bool) bool {
	v := strings.ToLower(os.Getenv(key))
	if v == "" {
		return defaultValue
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func getint(key string, defaultValue int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	if i, err := strconv.Atoi(v); err == nil {
		return i
	}
	return defaultValue
}

func getfloat(key string, defaultValue float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f
	}
	return defaultValue
}

func getdur(key string, defaultValue time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return defaultValue
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var result []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseCSVPorts(s string, defaultPorts []string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultPorts
	}
	var result []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Validate it's a number
		if _, err := strconv.Atoi(p); err == nil {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return defaultPorts
	}
	return result
}
