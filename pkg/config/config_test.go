package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/config"
)

// validConfig returns a Config struct that passes Validate().
func validConfig() *config.Config {
	return &config.Config{
		AdminToken:      "this-is-16-chars",
		MaxWorkers:      2,
		QueueSize:       512,
		Cooldown:        20 * time.Minute,
		ScanMode:        "basic",
		AutoScanLevel:   "basic",
		ReportDetail:    "summary",
		DailyReportTime: "23:59",
		ReportWindow:    24 * time.Hour,
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		if err := validConfig().Validate(); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("empty AdminToken", func(t *testing.T) {
		cfg := validConfig()
		cfg.AdminToken = ""
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN is required") {
			t.Errorf("expected ADMIN_TOKEN required error, got: %v", err)
		}
	})

	t.Run("AdminToken shorter than 16 chars", func(t *testing.T) {
		cfg := validConfig()
		cfg.AdminToken = "short"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN must be at least 16 characters") {
			t.Errorf("expected ADMIN_TOKEN length error, got: %v", err)
		}
	})

	t.Run("EventToken set but shorter than 16 chars", func(t *testing.T) {
		cfg := validConfig()
		cfg.EventToken = "tooshort"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "EVENT_TOKEN must be at least 16 characters") {
			t.Errorf("expected EVENT_TOKEN length error, got: %v", err)
		}
	})

	t.Run("MaxWorkers = 0", func(t *testing.T) {
		cfg := validConfig()
		cfg.MaxWorkers = 0
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "MAX_WORKERS") {
			t.Errorf("expected MAX_WORKERS error, got: %v", err)
		}
	})

	t.Run("MaxWorkers = 17", func(t *testing.T) {
		cfg := validConfig()
		cfg.MaxWorkers = 17
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "MAX_WORKERS") {
			t.Errorf("expected MAX_WORKERS error, got: %v", err)
		}
	})

	t.Run("QueueSize = 15", func(t *testing.T) {
		cfg := validConfig()
		cfg.QueueSize = 15
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "QUEUE_SIZE") {
			t.Errorf("expected QUEUE_SIZE error, got: %v", err)
		}
	})

	t.Run("QueueSize = 4097", func(t *testing.T) {
		cfg := validConfig()
		cfg.QueueSize = 4097
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "QUEUE_SIZE") {
			t.Errorf("expected QUEUE_SIZE error, got: %v", err)
		}
	})

	t.Run("negative Cooldown", func(t *testing.T) {
		cfg := validConfig()
		cfg.Cooldown = -1 * time.Second
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "COOLDOWN") {
			t.Errorf("expected COOLDOWN error, got: %v", err)
		}
	})

	t.Run("invalid ScanMode", func(t *testing.T) {
		cfg := validConfig()
		cfg.ScanMode = "stealth"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "SCAN_MODE") {
			t.Errorf("expected SCAN_MODE error, got: %v", err)
		}
	})

	t.Run("invalid AutoScanLevel", func(t *testing.T) {
		cfg := validConfig()
		cfg.AutoScanLevel = "ultra"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "AUTO_SCAN_LEVEL") {
			t.Errorf("expected AUTO_SCAN_LEVEL error, got: %v", err)
		}
	})

	// "custom" is not a valid AutoScanLevel per the code (only basic/deep/deepsafe are valid)
	t.Run("AutoScanLevel custom is invalid", func(t *testing.T) {
		cfg := validConfig()
		cfg.AutoScanLevel = "custom"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "AUTO_SCAN_LEVEL") {
			t.Errorf("expected AUTO_SCAN_LEVEL error for 'custom', got: %v", err)
		}
	})

	t.Run("invalid ReportDetail", func(t *testing.T) {
		cfg := validConfig()
		cfg.ReportDetail = "verbose"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "REPORT_DETAIL") {
			t.Errorf("expected REPORT_DETAIL error, got: %v", err)
		}
	})

	t.Run("invalid DailyReportTime format", func(t *testing.T) {
		cfg := validConfig()
		cfg.DailyReportTime = "2359"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "DAILY_REPORT_TIME") {
			t.Errorf("expected DAILY_REPORT_TIME error, got: %v", err)
		}
	})

	t.Run("ReportWindow less than 1h", func(t *testing.T) {
		cfg := validConfig()
		cfg.ReportWindow = 30 * time.Minute
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "REPORT_WINDOW") {
			t.Errorf("expected REPORT_WINDOW error, got: %v", err)
		}
	})

	t.Run("ReportWindow more than 30 days", func(t *testing.T) {
		cfg := validConfig()
		cfg.ReportWindow = 31 * 24 * time.Hour
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "REPORT_WINDOW") {
			t.Errorf("expected REPORT_WINDOW error, got: %v", err)
		}
	})
}

func TestLoad_Defaults(t *testing.T) {
	// Unset all env vars that Load() reads so defaults apply.
	envVars := []string{
		"ENABLED", "PORT", "EVENT_TOKEN", "DB_PATH", "TZ",
		"MAX_WORKERS", "QUEUE_SIZE", "COOLDOWN",
		"TLS_ENABLED", "TLS_CERT_PATH", "TLS_KEY_PATH",
		"RATE_LIMIT_ENABLED", "SCAN_MODE", "AUTO_SCAN_LEVEL",
		"HOST_PORTS", "TIMEOUT_BASIC", "TIMEOUT_DEEP", "TIMEOUT_CUSTOM", "CUSTOM_SCRIPTS",
		"DAILY_REPORT_TIME", "REPORT_WINDOW", "REPORT_DETAIL",
		"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM", "SMTP_TO", "SMTP_STARTTLS",
		"ARP_HARVEST_ALLOW", "ARP_INGESTER_ENABLED", "ARP_INGESTER_INTERVAL",
	}
	for _, k := range envVars {
		t.Setenv(k, "")
	}
	t.Setenv("ADMIN_TOKEN", "this-is-16-chars")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Addr != ":8080" {
		t.Errorf("expected Addr :8080, got %q", cfg.Addr)
	}
	if cfg.MaxWorkers != 2 {
		t.Errorf("expected MaxWorkers 2, got %d", cfg.MaxWorkers)
	}
	if cfg.QueueSize != 512 {
		t.Errorf("expected QueueSize 512, got %d", cfg.QueueSize)
	}
	if !cfg.TLSEnabled {
		t.Errorf("expected TLSEnabled true by default")
	}
	if !cfg.RateLimitEnabled {
		t.Errorf("expected RateLimitEnabled true by default")
	}
	if cfg.ScanMode != "basic" {
		t.Errorf("expected ScanMode 'basic', got %q", cfg.ScanMode)
	}
	if cfg.AutoScanLevel != "basic" {
		t.Errorf("expected AutoScanLevel 'basic', got %q", cfg.AutoScanLevel)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "this-is-16-chars")
	t.Setenv("MAX_WORKERS", "4")
	t.Setenv("QUEUE_SIZE", "256")
	t.Setenv("SCAN_MODE", "raw")
	t.Setenv("TLS_ENABLED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.MaxWorkers != 4 {
		t.Errorf("expected MaxWorkers 4, got %d", cfg.MaxWorkers)
	}
	if cfg.QueueSize != 256 {
		t.Errorf("expected QueueSize 256, got %d", cfg.QueueSize)
	}
	if cfg.ScanMode != "raw" {
		t.Errorf("expected ScanMode 'raw', got %q", cfg.ScanMode)
	}
	if cfg.TLSEnabled {
		t.Errorf("expected TLSEnabled false")
	}
}

func TestSplitCSV(t *testing.T) {
	baseSetenv := func(t *testing.T) {
		t.Helper()
		t.Setenv("ADMIN_TOKEN", "this-is-16-chars")
	}

	t.Run("empty SMTP_TO produces nil slice", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("SMTP_TO", "")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if cfg.SMTPTo != nil {
			t.Errorf("expected nil SMTPTo, got %v", cfg.SMTPTo)
		}
	})

	t.Run("single email", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("SMTP_TO", "a@b.com")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if len(cfg.SMTPTo) != 1 || cfg.SMTPTo[0] != "a@b.com" {
			t.Errorf("expected [a@b.com], got %v", cfg.SMTPTo)
		}
	})

	t.Run("two emails", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("SMTP_TO", "a@b.com,b@c.com")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if len(cfg.SMTPTo) != 2 || cfg.SMTPTo[0] != "a@b.com" || cfg.SMTPTo[1] != "b@c.com" {
			t.Errorf("expected [a@b.com b@c.com], got %v", cfg.SMTPTo)
		}
	})

	t.Run("emails with surrounding spaces are trimmed", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("SMTP_TO", " a@b.com , b@c.com ")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if len(cfg.SMTPTo) != 2 || cfg.SMTPTo[0] != "a@b.com" || cfg.SMTPTo[1] != "b@c.com" {
			t.Errorf("expected trimmed [a@b.com b@c.com], got %v", cfg.SMTPTo)
		}
	})
}

func TestParseCSVPorts(t *testing.T) {
	baseSetenv := func(t *testing.T) {
		t.Helper()
		t.Setenv("ADMIN_TOKEN", "this-is-16-chars")
	}

	t.Run("valid port list", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("HOST_PORTS", "22,80,443")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		want := []string{"22", "80", "443"}
		if len(cfg.HostPorts) != len(want) {
			t.Fatalf("expected %v, got %v", want, cfg.HostPorts)
		}
		for i, v := range want {
			if cfg.HostPorts[i] != v {
				t.Errorf("port[%d]: expected %q, got %q", i, v, cfg.HostPorts[i])
			}
		}
	})

	// When HOST_PORTS is empty, getenv returns the default "22,80,443,445,3389"
	// which parseCSVPorts parses into 5 ports.
	t.Run("empty HOST_PORTS uses getenv default", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("HOST_PORTS", "")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		want := []string{"22", "80", "443", "445", "3389"}
		if len(cfg.HostPorts) != len(want) {
			t.Fatalf("expected %v, got %v", want, cfg.HostPorts)
		}
		for i, v := range want {
			if cfg.HostPorts[i] != v {
				t.Errorf("port[%d]: expected %q, got %q", i, v, cfg.HostPorts[i])
			}
		}
	})

	t.Run("mixed valid and invalid ports - invalid ones skipped", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("HOST_PORTS", "notanumber,80")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		if len(cfg.HostPorts) != 1 || cfg.HostPorts[0] != "80" {
			t.Errorf("expected [80], got %v", cfg.HostPorts)
		}
	})

	t.Run("all invalid ports fall back to parseCSVPorts default", func(t *testing.T) {
		baseSetenv(t)
		t.Setenv("HOST_PORTS", "all-invalid")
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("Load() returned error: %v", err)
		}
		// parseCSVPorts fallback default is ["22","80","443"]
		want := []string{"22", "80", "443"}
		if len(cfg.HostPorts) != len(want) {
			t.Fatalf("expected %v, got %v", want, cfg.HostPorts)
		}
		for i, v := range want {
			if cfg.HostPorts[i] != v {
				t.Errorf("port[%d]: expected %q, got %q", i, v, cfg.HostPorts[i])
			}
		}
	})
}
