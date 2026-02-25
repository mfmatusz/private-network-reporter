// Package main is the entry point for pnr
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/arp"
	"github.com/mfmatusz/private-network-reporter/pkg/config"
	pkghttp "github.com/mfmatusz/private-network-reporter/pkg/http"
	"github.com/mfmatusz/private-network-reporter/pkg/reports"
	"github.com/mfmatusz/private-network-reporter/pkg/scanner"
	"github.com/mfmatusz/private-network-reporter/pkg/security"
	"github.com/mfmatusz/private-network-reporter/pkg/store"
	"github.com/mfmatusz/private-network-reporter/pkg/tlsutil"
)

//go:embed templates/report.html
var reportTemplate string

// Application holds all application dependencies
type Application struct {
	cfg              *config.Config
	store            store.Repository
	scanner          scanner.Scanner
	auth             *security.Authenticator
	adminRateLimiter *security.AdminRateLimiter
	queue            chan string
	reportGen        *reports.Generator
	httpServer       *http.Server

	// Prevents race condition: ensures max 1 concurrent scan per MAC
	// Key: MAC address (or IP address), Value: true (currently scanning)
	scanningNow sync.Map

	// For graceful shutdown
	cancel context.CancelFunc
}

func main() {
	// Setup logging to both file and stderr
	logFile, err := os.OpenFile("/data/debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
	if err != nil {
		log.Printf("Warning: cannot open log file: %v, using stderr only", err)
		log.SetOutput(os.Stderr)
	} else {
		multiWriter := io.MultiWriter(os.Stderr, logFile)
		log.SetOutput(multiWriter)
		defer logFile.Close()
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		log.Println("========== Application started ==========")
	}

	// Load and validate configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Log security configuration
	log.Printf("Security: ADMIN_TOKEN configured (%d chars)", len(cfg.AdminToken))
	if cfg.EventToken != "" {
		log.Printf("Security: EVENT_TOKEN configured (%d chars)", len(cfg.EventToken))
	} else {
		log.Printf("WARNING: EVENT_TOKEN not set - webhook authentication disabled")
	}

	if cfg.RateLimitEnabled {
		log.Printf("Rate limiting: ENABLED (scan=10/min, rescan=20/min, repair=1/5min, report=1/5min)")
	} else {
		log.Printf("Rate limiting: DISABLED")
	}

	// Initialize dependencies
	app, err := newApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.cleanup()

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app.cancel = stop

	// Start application components
	if err := app.start(ctx); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	// Wait for shutdown signal
	<-ctx.Done()
	log.Printf("Shutting down gracefully...")
}

// newApplication creates and initializes the application with all dependencies
func newApplication(cfg *config.Config) (*Application, error) {
	// Initialize store
	repo, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Initialize scanner
	nmapScanner := scanner.NewNmapScanner()

	// Initialize security components
	auth := security.NewAuthenticator(cfg.AdminToken, cfg.EventToken)
	adminRateLimiter := security.NewAdminRateLimiter(cfg.RateLimitEnabled)

	// Initialize email sender
	var emailer *reports.Emailer
	if cfg.SMTPHost != "" {
		emailer = reports.NewEmailer(reports.EmailConfig{
			SMTPHost:     cfg.SMTPHost,
			SMTPPort:     cfg.SMTPPort,
			SMTPUser:     cfg.SMTPUser,
			SMTPPass:     cfg.SMTPPass,
			SMTPFrom:     cfg.SMTPFrom,
			SMTPTo:       cfg.SMTPTo,
			SMTPStartTLS: cfg.SMTPStartTLS,
		})
		log.Printf("Email: SMTP configured (%s:%s)", cfg.SMTPHost, cfg.SMTPPort)
	}

	// Initialize report generator and inject template
	reportGen := reports.NewGenerator(repo, cfg.DBPath, cfg.ReportDetail, emailer)
	reports.SetTemplate(reportTemplate)

	// Create work queue
	queue := make(chan string, cfg.QueueSize)
	log.Printf("Queue: buffer size %d", cfg.QueueSize)

	return &Application{
		cfg:              cfg,
		store:            repo,
		scanner:          nmapScanner,
		auth:             auth,
		adminRateLimiter: adminRateLimiter,
		queue:            queue,
		reportGen:        reportGen,
	}, nil
}

// start begins all application services
func (app *Application) start(ctx context.Context) error {
	log.Printf("Starting pnr on %s (mode=%s, workers=%d, enabled=%v)",
		app.cfg.Addr, app.cfg.ScanMode, app.cfg.MaxWorkers, app.cfg.Enabled)

	// Start worker pool
	for i := 0; i < app.cfg.MaxWorkers; i++ {
		go app.worker(ctx, i+1)
	}

	// Start background services
	go app.reportScheduler(ctx)
	go app.arpIngesterLoop(ctx)

	// Setup HTTP handlers
	handler := pkghttp.NewHandler(
		app.cfg,
		app.store,
		app.scanner,
		app.auth,
		app.adminRateLimiter,
		app.queue,
		app.reportGen,
	)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create HTTP server
	srv := &http.Server{
		Addr:              app.cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Start HTTPS server
	go func() {
		if app.cfg.TLSEnabled {
			// Ensure TLS certificate exists (auto-generate if missing)
			if err := tlsutil.EnsureCertificate(app.cfg.TLSCertPath, app.cfg.TLSKeyPath); err != nil {
				log.Fatalf("TLS: Failed to setup certificate: %v", err)
			}

			// Configure modern TLS settings
			srv.TLSConfig = &tls.Config{
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			}

			log.Printf("pnr listening on %s (HTTPS)", app.cfg.Addr)
			log.Printf("TLS: Using certificate: %s", app.cfg.TLSCertPath)
			if err := srv.ListenAndServeTLS(app.cfg.TLSCertPath, app.cfg.TLSKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP server error: %v", err)
			}
		} else {
			log.Printf("pnr listening on %s (HTTP - INSECURE)", app.cfg.Addr)
			log.Printf("WARNING: TLS disabled - consider enabling TLS_ENABLED=true for production")
			if app.cfg.EventToken != "" || app.cfg.AdminToken != "" {
				log.Printf("WARNING: Tokens transmitted in plaintext without TLS!")
			}
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP server error: %v", err)
			}
		}
	}()

	// Store server for graceful shutdown
	app.httpServer = srv

	log.Printf("Application started successfully")
	return nil
}

// worker processes scan requests from the queue
func (app *Application) worker(ctx context.Context, id int) {
	log.Printf("Worker %d started", id)
	defer log.Printf("Worker %d stopped", id)

	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-app.queue:
			if !app.cfg.Enabled {
				continue
			}

			// Check cooldown per-MAC (or per-IP if MAC unknown)
			// First, try to get MAC for this IP
			mac, err := app.store.GetMACForIP(ip)
			if err != nil {
				log.Printf("Worker %d: failed to get MAC for %s: %v", id, ip, err)
			}

			// Use MAC for cooldown check if available, otherwise use IP
			cooldownKey := ip
			if mac != "" {
				cooldownKey = mac
			}

			// ATOMIC CHECK: Prevent race condition where two events for same MAC
			// arrive simultaneously. LoadOrStore ensures only one worker proceeds.
			if _, alreadyScanning := app.scanningNow.LoadOrStore(cooldownKey, true); alreadyScanning {
				log.Printf("Worker %d: skipping %s (MAC=%s, already being scanned by another worker)",
					id, ip, mac)
				continue
			}

			lastScanned, err := app.store.GetLastScanTime(cooldownKey)
			if err == nil && !lastScanned.IsZero() {
				if time.Since(lastScanned) < app.cfg.Cooldown {
					log.Printf("Worker %d: skipping %s (MAC=%s, cooldown: %v remaining)",
						id, ip, mac, app.cfg.Cooldown-time.Since(lastScanned))
					app.scanningNow.Delete(cooldownKey)
					continue
				}
			}
			if err != nil {
				log.Printf("Worker %d: GetLastScanTime failed for %s (MAC=%s): %v", id, ip, mac, err)
			}
			if !lastScanned.IsZero() {
				log.Printf("Worker %d: cooldown OK for %s (MAC=%s, last_scan=%v ago)", id, ip, mac, time.Since(lastScanned))
			} else {
				log.Printf("Worker %d: first scan for %s (MAC=%s, no previous scan)", id, ip, mac)
			}

			// Build scan request (uses AutoScanLevel from config)
			scanReq := scanner.ScanRequest{
				IP:     ip,
				Ports:  app.cfg.HostPorts,
				UseRaw: app.cfg.ScanMode == "raw",
				Level:  app.cfg.AutoScanLevel, // "basic" | "deep" | "deepsafe" | "custom"
				Timing: "T2",
			}

			// Set custom scripts if using custom scan level
			if app.cfg.AutoScanLevel == "custom" {
				scanReq.CustomScripts = app.cfg.CustomScripts
				scanReq.Timing = "T3"
			}

			// Set timeout based on scan level (configurable)
			var nmapTimeout time.Duration
			if app.cfg.AutoScanLevel == "deep" || app.cfg.AutoScanLevel == "deepsafe" {
				nmapTimeout = app.cfg.TimeoutDeep
				scanReq.Timing = "T3"
			} else if app.cfg.AutoScanLevel == "custom" {
				nmapTimeout = app.cfg.TimeoutCustom
			} else {
				nmapTimeout = app.cfg.TimeoutBasic
			}
			scanReq.Timeout = fmt.Sprintf("%ds", int(nmapTimeout.Seconds()))

			// Execute scan with context timeout (nmap timeout + 30s buffer)
			ctxTimeout := nmapTimeout + 30*time.Second
			started := time.Now()
			scanCtx, cancel := context.WithTimeout(ctx, ctxTimeout)
			result, err := app.scanner.ScanTarget(scanCtx, scanReq)
			cancel()
			finished := time.Now()

			if err != nil {
				log.Printf("Worker %d: scan failed for %s: %v", id, ip, err)
				// Mark as scanned even on failure to prevent infinite retry loop
				// (dead hosts, timeouts, firewalled IPs should respect cooldown)
				if markErr := app.store.MarkScanned(ip, finished); markErr != nil {
					log.Printf("Worker %d: failed to mark scanned after failure %s: %v", id, ip, markErr)
				}
				app.scanningNow.Delete(cooldownKey)
				continue
			}

			// Save to database
			if err := app.store.SaveScan(ip, "auto", started, finished, result); err != nil {
				log.Printf("Worker %d: failed to save scan for %s: %v", id, ip, err)
				app.scanningNow.Delete(cooldownKey)
				continue
			}

			app.scanningNow.Delete(cooldownKey)
			log.Printf("Worker %d: scanned %s successfully", id, ip)
		}
	}
}

// reportScheduler generates periodic reports
func (app *Application) reportScheduler(ctx context.Context) {
	log.Printf("Report scheduler started (periodic at %s)", app.cfg.DailyReportTime)

	for {
		now := time.Now()

		// Parse target time (HH:MM format)
		targetTime, err := time.Parse("15:04", app.cfg.DailyReportTime)
		if err != nil {
			log.Printf("Report: invalid ReportTime format: %v", err)
			return
		}

		// Calculate next report time
		nextReport := time.Date(now.Year(), now.Month(), now.Day(),
			targetTime.Hour(), targetTime.Minute(), 0, 0, now.Location())

		if now.After(nextReport) {
			nextReport = nextReport.Add(24 * time.Hour)
		}

		sleepDuration := time.Until(nextReport)
		log.Printf("Report: next report in %v (at %s)", sleepDuration.Round(time.Minute), nextReport.Format("2006-01-02 15:04"))

		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepDuration):
			log.Printf("Report: generating daily report")

			from := now.Add(-app.cfg.ReportWindow)
			to := now

			reportPath, err := app.reportGen.GenerateAndStore(from, to)
			if err != nil {
				log.Printf("Report: failed to generate: %v", err)
			} else {
				log.Printf("Report: generated successfully: %s", reportPath)
			}
		}
	}
}

// arpIngesterLoop periodically parses local ARP table for network discovery (additional functionality)
func (app *Application) arpIngesterLoop(ctx context.Context) {
	if !app.cfg.ARPIngesterEnabled {
		log.Printf("ARP Ingester: disabled (set ARP_INGESTER_ENABLED=true to enable)")
		return
	}

	log.Printf("ARP Ingester: started (interval: %v)", app.cfg.ARPIngesterInterval)

	ticker := time.NewTicker(app.cfg.ARPIngesterInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !app.cfg.Enabled {
				continue
			}

			// Parse local ARP table
			entries, err := arp.ParseARPTable()
			if err != nil {
				log.Printf("ARP Ingester: failed to parse ARP table: %v", err)
				continue
			}

			if len(entries) == 0 {
				continue
			}

			// Convert to models.ARPEntry format
			arpEntries := arp.ToARPEntries(entries)

			// Ingest to database (bulk UPSERT)
			if err := app.store.IngestARP(arpEntries, time.Now()); err != nil {
				log.Printf("ARP Ingester: failed to ingest: %v", err)
				continue
			}

			// Queue discovered IPs for scanning (with per-MAC cooldown check)
			queued := 0
			skipped := 0
			for _, entry := range arpEntries {
				// Check cooldown per-MAC or per-IP (fallback)
				cooldownKey := entry.MAC
				if cooldownKey == "" {
					cooldownKey = entry.IP // Fallback to IP if MAC empty
				}

				lastScan, err := app.store.GetLastScanTime(cooldownKey)
				if err == nil && time.Since(lastScan) < app.cfg.Cooldown {
					skipped++
					continue // Skip, too soon (same physical device recently scanned)
				}

				select {
				case app.queue <- entry.IP:
					queued++
				default:
					// Queue full, skip
				}
			}

			if queued > 0 || skipped > 0 {
				log.Printf("ARP Ingester: discovered %d hosts, queued %d, skipped %d (cooldown)", len(entries), queued, skipped)
			}
		}
	}
}

// cleanup releases all resources
func (app *Application) cleanup() {
	log.Printf("Cleaning up resources...")

	// Shutdown HTTP server gracefully
	if app.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := app.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down HTTP server: %v", err)
		}
	}

	// Close store
	if app.store != nil {
		if err := app.store.Close(); err != nil {
			log.Printf("Error closing store: %v", err)
		}
	}

	// Close queue
	if app.queue != nil {
		close(app.queue)
	}
}
