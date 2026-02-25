// Package http provides HTTP handlers for the pnr API
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/config"
	"github.com/mfmatusz/private-network-reporter/pkg/models"
	"github.com/mfmatusz/private-network-reporter/pkg/reports"
	"github.com/mfmatusz/private-network-reporter/pkg/scanner"
	"github.com/mfmatusz/private-network-reporter/pkg/security"
	"github.com/mfmatusz/private-network-reporter/pkg/store"
)

// Handler holds all HTTP handler dependencies
type Handler struct {
	cfg              *config.Config
	store            store.Repository
	scanner          scanner.Scanner
	auth             *security.Authenticator
	adminRateLimiter *security.AdminRateLimiter
	queue            chan string
	reportGen        *reports.Generator
}

// NewHandler creates a new HTTP handler with dependencies
func NewHandler(
	cfg *config.Config,
	repo store.Repository,
	scn scanner.Scanner,
	auth *security.Authenticator,
	adminRateLimiter *security.AdminRateLimiter,
	queue chan string,
	reportGen *reports.Generator,
) *Handler {
	return &Handler{
		cfg:              cfg,
		store:            repo,
		reportGen:        reportGen,
		scanner:          scn,
		auth:             auth,
		adminRateLimiter: adminRateLimiter,
		queue:            queue,
	}
}

// RegisterRoutes registers all HTTP routes on the given mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public webhooks (with signature auth)
	mux.HandleFunc("/events", h.EventsHandler)
	mux.HandleFunc("/arp/harvest", h.ARPHarvestHandler)

	// Public health check
	mux.HandleFunc("/healthz", h.Healthz)

	// Admin endpoints (require X-Admin-Token)
	mux.HandleFunc("/admin/health", h.requireAdminToken(h.AdminHealth))
	mux.HandleFunc("/admin/toggle", h.requireAdminToken(h.AdminToggle))
	mux.HandleFunc("/admin/config", h.requireAdminToken(h.AdminConfig))

	// Rate-limited admin operations (expensive/abusable)
	limits := security.DefaultAdminLimits
	mux.HandleFunc("/admin/repair", h.requireAdminToken(h.adminRateLimiter.Middleware(limits.Repair, "repair")(h.AdminRepair)))
	mux.HandleFunc("/admin/rescan", h.requireAdminToken(h.adminRateLimiter.Middleware(limits.Rescan, "rescan")(h.AdminRescan)))
	mux.HandleFunc("/admin/scan", h.requireAdminToken(h.adminRateLimiter.Middleware(limits.Scan, "scan")(h.AdminScan)))

	// Reports
	mux.HandleFunc("/admin/report/today", h.requireAdminToken(h.ServeLatestReport))
	mux.HandleFunc("/admin/report/generate", h.requireAdminToken(h.adminRateLimiter.Middleware(limits.ReportGenerate, "report-generate")(h.TriggerReport)))
}

// ----------------- Middleware -----------------

// requireAdminToken is middleware that requires admin token authentication
func (h *Handler) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.auth.ValidateAdminToken(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ----------------- Public Handlers -----------------

// EventsHandler receives network events from RouterOS webhooks
func (h *Handler) EventsHandler(w http.ResponseWriter, r *http.Request) {
	body, err := readBodyLimit(r, 1<<20)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Verify SHA512 signature if EVENT_TOKEN is set
	if h.cfg.EventToken != "" {
		if !h.auth.ValidateSHA512Signature(r, body) {
			log.Printf("events: auth failed from %s", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var ev models.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if net.ParseIP(ev.IP) == nil {
		http.Error(w, "bad ip", http.StatusBadRequest)
		return
	}

	// Upsert endpoint (discovery phase)
	now := time.Now()
	if err := h.store.UpsertEndpoint(ev.IP, ev.MAC, ev.Hostname, classifyEndpoint(ev.MAC, ev.Hostname), now, true); err != nil {
		log.Printf("events: failed to upsert endpoint: %v", err)
	}

	// Queue for scanning (with per-MAC cooldown check, fallback to IP)
	cooldownKey := ev.MAC
	if cooldownKey == "" {
		cooldownKey = ev.IP // Fallback when MAC not provided (e.g. Netwatch)
	}

	lastScan, err := h.store.GetLastScanTime(cooldownKey)
	if err == nil && time.Since(lastScan) < h.cfg.Cooldown {
		// Skip, too soon (same physical device recently scanned)
		// Debug (verbose): uncomment to log each skipped event individually
		// Log can be in production as well, because it does not produce as much noise as ARP harvest (1 log per event)
		// log.Printf("events: skipping %s (MAC=%s, last_scan=%v ago)", ev.IP, ev.MAC, time.Since(lastScan))
		writeJSON(w, 200, map[string]any{"status": "queued", "note": "cooldown active, scan deferred"})
		return
	}

	// Queue IP for scanning (worker will use AutoScanLevel from config)
	select {
	case h.queue <- ev.IP:
	default:
		log.Printf("WARN: queue full, dropped event for %s", ev.IP)
	}

	w.WriteHeader(http.StatusAccepted)
}

// ARPHarvestHandler receives bulk ARP data from RouterOS
func (h *Handler) ARPHarvestHandler(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.ARPHarvestAllow {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	body, err := readBodyLimit(r, 1<<20)
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	// Verify SHA512 signature if EVENT_TOKEN is set
	if h.cfg.EventToken != "" {
		if !h.auth.ValidateSHA512Signature(r, body) {
			log.Printf("arp-harvest: auth failed from %s", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var entries []models.ARPEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	now := time.Now()
	if err := h.store.IngestARP(entries, now); err != nil {
		log.Printf("arp-harvest: failed to upsert ARP data: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Queue discovered IPs for scanning (with per-MAC cooldown check)
	// Workers will use AutoScanLevel from config for scan depth
	queued := 0
	skipped := 0
	for _, entry := range entries {
		// Check cooldown per-MAC (preferred) or per-IP (fallback)
		cooldownKey := entry.MAC
		if cooldownKey == "" {
			cooldownKey = entry.IP // Fallback when MAC empty
		}

		lastScan, err := h.store.GetLastScanTime(cooldownKey)
		if err == nil && !lastScan.IsZero() && time.Since(lastScan) < h.cfg.Cooldown {
			skipped++
			// Debug (verbose): uncomment to log each skipped entry individually
			// log.Printf("arp-harvest: skipping %s (MAC=%s, last_scan=%v ago)", entry.IP, entry.MAC, time.Since(lastScan))
			continue // Skip, too soon (same physical device recently scanned)
		}
		if err != nil {
			log.Printf("arp-harvest: GetLastScanTime failed for %s (MAC=%s): %v", entry.IP, entry.MAC, err)
		}

		select {
		case h.queue <- entry.IP:
			queued++
		default:
			// Queue full - logged once at the end
		}
	}

	droppedCount := len(entries) - queued - skipped
	if queued > 0 || skipped > 0 || droppedCount > 0 {
		log.Printf("arp-harvest: processed %d hosts, queued %d, skipped %d (cooldown), dropped %d (queue full)", len(entries), queued, skipped, droppedCount)
	}

	writeJSON(w, 202, map[string]any{"harvested": len(entries), "queued": queued, "skipped_cooldown": skipped, "dropped_queue_full": droppedCount})
}

// ----------------- Admin Handlers -----------------

// Healthz returns service health status
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok":            true,
		"enabled":       h.cfg.Enabled,
		"max_workers":   h.cfg.MaxWorkers,
		"cooldown":      h.cfg.Cooldown.String(),
		"report_time":   h.cfg.DailyReportTime,
		"report_detail": h.cfg.ReportDetail,
	})
}

// AdminHealth returns health status (same as public healthz)
func (h *Handler) AdminHealth(w http.ResponseWriter, r *http.Request) {
	h.Healthz(w, r)
}

// AdminToggle enables/disables scanning
func (h *Handler) AdminToggle(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Enabled *bool `json:"enabled"`
	}
	var x req
	if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if x.Enabled != nil {
		h.cfg.Enabled = *x.Enabled
	}

	writeJSON(w, 200, map[string]any{"enabled": h.cfg.Enabled})
}

// AdminConfig gets/updates runtime configuration
func (h *Handler) AdminConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.cfg)

	case http.MethodPost:
		type req struct {
			Cooldown        *string `json:"cooldown"`
			DailyReportTime *string `json:"daily_report_time"`
			ReportDetail    *string `json:"report_detail"`
			MaxWorkers      *int    `json:"max_workers"`
			TimeoutBasic    *string `json:"timeout_basic"`
			TimeoutDeep     *string `json:"timeout_deep"`
		}
		var x req
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, "bad json", 400)
			return
		}

		if x.Cooldown != nil {
			if d, err := time.ParseDuration(*x.Cooldown); err == nil {
				h.cfg.Cooldown = d
			}
		}
		if x.DailyReportTime != nil && len(*x.DailyReportTime) == 5 {
			h.cfg.DailyReportTime = *x.DailyReportTime
		}
		if x.ReportDetail != nil && (*x.ReportDetail == "summary" || *x.ReportDetail == "detailed") {
			h.cfg.ReportDetail = *x.ReportDetail
		}
		if x.MaxWorkers != nil && *x.MaxWorkers > 0 && *x.MaxWorkers <= 16 {
			h.cfg.MaxWorkers = *x.MaxWorkers
		}
		if x.TimeoutBasic != nil {
			if d, err := time.ParseDuration(*x.TimeoutBasic); err == nil && d >= 10*time.Second && d <= 10*time.Minute {
				h.cfg.TimeoutBasic = d
			}
		}
		if x.TimeoutDeep != nil {
			if d, err := time.ParseDuration(*x.TimeoutDeep); err == nil && d >= 30*time.Second && d <= 30*time.Minute {
				h.cfg.TimeoutDeep = d
			}
		}

		writeJSON(w, 200, map[string]string{"ok": "updated"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// AdminRepair performs database maintenance
func (h *Handler) AdminRepair(w http.ResponseWriter, r *http.Request) {
	if err := h.store.VacuumAnalyze(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "repaired"})
}

// AdminRescan queues a single IP for scanning
func (h *Handler) AdminRescan(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, "bad ip", 400)
		return
	}

	select {
	case h.queue <- ip:
		writeJSON(w, 202, map[string]string{"queued": ip})
	default:
		log.Printf("WARN: queue full, cannot rescan %s", ip)
		writeJSON(w, 503, map[string]string{"error": "queue full", "ip": ip})
	}
}

// AdminScan performs an immediate scan of a single IP
// GET /admin/scan?ip=1.2.3.4[&deep=1|true][&deepsafe=1][&custom=1][&scripts=http-title,vulners][&mode=raw|basic][&ports=22,80,443][&timeout=120s]
func (h *Handler) AdminScan(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		http.Error(w, "bad ip", http.StatusBadRequest)
		return
	}

	// Scan mode: raw (-sS) | basic (-sT)
	mode := r.URL.Query().Get("mode")
	if mode != "raw" && mode != "basic" {
		mode = h.cfg.ScanMode
	}
	useRaw := (mode == "raw")

	// Ports: from parameter or config defaults
	ports := parseCSVPorts(r.URL.Query().Get("ports"), h.cfg.HostPorts)

	// Scan level from query parameters (default from config)
	q := r.URL.Query()
	deep := queryBool(q, "deep")
	deepsafe := queryBool(q, "deepsafe")
	custom := queryBool(q, "custom")
	basic := queryBool(q, "basic")

	// Determine scan level: explicit params override config default
	level := h.cfg.AutoScanLevel
	if custom {
		level = "custom"
	} else if deepsafe {
		level = "deepsafe"
	} else if deep {
		level = "deep"
	} else if basic {
		level = "basic"
	}

	// Build scan request
	req := scanner.ScanRequest{
		IP:     ip,
		Ports:  ports,
		UseRaw: useRaw,
		Level:  level,
	}

	// Custom scripts: from URL param or config default
	if level == "custom" {
		scripts := r.URL.Query().Get("scripts")
		if scripts == "" {
			scripts = h.cfg.CustomScripts
		}
		if scripts == "" {
			http.Error(w, "custom scan requires scripts param or CUSTOM_SCRIPTS env", http.StatusBadRequest)
			return
		}
		req.CustomScripts = scripts
	}

	// Set timeout: custom from query param, or default based on scan level
	var nmapTimeout time.Duration
	if customTimeout := r.URL.Query().Get("timeout"); customTimeout != "" {
		if d, err := time.ParseDuration(customTimeout); err == nil && d >= 10*time.Second && d <= 30*time.Minute {
			nmapTimeout = d
		} else {
			http.Error(w, "invalid timeout (min 10s, max 30m)", http.StatusBadRequest)
			return
		}
	} else if level == "deep" || level == "deepsafe" {
		nmapTimeout = h.cfg.TimeoutDeep
	} else if level == "custom" {
		nmapTimeout = h.cfg.TimeoutCustom
	} else if level == "basic" {
		nmapTimeout = h.cfg.TimeoutBasic
	} else {
		nmapTimeout = h.cfg.TimeoutBasic
	}

	// Set timing based on scan level
	if level == "deep" || level == "deepsafe" || level == "custom" {
		req.Timing = "T3"
	} else {
		req.Timing = "T2"
	}
	req.Timeout = fmt.Sprintf("%ds", int(nmapTimeout.Seconds()))

	// Execute scan with context timeout (nmap timeout + 30s buffer)
	started := time.Now()
	ctxTimeout := nmapTimeout + 30*time.Second
	ctxScan, cancel := context.WithTimeout(r.Context(), ctxTimeout)
	defer cancel()

	result, err := h.scanner.ScanTarget(ctxScan, req)
	finished := time.Now()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
			"ip":    ip,
		})
		return
	}

	// Save to database
	scanType := level

	b, _ := json.Marshal(result)
	scanID, dbErr := h.store.InsertScan(ip, scanType, started, finished, string(b))
	if dbErr == nil {
		_ = h.store.MarkScanned(ip, finished)
		if result != nil {
			for _, host := range result.Hosts {
				if host.Ports != nil && len(host.Ports.List) > 0 {
					_ = h.store.InsertPorts(scanID, ip, host.Ports.List)
				}
				// Update endpoint metadata
				var mac, hostname string
				for _, a := range host.Addresses {
					if a.AddrType == "mac" {
						mac = a.Addr
					}
				}
				if host.Hostnames != nil && len(host.Hostnames.List) > 0 {
					hostname = host.Hostnames.List[0].Name
				}
				_ = h.store.UpsertEndpoint(ip, mac, hostname, classifyEndpoint(mac, hostname), time.Now(), true)
			}
		}
	}

	// Build response summary
	sum := map[string]any{"open_ports": 0}
	if result != nil && len(result.Hosts) > 0 && result.Hosts[0].Ports != nil {
		sum["open_ports"] = len(result.Hosts[0].Ports.List)
	}

	// Check for sensitive information in NSE scripts (deep/deepsafe scans)
	response := map[string]any{
		"scan_id": scanID,
		"ip":      ip,
		"summary": sum,
	}

	if (level == "deep" || level == "deepsafe") && result != nil {
		sensitiveScripts := reports.DetectSensitiveScripts(result)
		if len(sensitiveScripts) > 0 {
			response["sensitive_data_detected"] = true
			response["sensitive_scripts"] = sensitiveScripts
			response["recommendation"] = " Sensitive information detected! Generate a report now with /admin/report/generate and check your email for details."
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// ServeLatestReport serves the most recent HTML report
func (h *Handler) ServeLatestReport(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(filepath.Dir(h.cfg.DBPath), "reports")
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "no reports", 404)
		return
	}

	latest := ""
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".html") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}

	if latest == "" {
		http.Error(w, "no reports", 404)
		return
	}

	p := filepath.Join(dir, latest)
	b, err := os.ReadFile(p)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(b)
}

// TriggerReport generates a report for a time window
// Query params: ?from=<RFC3339|unix>&to=<RFC3339|unix>
// If not specified, uses REPORT_WINDOW from config (default: last 24 hours)
func (h *Handler) TriggerReport(w http.ResponseWriter, r *http.Request) {
	loc, _ := time.LoadLocation(h.cfg.TZ)

	// Parse custom time range from query params
	to := time.Now().In(loc)
	from := to.Add(-h.cfg.ReportWindow)

	// Override with query parameters if provided
	if fromParam := r.URL.Query().Get("from"); fromParam != "" {
		if t, err := parseTimeParam(fromParam, loc); err == nil {
			from = t
		} else {
			http.Error(w, fmt.Sprintf("invalid from parameter: %v", err), http.StatusBadRequest)
			return
		}
	}

	if toParam := r.URL.Query().Get("to"); toParam != "" {
		if t, err := parseTimeParam(toParam, loc); err == nil {
			to = t
		} else {
			http.Error(w, fmt.Sprintf("invalid to parameter: %v", err), http.StatusBadRequest)
			return
		}
	}

	// Validate time range
	if from.After(to) {
		http.Error(w, "from must be before to", http.StatusBadRequest)
		return
	}
	if to.Sub(from) > 30*24*time.Hour {
		http.Error(w, "time range cannot exceed 30 days", http.StatusBadRequest)
		return
	}

	// Generate report synchronously and return HTML
	log.Printf("report: generating report for %s to %s...", from.Format(time.RFC3339), to.Format(time.RFC3339))

	path, err := h.reportGen.GenerateAndStore(from, to)
	if err != nil {
		log.Printf("report: generation failed: %v", err)
		http.Error(w, fmt.Sprintf("report generation failed: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("report: completed successfully: %s", path)

	// Read and serve the generated report
	htmlContent, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "failed to read generated report", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(htmlContent)
}

// ----------------- Helper Functions -----------------

// readBodyLimit reads request body with size limit
func readBodyLimit(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	lr := &io.LimitedReader{R: r.Body, N: limit}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("body too large")
	}
	return b, nil
}

// writeJSON writes JSON response
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// parseTimeParam parses time from query parameter (RFC3339 or unix timestamp)
func parseTimeParam(param string, loc *time.Location) (time.Time, error) {
	// Try RFC3339 format first
	if t, err := time.Parse(time.RFC3339, param); err == nil {
		return t.In(loc), nil
	}

	// Try unix timestamp (seconds)
	if ts, err := strconv.ParseInt(param, 10, 64); err == nil {
		return time.Unix(ts, 0).In(loc), nil
	}

	return time.Time{}, fmt.Errorf("invalid time format (use RFC3339 or unix timestamp)")
}

// classifyEndpoint performs simple heuristic classification
func classifyEndpoint(mac, hostname string) string {
	hn := strings.ToLower(hostname)
	if strings.Contains(hn, "iphone") || strings.Contains(hn, "android") ||
		strings.Contains(hn, "pixel") || strings.Contains(hn, "galaxy") {
		return "phone"
	}
	if strings.Contains(hn, "win-") || strings.Contains(hn, "desktop") ||
		strings.Contains(hn, "laptop") || strings.Contains(hn, "macbook") {
		return "pc"
	}
	if mac != "" {
		pref := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, ":", ""), "-", ""))
		if strings.HasPrefix(pref, "B827EB") || strings.HasPrefix(pref, "DCA632") {
			return "iot"
		}
	}
	return "unknown"
}

// parseBool parses boolean from query parameter
// Returns true for "1", "true", "yes", or empty string (param present without value)
// queryBool checks if a query parameter is truthy
// Returns true if parameter is present with value "1", "true", "yes", or empty (e.g., ?deep)
func queryBool(q map[string][]string, key string) bool {
	vals, present := q[key]
	if !present {
		return false
	}
	if len(vals) == 0 || vals[0] == "" {
		// Parameter present without value (e.g., ?deep)
		return true
	}
	s := strings.ToLower(vals[0])
	return s == "1" || s == "true" || s == "yes"
}

// parseCSVPorts parses comma-separated port list
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
		result = append(result, p)
	}

	if len(result) == 0 {
		return defaultPorts
	}
	return result
}
