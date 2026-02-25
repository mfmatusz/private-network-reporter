// Package reports provides HTML report generation functionality
package reports

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
	"github.com/mfmatusz/private-network-reporter/pkg/store"
)

// reportTemplate is the HTML template for reports (embedded from root templates/ dir in cmd)
var reportTemplate string

// SetTemplate allows injecting the report template from the main package
func SetTemplate(tmpl string) {
	reportTemplate = tmpl
}

// Sensitive NSE scripts that reveal potentially exploitable information (testing purposes - fully customizable)
var sensitiveNSEScripts = map[string]bool{
	"ssh-hostkey":           true, // SSH public keys (fingerprinting)
	"ssl-cert":              true, // SSL certificates (org structure, domains)
	"ssl-cert-intaddr":      true, // Internal addresses in certs
	"smb-os-discovery":      true, // Windows versions, domains
	"smb-security-mode":     true, // SMB security config
	"http-title":            true, // HTTP titles (software versions)
	"http-headers":          true, // HTTP headers (server versions)
	"http-server-header":    true, // Server identification
	"mysql-info":            true, // MySQL versions & config
	"mongodb-info":          true, // MongoDB versions & config
	"dns-nsid":              true, // DNS server identity
	"dns-service-discovery": true, // DNS structure
	"ftp-anon":              true, // Anonymous FTP (security issue)
	"telnet-encryption":     true, // Telnet encryption status
	"vnc-info":              true, // VNC server info
	"rdp-enum-encryption":   true, // RDP encryption
	"smb-enum-shares":       true, // SMB shares enumeration
	"smb-enum-users":        true, // SMB users enumeration
	"nfs-showmount":         true, // NFS exports
	"snmp-info":             true, // SNMP device info
}

// DetectSensitiveScripts checks if scan result contains sensitive NSE scripts
func DetectSensitiveScripts(result *models.NmapRun) []string {
	if result == nil {
		return nil
	}

	sensitiveFound := make(map[string]bool)

	for _, host := range result.Hosts {
		if host.Ports == nil {
			continue
		}
		for _, port := range host.Ports.List {
			for _, script := range port.Scripts {
				if sensitiveNSEScripts[script.ID] {
					sensitiveFound[script.ID] = true
				}
			}
		}
	}

	var scripts []string
	for scriptID := range sensitiveFound {
		scripts = append(scripts, scriptID)
	}

	return scripts
}

// NSEScriptInfo represents a single NSE script result
type NSEScriptInfo struct {
	ID     string
	Output string
}

// PortRow represents a single port in the report
type PortRow struct {
	Port    int
	Proto   string
	State   string
	Service string
	Product string
	Version string
	Scripts []NSEScriptInfo
}

// ScanReport represents a single scan in the report
type ScanReport struct {
	ID        int64
	IP        string
	MAC       string
	Started   time.Time
	Finished  time.Time
	ScanType  string
	OpenCount int
	Ports     []PortRow
	RawResult string
}

// PortCount represents port statistics
type PortCount struct {
	Port  int
	Count int
}

// ReportData is the root data structure for report templating
type ReportData struct {
	Title                string // "LAN Daily Report 2025-12-04" or "LAN Report 2025-12-01 - 2025-12-04"
	IsDaily              bool   // true if time range is ~24h
	From                 time.Time
	To                   time.Time
	Scans                []ScanReport
	TopPorts             []PortCount
	DistinctHosts        int
	UniqueOpenPortsCount int
	HasSensitiveData     bool
	SensitiveScripts     []string
}

// Generator handles report generation
type Generator struct {
	store        store.Repository
	dbPath       string
	reportDetail string // "summary" or "detailed"
	emailer      *Emailer
}

// NewGenerator creates a new report generator
func NewGenerator(repo store.Repository, dbPath, reportDetail string, emailer *Emailer) *Generator {
	return &Generator{
		store:        repo,
		dbPath:       dbPath,
		reportDetail: reportDetail,
		emailer:      emailer,
	}
}

// GenerateAndStore creates an HTML report for the given time range and saves it to disk
func (g *Generator) GenerateAndStore(from, to time.Time) (string, error) {
	data, err := g.collectReportData(from, to)
	if err != nil {
		return "", fmt.Errorf("failed to collect report data: %w", err)
	}

	html, err := g.renderReport(data)
	if err != nil {
		return "", fmt.Errorf("failed to render report: %w", err)
	}

	outPath, err := g.saveReport(html, from, to)
	if err != nil {
		return "", fmt.Errorf("failed to save report: %w", err)
	}

	log.Printf("report: generated successfully (%d scans, %d distinct hosts, %d unique open ports)",
		len(data.Scans), data.DistinctHosts, data.UniqueOpenPortsCount)

	// Send email if configured
	if g.emailer != nil {
		if err := g.emailer.SendReport(outPath, from, to); err != nil {
			log.Printf("report: email send failed: %v", err)
			// Don't return error - report generation succeeded
		} else {
			log.Printf("report: email sent successfully")
		}
	}

	return outPath, nil
}

// collectReportData queries the database and builds the report data structure
func (g *Generator) collectReportData(from, to time.Time) (*ReportData, error) {
	scanRecords, err := g.store.GetScansInWindow(from, to, 500) // Limit to prevent huge reports
	if err != nil {
		return nil, fmt.Errorf("query scans failed: %w", err)
	}

	var scans []ScanReport
	hostSet := make(map[string]struct{})
	openPortSet := make(map[int]struct{})
	sensitiveScriptsFound := make(map[string]bool)

	for _, record := range scanRecords {
		hostSet[record.IP] = struct{}{}

		// Parse nmap result JSON
		var nmapResult models.NmapRun
		var ports []PortRow
		openCount := 0

		// Get MAC from endpoints table (more reliable than nmap scan)
		mac, _ := g.store.GetMACForIP(record.IP)

		if err := json.Unmarshal([]byte(record.ResultJSON), &nmapResult); err == nil && len(nmapResult.Hosts) > 0 {
			host := nmapResult.Hosts[0]
			if host.Ports != nil {
				for _, p := range host.Ports.List {
					pr := PortRow{
						Port:  p.PortID,
						Proto: p.Protocol,
					}

					if p.State != nil {
						pr.State = p.State.State
					}

					if p.Service != nil {
						pr.Service = p.Service.Name
						pr.Product = p.Service.Product
						pr.Version = p.Service.Version
					}

					// Add NSE scripts
					for _, script := range p.Scripts {
						pr.Scripts = append(pr.Scripts, NSEScriptInfo{
							ID:     script.ID,
							Output: script.Output,
						})
						// Track sensitive scripts
						if sensitiveNSEScripts[script.ID] {
							sensitiveScriptsFound[script.ID] = true
						}
					}

					if pr.State == "open" {
						openCount++
						openPortSet[pr.Port] = struct{}{}
					}

					ports = append(ports, pr)
					if len(ports) >= 100 { // Limit per scan
						break
					}
				}
			}
		}

		sr := ScanReport{
			ID:        record.ID,
			IP:        record.IP,
			MAC:       mac,
			Started:   record.StartedAt,
			Finished:  record.FinishedAt,
			ScanType:  record.ScanType,
			OpenCount: openCount,
			Ports:     ports,
			RawResult: "",
		}

		// Include raw JSON only in detailed mode (truncated)
		if g.reportDetail == "detailed" && len(record.ResultJSON) > 0 {
			if len(record.ResultJSON) > 1000 {
				sr.RawResult = record.ResultJSON[:1000] + "... (truncated)"
			} else {
				sr.RawResult = record.ResultJSON
			}
		}

		scans = append(scans, sr)
	}

	// Compute top ports (only in detailed mode)
	var topPorts []PortCount
	if g.reportDetail == "detailed" {
		topPortRecords, err := g.store.GetTopPorts(from, to, 20)
		if err != nil {
			log.Printf("report: top ports query failed: %v", err)
		} else {
			for _, tp := range topPortRecords {
				topPorts = append(topPorts, PortCount{Port: tp.Port, Count: tp.Count})
			}
		}
	}

	// Convert sensitive scripts map to sorted slice
	var sensitiveScriptsList []string
	for scriptID := range sensitiveScriptsFound {
		sensitiveScriptsList = append(sensitiveScriptsList, scriptID)
	}

	// Determine if this is a daily report (time range ~24h ± 1h tolerance)
	duration := to.Sub(from)
	isDaily := duration >= 23*time.Hour && duration <= 25*time.Hour

	// Build title based on report type
	var title string
	if isDaily {
		title = fmt.Sprintf("LAN Daily Report %s", to.Format("2006-01-02"))
	} else {
		title = fmt.Sprintf("LAN Report %s – %s", from.Format("2006-01-02"), to.Format("2006-01-02"))
	}

	return &ReportData{
		Title:                title,
		IsDaily:              isDaily,
		From:                 from,
		To:                   to,
		Scans:                scans,
		TopPorts:             topPorts,
		DistinctHosts:        len(hostSet),
		UniqueOpenPortsCount: len(openPortSet),
		HasSensitiveData:     len(sensitiveScriptsFound) > 0,
		SensitiveScripts:     sensitiveScriptsList,
	}, nil
}

// renderReport renders the HTML template with data
func (g *Generator) renderReport(data *ReportData) ([]byte, error) {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("template execute error: %w", err)
	}

	return buf.Bytes(), nil
}

// saveReport writes the HTML report to disk
func (g *Generator) saveReport(html []byte, from, to time.Time) (string, error) {
	outDir := filepath.Join(filepath.Dir(g.dbPath), "reports")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Format: report_from_to.html
	// If range < 24h or times are not at midnight, include hours
	// Examples:
	//   report_2025-12-01_2025-12-05.html (full days)
	//   report_2025-12-01T14-30_2025-12-05T18-45.html (with hours)
	fromStr := formatReportTimestamp(from)
	toStr := formatReportTimestamp(to)
	fname := filepath.Join(outDir, fmt.Sprintf("report_%s_%s.html", fromStr, toStr))

	if err := os.WriteFile(fname, html, 0o644); err != nil {
		return "", fmt.Errorf("failed to write report file: %w", err)
	}

	return fname, nil
}

// formatReportTimestamp formats time for report filename
// Returns "2006-01-02" if time is at midnight, otherwise "2006-01-02T15-04"
func formatReportTimestamp(t time.Time) string {
	if t.Hour() == 0 && t.Minute() == 0 && t.Second() == 0 {
		return t.Format("2006-01-02")
	}
	return t.Format("2006-01-02T15-04")
}
