// Package scanner provides nmap-based network scanning
package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

// NmapScanner implements Scanner interface using nmap command
type NmapScanner struct{}

// NewNmapScanner creates a new nmap-based scanner
func NewNmapScanner() *NmapScanner {
	return &NmapScanner{}
}

// ScanTarget performs an nmap scan on the target IP
func (s *NmapScanner) ScanTarget(ctx context.Context, req ScanRequest) (*models.NmapRun, error) {
	args := buildNmapArgs(req)

	cmd := exec.CommandContext(ctx, "nmap", args...)

	// Debug: log nmap command
	fmt.Printf("[NMAP] Executing: nmap %s\n", strings.Join(args, " "))

	out, err := cmd.CombinedOutput()

	// Debug: log output size and first 200 bytes
	fmt.Printf("[NMAP] Output size: %d bytes, err=%v\n", len(out), err)
	if len(out) > 0 {
		preview := string(out)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		fmt.Printf("[NMAP] Output preview: %s...\n", preview)
	}

	// Extract XML from output (NSE scripts may print non-XML warnings like "No profinet devices")
	xmlOutput := extractXML(out)

	// Try to parse XML output even if command failed
	var result models.NmapRun
	if parseErr := xml.Unmarshal(xmlOutput, &result); parseErr == nil && (len(result.Hosts) > 0 || result.Start != "") {
		fmt.Printf("[NMAP] Parsed successfully: %d hosts, start=%s\n", len(result.Hosts), result.Start)
		return &result, nil
	}

	// If parsing failed and command failed, return command error
	if err != nil {
		return nil, fmt.Errorf("nmap command failed for %s: %w (output: %s)", req.IP, err, string(out))
	}

	// XML parsing failed but command succeeded
	return &result, nil
}

// extractXML extracts XML portion from nmap output
// NSE scripts (especially broadcast-*) may print warnings to stdout that break XML parsing
func extractXML(output []byte) []byte {
	// Find XML declaration start
	start := bytes.Index(output, []byte("<?xml"))
	if start == -1 {
		return output // No XML declaration, return as-is
	}

	// Find closing tag
	end := bytes.LastIndex(output, []byte("</nmaprun>"))
	if end == -1 {
		return output[start:] // Return from XML start to end
	}

	return output[start : end+len("</nmaprun>")]
}

// buildNmapArgs constructs nmap command line arguments from request
func buildNmapArgs(req ScanRequest) []string {
	// Base args: XML output, no DNS resolution
	args := []string{"-oX", "-", "-n"}

	// Scan technique
	if req.UseRaw {
		args = append(args, "-sS") // SYN scan (requires root)
	} else {
		args = append(args, "-sT") // TCP connect scan
	}

	// Skip ping (assume host is up)
	args = append(args, "-Pn")

	// Timing template
	if req.Timing != "" {
		args = append(args, "-"+req.Timing)
	} else {
		args = append(args, "-T2") // Default: polite timing
	}

	// Timeout settings (auto-adjust based on scan level)
	args = append(args, "--max-retries", "1")
	if req.Timeout != "" {
		args = append(args, "--host-timeout", req.Timeout)
	} else {
		// Auto-timeout: 300s for deep scans, 60s for basic
		if req.Level == "deep" || req.Level == "deepsafe" {
			args = append(args, "--host-timeout", "300s")
		} else {
			args = append(args, "--host-timeout", "60s")
		}
	}

	// Deep scanning options based on Level
	if req.Level == "deep" {
		args = append(args, "-sV", "-sC") // Service version + default scripts
	} else if req.Level == "deepsafe" {
		args = append(args, "-sV", "--script", "default and safe")
	} else if req.Level == "custom" && req.CustomScripts != "" {
		args = append(args, "-sV", "--script", req.CustomScripts)
	} else if req.Level == "basic" {
		// Basic scan: no additional options
	}

	// Port specification
	if len(req.Ports) > 0 {
		portList := ""
		for i, p := range req.Ports {
			if i > 0 {
				portList += ","
			}
			portList += p
		}
		args = append(args, "-p", portList)
	}

	// Target IP
	args = append(args, req.IP)

	return args
}
