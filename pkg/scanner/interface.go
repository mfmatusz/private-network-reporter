// Package scanner provides network scanning capabilities
package scanner

import (
	"context"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

// Scanner defines the interface for network scanning operations
type Scanner interface {
	// ScanTarget performs a network scan on the given IP address
	ScanTarget(ctx context.Context, req ScanRequest) (*models.NmapRun, error)
}

// ScanRequest contains parameters for a network scan
type ScanRequest struct {
	IP            string   // Target IP address
	Ports         []string // Port list to scan (e.g., ["22", "80", "443"])
	UseRaw        bool     // Use raw sockets (-sS) vs TCP connect (-sT)
	Level         string   // Scan level: "basic" (fast), "deep" (NSE+scripts), "deepsafe" (safe scripts only), "custom"
	Timeout       string   // Host timeout (e.g., "60s" for basic, "300s" for deep)
	Timing        string   // Timing template (T2, T3, T4)
	CustomScripts string   // NSE scripts for "custom" level (e.g., "http-title,ssh-hostkey,vulners")
}
