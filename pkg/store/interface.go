// Package store provides data persistence interfaces and implementations
package store

import (
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

// Repository defines the interface for data persistence operations
type Repository interface {
	// Endpoint management
	UpsertEndpoint(ip, mac, hostname, typ string, seen time.Time, up bool) error
	MarkScanned(ip string, ts time.Time) error
	GetMACForIP(ip string) (string, error)
	EndpointsNeedingScan(cutoff time.Time) ([]string, error)
	GetEndpointsNeedingScan(cutoff time.Time) ([]string, error)
	GetLastScanTime(macOrIP string) (time.Time, error)

	// Scan results
	InsertScan(ip, scanType string, started, finished time.Time, resultJSON string) (int64, error)
	InsertPorts(scanID int64, ip string, ports []models.Port) error
	SaveScan(ip, scanType string, started, finished time.Time, result *models.NmapRun) error

	// ARP ingestion
	IngestARP(entries []models.ARPEntry, ts time.Time) error

	// Maintenance
	VacuumAnalyze() error

	// Report queries
	GetScansInWindow(from, to time.Time, limit int) ([]ScanRecord, error)
	GetTopPorts(from, to time.Time, limit int) ([]PortCount, error)

	// Close releases database resources
	Close() error
}

// ScanRecord represents a scan result with metadata
type ScanRecord struct {
	ID         int64
	IP         string
	StartedAt  time.Time
	FinishedAt time.Time
	ScanType   string
	ResultJSON string
}

// PortCount represents port usage statistics
type PortCount struct {
	Port  int
	Count int
}
