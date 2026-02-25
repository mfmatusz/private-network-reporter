// Package store provides SQLite-based data persistence
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

//go:embed schema.sql
var schemaFS embed.FS

// SQLiteStore implements Repository interface using SQLite database
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite store at the given path
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure for concurrency (WAL mode allows concurrent reads)
	// Lower connection count reduces lock contention for writes
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)

	// Enable WAL mode and optimize settings
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA temp_store=MEMORY;",
		"PRAGMA busy_timeout=30000;", // 30 seconds - allow more time for lock contention
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	// Load and execute schema
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to read schema: %w", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to execute schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// UpsertEndpoint inserts or updates endpoint information
func (s *SQLiteStore) UpsertEndpoint(ip, mac, hostname, typ string, seen time.Time, up bool) error {
	_, err := s.db.Exec(`
		INSERT INTO endpoints(ip, mac, hostname, type, first_seen, last_seen, last_scan_at, up)
		VALUES(?,?,?,?,?,?,NULL,?)
		ON CONFLICT(ip) DO UPDATE SET
		  mac=COALESCE(NULLIF(excluded.mac, ''), endpoints.mac),
		  hostname=COALESCE(NULLIF(excluded.hostname, ''), endpoints.hostname),
		  type=COALESCE(NULLIF(excluded.type, ''), endpoints.type),
		  last_seen=excluded.last_seen,
		  up=excluded.up
	`, ip, mac, hostname, typ, seen, seen, boolToInt(up))
	if err != nil {
		return fmt.Errorf("upsert endpoint %s failed: %w", ip, err)
	}
	return nil
}

// MarkScanned updates the last_scan_at timestamp for an endpoint
func (s *SQLiteStore) MarkScanned(ip string, ts time.Time) error {
	// Update last_scan_at for the IP endpoint
	_, err := s.db.Exec(`UPDATE endpoints SET last_scan_at=? WHERE ip=?`, ts, ip)
	if err != nil {
		return fmt.Errorf("mark scanned %s failed: %w", ip, err)
	}

	// Also update all endpoints with the same MAC (per-MAC cooldown)
	// This ensures cooldown works correctly when device has multiple IPs or IP changes
	_, err = s.db.Exec(`
		UPDATE endpoints 
		SET last_scan_at=? 
		WHERE mac IS NOT NULL 
		  AND mac != '' 
		  AND mac = (SELECT mac FROM endpoints WHERE ip=? AND mac IS NOT NULL LIMIT 1)
	`, ts, ip)
	if err != nil {
		return fmt.Errorf("mark scanned (per-MAC) for %s failed: %w", ip, err)
	}

	return nil
}

// GetMACForIP retrieves the MAC address for a given IP
func (s *SQLiteStore) GetMACForIP(ip string) (string, error) {
	var mac string
	err := s.db.QueryRow(`SELECT mac FROM endpoints WHERE ip=? AND mac IS NOT NULL LIMIT 1`, ip).Scan(&mac)
	if err == sql.ErrNoRows {
		return "", nil // Not an error, just no MAC found
	}
	if err != nil {
		return "", fmt.Errorf("get MAC for %s failed: %w", ip, err)
	}
	return mac, nil
}

// EndpointsNeedingScan returns IPs that haven't been scanned since cutoff time
func (s *SQLiteStore) EndpointsNeedingScan(cutoff time.Time) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT ip FROM endpoints
		WHERE (last_scan_at IS NULL OR last_scan_at < ?)
		  AND up=1
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query endpoints needing scan failed: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue // Skip malformed rows
		}
		ips = append(ips, ip)
	}

	return ips, rows.Err()
}

// InsertScan stores a scan result and returns the scan ID
// Retries on SQLITE_BUSY to handle write contention
func (s *SQLiteStore) InsertScan(ip, scanType string, started, finished time.Time, resultJSON string) (int64, error) {
	var res sql.Result
	var err error

	// Retry up to 3 times on busy errors
	for attempt := 0; attempt < 3; attempt++ {
		res, err = s.db.Exec(`
			INSERT INTO scans(ip, started_at, finished_at, scan_type, result_json)
			VALUES(?,?,?,?,?)
		`, ip, started, finished, scanType, resultJSON)

		if err == nil {
			break // Success
		}

		// Check if error is SQLITE_BUSY
		if attempt < 2 && (err.Error() == "database is locked (5) (SQLITE_BUSY)" ||
			err.Error() == "database is locked") {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
			continue
		}
		break
	}

	if err != nil {
		return 0, fmt.Errorf("insert scan for %s failed: %w", ip, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id failed: %w", err)
	}
	return id, nil
}

// InsertPorts stores port scan results for a given scan ID
func (s *SQLiteStore) InsertPorts(scanID int64, ip string, ports []models.Port) error {
	if len(ports) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction failed: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO ports(scan_id, ip, port, proto, state, service, product, version)
		VALUES(?,?,?,?,?,?,?,?)
	`)
	if err != nil {
		return fmt.Errorf("prepare statement failed: %w", err)
	}
	defer stmt.Close()

	for _, p := range ports {
		svc, prod, ver := "", "", ""
		if p.Service != nil {
			svc = p.Service.Name
			prod = p.Service.Product
			ver = p.Service.Version
		}
		state := ""
		if p.State != nil {
			state = p.State.State
		}

		if _, err := stmt.Exec(scanID, ip, p.PortID, p.Protocol, state, svc, prod, ver); err != nil {
			return fmt.Errorf("insert port %d failed: %w", p.PortID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction failed: %w", err)
	}
	return nil
}

// IngestARP stores ARP table entries
func (s *SQLiteStore) IngestARP(entries []models.ARPEntry, ts time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction failed: %w", err)
	}
	defer tx.Rollback()

	for _, e := range entries {
		if _, err := tx.Exec(`
			INSERT INTO endpoints(ip, mac, first_seen, last_seen, up)
			VALUES(?,?,?,?,1)
			ON CONFLICT(ip) DO UPDATE SET
			  mac=COALESCE(NULLIF(excluded.mac, ''), endpoints.mac),
			  last_seen=?,
			  up=1
		`, e.IP, e.MAC, ts, ts, ts); err != nil {
			return fmt.Errorf("ingest ARP entry %s failed: %w", e.IP, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction failed: %w", err)
	}
	return nil
}

// VacuumAnalyze performs database maintenance
func (s *SQLiteStore) VacuumAnalyze() error {
	if _, err := s.db.Exec(`PRAGMA optimize; VACUUM; ANALYZE;`); err != nil {
		return fmt.Errorf("vacuum analyze failed: %w", err)
	}
	return nil
}

// GetScansInWindow retrieves scans within a time window
func (s *SQLiteStore) GetScansInWindow(from, to time.Time, limit int) ([]ScanRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, ip, started_at, finished_at, scan_type, result_json
		FROM scans
		WHERE started_at BETWEEN ? AND ?
		ORDER BY started_at DESC
		LIMIT ?
	`, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("query scans in window failed: %w", err)
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.IP, &s.StartedAt, &s.FinishedAt, &s.ScanType, &s.ResultJSON); err != nil {
			continue
		}
		scans = append(scans, s)
	}

	return scans, rows.Err()
}

// GetTopPorts returns most commonly open ports in a time window
func (s *SQLiteStore) GetTopPorts(from, to time.Time, limit int) ([]PortCount, error) {
	rows, err := s.db.Query(`
		SELECT port, COUNT(*) as c
		FROM ports
		WHERE scan_id IN (
			SELECT id FROM scans WHERE started_at BETWEEN ? AND ?
		) AND state='open'
		GROUP BY port
		ORDER BY c DESC
		LIMIT ?
	`, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("query top ports failed: %w", err)
	}
	defer rows.Close()

	var ports []PortCount
	for rows.Next() {
		var pc PortCount
		if err := rows.Scan(&pc.Port, &pc.Count); err != nil {
			continue
		}
		ports = append(ports, pc)
	}

	return ports, rows.Err()
}

// GetEndpointsNeedingScan returns endpoints that haven't been scanned since cutoff time
func (s *SQLiteStore) GetEndpointsNeedingScan(cutoff time.Time) ([]string, error) {
	return s.EndpointsNeedingScan(cutoff)
}

// GetLastScanTime returns the last scan time for a MAC address (or IP as fallback)
// This implements per-MAC cooldown: the same physical device (MAC) should not be
// scanned more frequently than the cooldown period, even if it changes IP addresses.
// If MAC is empty/unknown, falls back to IP-based lookup.
func (s *SQLiteStore) GetLastScanTime(macOrIP string) (time.Time, error) {
	var tsStr sql.NullString

	// Try MAC first (preferred - identifies physical device)
	err := s.db.QueryRow(`
		SELECT last_scan_at
		FROM endpoints
		WHERE mac = ? AND mac != '' AND mac IS NOT NULL
		ORDER BY last_scan_at DESC
		LIMIT 1
	`, macOrIP).Scan(&tsStr)

	if err == nil && tsStr.Valid {
		return time.Parse(time.RFC3339, tsStr.String) // Found by MAC
	}

	if err != nil && err != sql.ErrNoRows {
		return time.Time{}, fmt.Errorf("get last scan time by MAC failed: %w", err)
	}

	// Fallback to IP (when MAC is unknown or not provided)
	err = s.db.QueryRow(`
		SELECT last_scan_at
		FROM endpoints
		WHERE ip = ?
	`, macOrIP).Scan(&tsStr)

	if err == sql.ErrNoRows || !tsStr.Valid {
		return time.Time{}, nil // Never scanned
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get last scan time by IP failed: %w", err)
	}

	return time.Parse(time.RFC3339, tsStr.String)
}

// SaveScan is a convenience method that saves scan results in one transaction
func (s *SQLiteStore) SaveScan(ip, scanType string, started, finished time.Time, result *models.NmapRun) error {
	// Marshal result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal scan result failed: %w", err)
	}

	// Insert scan record
	scanID, err := s.InsertScan(ip, scanType, started, finished, string(resultJSON))
	if err != nil {
		return err
	}

	// Mark endpoint as scanned
	if err := s.MarkScanned(ip, finished); err != nil {
		return err
	}

	// Insert port data if available
	if result != nil && len(result.Hosts) > 0 {
		for _, host := range result.Hosts {
			if host.Ports != nil && len(host.Ports.List) > 0 {
				if err := s.InsertPorts(scanID, ip, host.Ports.List); err != nil {
					return err
				}
			}

			// Update endpoint metadata heuristically
			var mac, hostname string
			for _, addr := range host.Addresses {
				if addr.AddrType == "mac" {
					mac = addr.Addr
					break
				}
			}
			if host.Hostnames != nil && len(host.Hostnames.List) > 0 {
				hostname = host.Hostnames.List[0].Name
			}
			if mac != "" || hostname != "" {
				_ = s.UpsertEndpoint(ip, mac, hostname, classifyEndpoint(mac, hostname), finished, true)
			}
		}
	}

	return nil
}

// Close releases database resources
func (s *SQLiteStore) Close() error {
	// Perform WAL checkpoint to ensure all data is written to main database file
	// TRUNCATE mode also removes the WAL file after checkpoint
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		// Log error but continue with close - checkpoint failure shouldn't prevent cleanup
		fmt.Printf("warning: WAL checkpoint failed: %v\n", err)
	}

	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close database failed: %w", err)
	}
	return nil
}

// Helper functions
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// classifyEndpoint returns endpoint type based on MAC/hostname heuristics
func classifyEndpoint(mac, hostname string) string {
	// Add basic classification logic here
	if hostname != "" {
		return "host"
	}
	return "unknown"
}
