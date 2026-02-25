package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
	"github.com/mfmatusz/private-network-reporter/pkg/store"
)

func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	db, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func truncSec(ts time.Time) time.Time {
	return ts.Truncate(time.Second)
}

// ── UpsertEndpoint ────────────────────────────────────────────────────────────

func TestUpsertEndpoint(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	// Insert new endpoint
	if err := db.UpsertEndpoint("10.0.0.1", "aa:bb:cc:dd:ee:ff", "host1", "pc", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mac, err := db.GetMACForIP("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:ff, got %q", mac)
	}

	// Upsert with a new non-empty MAC – should overwrite
	if err := db.UpsertEndpoint("10.0.0.1", "11:22:33:44:55:66", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mac, _ = db.GetMACForIP("10.0.0.1")
	if mac != "11:22:33:44:55:66" {
		t.Errorf("expected updated MAC 11:22:33:44:55:66, got %q", mac)
	}

	// Upsert with empty MAC – should NOT overwrite existing MAC (COALESCE)
	if err := db.UpsertEndpoint("10.0.0.1", "", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mac, _ = db.GetMACForIP("10.0.0.1")
	if mac != "11:22:33:44:55:66" {
		t.Errorf("COALESCE: expected MAC unchanged 11:22:33:44:55:66, got %q", mac)
	}
}

// ── MarkScanned ───────────────────────────────────────────────────────────────

func TestMarkScanned(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	// Insert endpoint then mark scanned
	if err := db.UpsertEndpoint("10.0.0.2", "de:ad:be:ef:00:01", "h2", "pc", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scanTime := truncSec(now.Add(time.Minute))
	if err := db.MarkScanned("10.0.0.2", scanTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ts, err := db.GetLastScanTime("10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.Equal(scanTime) {
		t.Errorf("expected last_scan_at %v, got %v", scanTime, ts)
	}

	// MarkScanned on non-existent IP must not error
	if err := db.MarkScanned("192.168.99.99", now); err != nil {
		t.Errorf("expected no error for unknown IP, got: %v", err)
	}

	// Two endpoints share the same MAC → MarkScanned one propagates to both
	mac := "ff:ee:dd:cc:bb:aa"
	if err := db.UpsertEndpoint("10.0.0.3", mac, "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := db.UpsertEndpoint("10.0.0.4", mac, "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sharedTime := truncSec(now.Add(2 * time.Minute))
	if err := db.MarkScanned("10.0.0.3", sharedTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ts4, err := db.GetLastScanTime("10.0.0.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts4.Equal(sharedTime) {
		t.Errorf("expected shared MAC propagation: %v, got %v", sharedTime, ts4)
	}
}

// ── GetMACForIP ───────────────────────────────────────────────────────────────

func TestGetMACForIP(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	// Unknown IP → empty string, no error
	mac, err := db.GetMACForIP("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mac != "" {
		t.Errorf("expected empty string for unknown IP, got %q", mac)
	}

	// Known IP returns MAC
	if err := db.UpsertEndpoint("1.2.3.4", "ca:fe:ba:be:00:00", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mac, err = db.GetMACForIP("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mac != "ca:fe:ba:be:00:00" {
		t.Errorf("expected ca:fe:ba:be:00:00, got %q", mac)
	}
}

// ── EndpointsNeedingScan ──────────────────────────────────────────────────────

func TestEndpointsNeedingScan(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())
	cutoff := now

	// NULL last_scan_at + up=1 → included
	if err := db.UpsertEndpoint("10.1.0.1", "", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old last_scan_at (before cutoff) + up=1 → included
	if err := db.UpsertEndpoint("10.1.0.2", "", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	old := truncSec(now.Add(-2 * time.Hour))
	if err := db.MarkScanned("10.1.0.2", old); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Recent last_scan_at (after cutoff) → NOT included
	if err := db.UpsertEndpoint("10.1.0.3", "", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	recent := truncSec(now.Add(time.Hour))
	if err := db.MarkScanned("10.1.0.3", recent); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// up=0 → NOT included
	if err := db.UpsertEndpoint("10.1.0.4", "", "", "", now, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ips, err := db.EndpointsNeedingScan(cutoff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ipSet := make(map[string]bool)
	for _, ip := range ips {
		ipSet[ip] = true
	}

	if !ipSet["10.1.0.1"] {
		t.Error("10.1.0.1 (NULL last_scan_at) should be returned")
	}
	if !ipSet["10.1.0.2"] {
		t.Error("10.1.0.2 (old scan) should be returned")
	}
	if ipSet["10.1.0.3"] {
		t.Error("10.1.0.3 (recent scan) should NOT be returned")
	}
	if ipSet["10.1.0.4"] {
		t.Error("10.1.0.4 (up=0) should NOT be returned")
	}
}

// ── IngestARP ─────────────────────────────────────────────────────────────────

func TestIngestARP(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	entries := []models.ARPEntry{
		{IP: "172.16.0.1", MAC: "01:02:03:04:05:06"},
		{IP: "172.16.0.2", MAC: "07:08:09:0a:0b:0c"},
	}

	if err := db.IngestARP(entries, now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, e := range entries {
		mac, err := db.GetMACForIP(e.IP)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", e.IP, err)
		}
		if mac != e.MAC {
			t.Errorf("IP %s: expected MAC %s, got %s", e.IP, e.MAC, mac)
		}
	}

	// Re-ingest with empty MAC – existing MAC must be kept (COALESCE)
	emptyEntries := []models.ARPEntry{{IP: "172.16.0.1", MAC: ""}}
	if err := db.IngestARP(emptyEntries, now); err != nil {
		t.Fatalf("unexpected error on re-ingest: %v", err)
	}
	mac, _ := db.GetMACForIP("172.16.0.1")
	if mac != "01:02:03:04:05:06" {
		t.Errorf("COALESCE: expected original MAC preserved, got %q", mac)
	}
}

// ── InsertScan ────────────────────────────────────────────────────────────────

func TestInsertScan(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	id1, err := db.InsertScan("10.0.0.1", "nmap", now, now.Add(time.Second), `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 <= 0 {
		t.Errorf("expected scan ID > 0, got %d", id1)
	}

	id2, err := db.InsertScan("10.0.0.1", "nmap", now, now.Add(time.Second), `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id2 == id1 {
		t.Errorf("expected different scan IDs, both were %d", id1)
	}
}

// ── InsertPorts ───────────────────────────────────────────────────────────────

func TestInsertPorts(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	scanID, err := db.InsertScan("10.0.0.1", "nmap", now, now.Add(time.Second), `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ports := []models.Port{
		{Protocol: "tcp", PortID: 80, State: &models.PState{State: "open"}, Service: &models.Service{Name: "http"}},
		{Protocol: "tcp", PortID: 443, State: &models.PState{State: "open"}, Service: &models.Service{Name: "https"}},
	}
	if err := db.InsertPorts(scanID, "10.0.0.1", ports); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify via GetTopPorts
	topPorts, err := db.GetTopPorts(now.Add(-time.Second), now.Add(2*time.Second), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(topPorts) != 2 {
		t.Errorf("expected 2 port entries, got %d", len(topPorts))
	}

	// Empty ports slice → no error
	if err := db.InsertPorts(scanID, "10.0.0.1", nil); err != nil {
		t.Errorf("unexpected error for nil ports: %v", err)
	}
	if err := db.InsertPorts(scanID, "10.0.0.1", []models.Port{}); err != nil {
		t.Errorf("unexpected error for empty ports: %v", err)
	}
}

// ── GetScansInWindow ──────────────────────────────────────────────────────────

func TestGetScansInWindow(t *testing.T) {
	db := newTestStore(t)
	base := truncSec(time.Now().UTC())

	t1 := base.Add(-3 * time.Hour)
	t2 := base.Add(-2 * time.Hour)
	t3 := base.Add(-1 * time.Hour)
	outside := base.Add(-5 * time.Hour)

	for _, ts := range []time.Time{t1, t2, t3} {
		if _, err := db.InsertScan("10.0.0.5", "nmap", ts, ts.Add(time.Second), `{}`); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// Insert one outside window
	if _, err := db.InsertScan("10.0.0.5", "nmap", outside, outside.Add(time.Second), `{}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	from := base.Add(-4 * time.Hour)
	to := base

	scans, err := db.GetScansInWindow(from, to, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans in window, got %d", len(scans))
	}

	// Results should be ordered DESC (newest first)
	if len(scans) >= 2 && scans[0].StartedAt.Before(scans[1].StartedAt) {
		t.Error("expected results ordered by started_at DESC")
	}

	// Nothing returned outside window
	noScans, err := db.GetScansInWindow(base.Add(-10*time.Hour), base.Add(-6*time.Hour), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noScans) != 0 {
		t.Errorf("expected 0 scans outside window, got %d", len(noScans))
	}
}

// ── GetTopPorts ───────────────────────────────────────────────────────────────

func TestGetTopPorts(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	// Scan 1: ports 80 (open), 443 (open), 22 (closed)
	id1, err := db.InsertScan("10.0.0.10", "nmap", now, now.Add(time.Second), `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = db.InsertPorts(id1, "10.0.0.10", []models.Port{
		{Protocol: "tcp", PortID: 80, State: &models.PState{State: "open"}},
		{Protocol: "tcp", PortID: 443, State: &models.PState{State: "open"}},
		{Protocol: "tcp", PortID: 22, State: &models.PState{State: "closed"}},
	})

	// Scan 2: port 80 open again
	id2, err := db.InsertScan("10.0.0.11", "nmap", now, now.Add(time.Second), `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = db.InsertPorts(id2, "10.0.0.11", []models.Port{
		{Protocol: "tcp", PortID: 80, State: &models.PState{State: "open"}},
	})

	topPorts, err := db.GetTopPorts(now.Add(-time.Second), now.Add(2*time.Second), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Port 80 should appear first with count 2
	if len(topPorts) == 0 {
		t.Fatal("expected at least one port result")
	}
	if topPorts[0].Port != 80 {
		t.Errorf("expected port 80 first, got %d", topPorts[0].Port)
	}
	if topPorts[0].Count != 2 {
		t.Errorf("expected port 80 count=2, got %d", topPorts[0].Count)
	}

	// Port 22 (closed) must not appear
	for _, pc := range topPorts {
		if pc.Port == 22 {
			t.Error("closed port 22 should not appear in top ports")
		}
	}

	// Results ordered DESC by count
	for i := 1; i < len(topPorts); i++ {
		if topPorts[i].Count > topPorts[i-1].Count {
			t.Error("expected top ports ordered by count DESC")
		}
	}
}

// ── SaveScan ──────────────────────────────────────────────────────────────────

func TestSaveScan(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	result := &models.NmapRun{
		Hosts: []models.Host{
			{
				Addresses: []models.Address{{Addr: "10.0.0.20", AddrType: "ipv4"}},
				Ports: &models.Ports{
					List: []models.Port{
						{Protocol: "tcp", PortID: 8080, State: &models.PState{State: "open"}},
					},
				},
			},
		},
	}

	if err := db.SaveScan("10.0.0.20", "nmap", now, now.Add(time.Second), result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scans, err := db.GetScansInWindow(now.Add(-time.Second), now.Add(2*time.Second), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("expected 1 scan after SaveScan, got %d", len(scans))
	}
}

// ── VacuumAnalyze ─────────────────────────────────────────────────────────────

func TestVacuumAnalyze(t *testing.T) {
	db := newTestStore(t)
	if err := db.VacuumAnalyze(); err != nil {
		t.Errorf("VacuumAnalyze returned error: %v", err)
	}
}

// ── GetLastScanTime ───────────────────────────────────────────────────────────

func TestGetLastScanTime(t *testing.T) {
	db := newTestStore(t)
	now := truncSec(time.Now().UTC())

	// Unknown MAC/IP → zero time, no error
	ts, err := db.GetLastScanTime("unknown-mac")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.IsZero() {
		t.Errorf("expected zero time for unknown identifier, got %v", ts)
	}

	// After MarkScanned by IP
	if err := db.UpsertEndpoint("10.0.0.30", "", "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scanTime := truncSec(now.Add(time.Minute))
	if err := db.MarkScanned("10.0.0.30", scanTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ts, err = db.GetLastScanTime("10.0.0.30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.Equal(scanTime) {
		t.Errorf("expected %v, got %v", scanTime, ts)
	}

	// After UpsertEndpoint with MAC and MarkScanned, GetLastScanTime by MAC returns the time
	mac := "ab:cd:ef:01:23:45"
	if err := db.UpsertEndpoint("10.0.0.31", mac, "", "", now, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	macScanTime := truncSec(now.Add(2 * time.Minute))
	if err := db.MarkScanned("10.0.0.31", macScanTime); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ts, err = db.GetLastScanTime(mac)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.Equal(macScanTime) {
		t.Errorf("GetLastScanTime by MAC: expected %v, got %v", macScanTime, ts)
	}
}
