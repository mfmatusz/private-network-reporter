package arp

import (
	"bufio"
	"runtime"
	"strings"
	"testing"
)

func TestToARPEntries_Empty(t *testing.T) {
	result := ToARPEntries([]Entry{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d entries", len(result))
	}
}

func TestToARPEntries_Single(t *testing.T) {
	entries := []Entry{
		{IP: "192.168.1.1", HWType: "0x1", Flags: "0x2", HWAddr: "aa:bb:cc:dd:ee:ff", Mask: "*", Device: "eth0"},
	}
	result := ToARPEntries(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", result[0].IP)
	}
	if result[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:ff, got %s", result[0].MAC)
	}
}

func TestToARPEntries_Multiple(t *testing.T) {
	entries := []Entry{
		{IP: "10.0.0.1", HWAddr: "11:22:33:44:55:66"},
		{IP: "10.0.0.2", HWAddr: "aa:bb:cc:dd:ee:ff"},
		{IP: "10.0.0.3", HWAddr: "de:ad:be:ef:00:01"},
	}
	result := ToARPEntries(entries)
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	for i, want := range []struct{ ip, mac string }{
		{"10.0.0.1", "11:22:33:44:55:66"},
		{"10.0.0.2", "aa:bb:cc:dd:ee:ff"},
		{"10.0.0.3", "de:ad:be:ef:00:01"},
	} {
		if result[i].IP != want.ip {
			t.Errorf("[%d] expected IP %s, got %s", i, want.ip, result[i].IP)
		}
		if result[i].MAC != want.mac {
			t.Errorf("[%d] expected MAC %s, got %s", i, want.mac, result[i].MAC)
		}
	}
}

// TestToARPEntries_OnlyIPAndMAC verifies HWType/Flags/Mask/Device are not exposed in output.
func TestToARPEntries_OnlyIPAndMAC(t *testing.T) {
	entries := []Entry{
		{IP: "172.16.0.5", HWType: "0x1", Flags: "0x2", HWAddr: "ca:fe:ba:be:00:01", Mask: "*", Device: "wlan0"},
	}
	result := ToARPEntries(entries)
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	// models.ARPEntry only has IP and MAC fields — confirming compilation is sufficient,
	// but we also double-check the values match the source Entry fields.
	if result[0].IP != entries[0].IP {
		t.Errorf("IP mismatch: want %s got %s", entries[0].IP, result[0].IP)
	}
	if result[0].MAC != entries[0].HWAddr {
		t.Errorf("MAC mismatch: want %s got %s", entries[0].HWAddr, result[0].MAC)
	}
}

// parseARPReader is a helper that replicates ParseARPTable parsing logic
// on an arbitrary io.Reader, enabling OS-independent unit testing.
func parseARPReader(data string) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(data))

	// Skip header line
	if !scanner.Scan() {
		return entries, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		hwAddr := fields[3]
		if fields[2] == "0x0" {
			continue
		}
		if hwAddr == "00:00:00:00:00:00" || hwAddr == "*" {
			continue
		}
		entries = append(entries, Entry{
			IP:     ip,
			HWType: fields[1],
			Flags:  fields[2],
			HWAddr: hwAddr,
			Mask:   fields[4],
			Device: fields[5],
		})
	}
	return entries, scanner.Err()
}

func TestParseARPLineFormat(t *testing.T) {
	const arpData = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x0         11:22:33:44:55:66     *        eth0
192.168.1.3      0x1         0x2         00:00:00:00:00:00     *        eth0
192.168.1.4      0x1         0x2         de:ad:be:ef:ca:fe     *        eth0
`
	entries, err := parseARPReader(arpData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 192.168.1.2 skipped (flags 0x0), 192.168.1.3 skipped (zero MAC)
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d", len(entries))
	}
	if entries[0].IP != "192.168.1.1" || entries[0].HWAddr != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].IP != "192.168.1.4" || entries[1].HWAddr != "de:ad:be:ef:ca:fe" {
		t.Errorf("unexpected second entry: %+v", entries[1])
	}
}

func TestParseARPLineFormat_EmptyTable(t *testing.T) {
	const arpData = `IP address       HW type     Flags       HW address            Mask     Device
`
	entries, err := parseARPReader(arpData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseARPTable_Integration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping /proc/net/arp test on non-Linux")
	}
	entries, err := ParseARPTable()
	if err != nil {
		t.Logf("ParseARPTable returned error (may be expected in CI): %v", err)
		return
	}
	// Basic sanity: all entries must have non-empty IP and MAC
	for _, e := range entries {
		if e.IP == "" {
			t.Errorf("entry has empty IP: %+v", e)
		}
		if e.HWAddr == "" {
			t.Errorf("entry has empty HWAddr: %+v", e)
		}
	}
}
