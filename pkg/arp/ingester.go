// Package arp provides local ARP table monitoring for network endpoint discovery (additional functionality).
// It parses the Linux kernel's /proc/net/arp file to detect active hosts on the local network.
package arp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

// Entry represents a single ARP table entry from /proc/net/arp
type Entry struct {
	IP     string
	HWType string
	Flags  string
	HWAddr string
	Mask   string
	Device string
}

// ParseARPTable reads and parses /proc/net/arp file.
// Returns a slice of Entry structs containing IP and MAC addresses.
// The file format is:
// IP address       HW type     Flags       HW address            Mask     Device
// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
func ParseARPTable() ([]Entry, error) {
	// Check if /proc/net/arp exists (Linux only)
	if _, err := os.Stat("/proc/net/arp"); os.IsNotExist(err) {
		return nil, fmt.Errorf("ARP table not available: /proc/net/arp does not exist (Linux only)")
	}

	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/arp: %w", err)
	}
	defer file.Close()

	var entries []Entry
	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return entries, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Expected format: IP HWType Flags HWAddr Mask Device
		if len(fields) < 6 {
			continue
		}

		ip := fields[0]
		hwAddr := fields[3]

		// Skip incomplete entries (0x0 flags = incomplete)
		if fields[2] == "0x0" {
			continue
		}

		// Skip invalid MAC addresses
		if hwAddr == "00:00:00:00:00:00" || hwAddr == "*" {
			continue
		}

		// Validate IP address
		if net.ParseIP(ip) == nil {
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

	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("error reading /proc/net/arp: %w", err)
	}

	return entries, nil
}

// ToARPEntries converts parsed ARP entries to models.ARPEntry format
// suitable for database ingestion via store.IngestARP()
func ToARPEntries(entries []Entry) []models.ARPEntry {
	result := make([]models.ARPEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, models.ARPEntry{
			IP:  e.IP,
			MAC: e.HWAddr,
		})
	}
	return result
}
