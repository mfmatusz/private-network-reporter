// Package models contains shared data structures used across the application
package models

import "encoding/xml"

// NmapRun represents the root element of nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Start   string   `xml:"startstr,attr"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a single scanned host
type Host struct {
	Status    *Status    `xml:"status" json:"status"`
	Addresses []Address  `xml:"address" json:"addresses"`
	Hostnames *Hostnames `xml:"hostnames" json:"hostnames,omitempty"`
	Ports     *Ports     `xml:"ports" json:"ports,omitempty"`
}

// Status represents host up/down status
type Status struct {
	State string `xml:"state,attr" json:"state"`
}

// Address represents an IP or MAC address
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"type"`
}

// Hostnames contains list of hostnames
type Hostnames struct {
	List []Hostname `xml:"hostname" json:"list"`
}

// Hostname represents a single hostname
type Hostname struct {
	Name string `xml:"name,attr" json:"name"`
	Type string `xml:"type,attr" json:"type"`
}

// Ports contains list of scanned ports
type Ports struct {
	List []Port `xml:"port" json:"list"`
}

// Port represents a single scanned port
type Port struct {
	Protocol string      `xml:"protocol,attr" json:"protocol"`
	PortID   int         `xml:"portid,attr" json:"port"`
	State    *PState     `xml:"state" json:"state"`
	Service  *Service    `xml:"service" json:"service,omitempty"`
	Scripts  []NSEScript `xml:"script" json:"scripts,omitempty"`
}

// PState represents port state (open/closed/filtered)
type PState struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

// Service represents detected service information
type Service struct {
	Name    string `xml:"name,attr" json:"name"`
	Product string `xml:"product,attr" json:"product,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
}

// NSEScript represents output from Nmap Scripting Engine
type NSEScript struct {
	ID     string `xml:"id,attr" json:"id"`
	Output string `xml:"output,attr" json:"output"`
}

// Event represents network event from RouterOS webhook
type Event struct {
	Source   string `json:"source"`           // dhcp|netwatch|wifi|arp
	Action   string `json:"action,omitempty"` // bound|deassigned|expired
	State    string `json:"state,omitempty"`  // up|down
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// ARPEntry represents a single ARP table entry
type ARPEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}
