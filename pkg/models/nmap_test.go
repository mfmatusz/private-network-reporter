package models_test

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/mfmatusz/private-network-reporter/pkg/models"
)

const fullNmapXML = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" startstr="Wed Feb 25 12:00:00 2026">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
    <hostnames>
      <hostname name="myhost.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
        <script id="ssh-hostkey" output="2048 aa:bb:cc:dd"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="conn-refused"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestNmapRun_ParseFullXML(t *testing.T) {
	var run models.NmapRun
	if err := xml.Unmarshal([]byte(fullNmapXML), &run); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	if run.Start != "Wed Feb 25 12:00:00 2026" {
		t.Errorf("unexpected Start: %q", run.Start)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(run.Hosts))
	}
}

func TestNmapRun_HostStatus(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	host := run.Hosts[0]

	if host.Status == nil {
		t.Fatal("expected Status to be non-nil")
	}
	if host.Status.State != "up" {
		t.Errorf("expected state 'up', got %q", host.Status.State)
	}
}

func TestNmapRun_HostAddresses(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	host := run.Hosts[0]

	if len(host.Addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(host.Addresses))
	}

	var ipv4, mac string
	for _, a := range host.Addresses {
		switch a.AddrType {
		case "ipv4":
			ipv4 = a.Addr
		case "mac":
			mac = a.Addr
		}
	}
	if ipv4 != "192.168.1.100" {
		t.Errorf("expected IPv4 192.168.1.100, got %q", ipv4)
	}
	if mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:ff, got %q", mac)
	}
}

func TestNmapRun_Hostnames(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	host := run.Hosts[0]

	if host.Hostnames == nil {
		t.Fatal("expected Hostnames to be non-nil")
	}
	if len(host.Hostnames.List) != 1 {
		t.Fatalf("expected 1 hostname, got %d", len(host.Hostnames.List))
	}
	hn := host.Hostnames.List[0]
	if hn.Name != "myhost.local" {
		t.Errorf("expected hostname myhost.local, got %q", hn.Name)
	}
	if hn.Type != "PTR" {
		t.Errorf("expected type PTR, got %q", hn.Type)
	}
}

func TestNmapRun_Ports(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	host := run.Hosts[0]

	if host.Ports == nil {
		t.Fatal("expected Ports to be non-nil")
	}
	ports := host.Ports.List
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}

	p22 := ports[0]
	if p22.PortID != 22 {
		t.Errorf("expected portid 22, got %d", p22.PortID)
	}
	if p22.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %q", p22.Protocol)
	}
	if p22.State == nil || p22.State.State != "open" {
		t.Errorf("expected state open, got %v", p22.State)
	}

	p80 := ports[1]
	if p80.PortID != 80 {
		t.Errorf("expected portid 80, got %d", p80.PortID)
	}
	if p80.State == nil || p80.State.State != "closed" {
		t.Errorf("expected state closed, got %v", p80.State)
	}
}

func TestNmapRun_Service(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	port := run.Hosts[0].Ports.List[0]

	if port.Service == nil {
		t.Fatal("expected Service to be non-nil")
	}
	if port.Service.Name != "ssh" {
		t.Errorf("expected service name ssh, got %q", port.Service.Name)
	}
	if port.Service.Product != "OpenSSH" {
		t.Errorf("expected product OpenSSH, got %q", port.Service.Product)
	}
	if port.Service.Version != "8.9" {
		t.Errorf("expected version 8.9, got %q", port.Service.Version)
	}
}

func TestNmapRun_NSEScript(t *testing.T) {
	var run models.NmapRun
	xml.Unmarshal([]byte(fullNmapXML), &run) //nolint:errcheck
	port := run.Hosts[0].Ports.List[0]

	if len(port.Scripts) != 1 {
		t.Fatalf("expected 1 script, got %d", len(port.Scripts))
	}
	s := port.Scripts[0]
	if s.ID != "ssh-hostkey" {
		t.Errorf("expected script id ssh-hostkey, got %q", s.ID)
	}
	if s.Output != "2048 aa:bb:cc:dd" {
		t.Errorf("unexpected script output: %q", s.Output)
	}
}

func TestNmapRun_Empty(t *testing.T) {
	const emptyXML = `<nmaprun scanner="nmap" startstr=""></nmaprun>`
	var run models.NmapRun
	if err := xml.Unmarshal([]byte(emptyXML), &run); err != nil {
		t.Fatalf("unexpected error parsing empty nmaprun: %v", err)
	}
	if len(run.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(run.Hosts))
	}
}

// --- Event JSON tests ---

func TestEvent_JSONRoundtrip(t *testing.T) {
	orig := models.Event{
		Source:   "dhcp",
		Action:   "bound",
		State:    "up",
		IP:       "10.0.0.5",
		MAC:      "de:ad:be:ef:00:01",
		Hostname: "device.local",
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got models.Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if got != orig {
		t.Errorf("roundtrip mismatch: want %+v, got %+v", orig, got)
	}
}

func TestEvent_OmitEmpty(t *testing.T) {
	e := models.Event{Source: "arp", IP: "192.168.0.1"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	// action, state, mac, hostname should be absent due to omitempty
	var m map[string]interface{}
	json.Unmarshal(data, &m) //nolint:errcheck
	for _, key := range []string{"action", "state", "mac", "hostname"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected key %q to be omitted, but it was present", key)
		}
	}
	if _, ok := m["source"]; !ok {
		t.Error("expected key 'source' to be present")
	}
	if _, ok := m["ip"]; !ok {
		t.Error("expected key 'ip' to be present")
	}
}

// --- ARPEntry JSON tests ---

func TestARPEntry_JSONRoundtrip(t *testing.T) {
	orig := models.ARPEntry{IP: "172.16.0.1", MAC: "ca:fe:ba:be:00:ff"}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var got models.ARPEntry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if got != orig {
		t.Errorf("roundtrip mismatch: want %+v, got %+v", orig, got)
	}
}

func TestARPEntry_JSONKeys(t *testing.T) {
	e := models.ARPEntry{IP: "1.2.3.4", MAC: "01:02:03:04:05:06"}
	data, _ := json.Marshal(e)
	var m map[string]interface{}
	json.Unmarshal(data, &m) //nolint:errcheck
	if m["ip"] != "1.2.3.4" {
		t.Errorf("expected ip key '1.2.3.4', got %v", m["ip"])
	}
	if m["mac"] != "01:02:03:04:05:06" {
		t.Errorf("expected mac key '01:02:03:04:05:06', got %v", m["mac"])
	}
}
