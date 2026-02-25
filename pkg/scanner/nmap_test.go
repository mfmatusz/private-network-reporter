package scanner

import (
	"testing"
)

// contains checks if a string slice contains a specific string
func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

// containsAll checks if a string slice contains all specified strings
func containsAll(args []string, ss ...string) bool {
	for _, s := range ss {
		if !contains(args, s) {
			return false
		}
	}
	return true
}

// --- buildNmapArgs tests ---

func TestBuildNmapArgs_BasicScan(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Level: "basic"}
	args := buildNmapArgs(req)

	if !containsAll(args, "-sT", "-Pn", "-T2", "--max-retries", "1", "--host-timeout", "60s") {
		t.Errorf("basic scan missing expected args, got: %v", args)
	}
}

func TestBuildNmapArgs_RawScan(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", UseRaw: true}
	args := buildNmapArgs(req)

	if !contains(args, "-sS") {
		t.Errorf("raw scan should contain -sS, got: %v", args)
	}
	if contains(args, "-sT") {
		t.Errorf("raw scan should not contain -sT, got: %v", args)
	}
}

func TestBuildNmapArgs_DeepLevel(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Level: "deep"}
	args := buildNmapArgs(req)

	if !containsAll(args, "-sV", "-sC", "--host-timeout", "300s") {
		t.Errorf("deep scan missing expected args, got: %v", args)
	}
}

func TestBuildNmapArgs_DeepSafeLevel(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Level: "deepsafe"}
	args := buildNmapArgs(req)

	if !containsAll(args, "-sV", "--script", "default and safe") {
		t.Errorf("deepsafe scan missing expected args, got: %v", args)
	}
}

func TestBuildNmapArgs_CustomLevelWithScripts(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Level: "custom", CustomScripts: "http-title"}
	args := buildNmapArgs(req)

	if !containsAll(args, "-sV", "--script", "http-title") {
		t.Errorf("custom scan missing expected args, got: %v", args)
	}
}

func TestBuildNmapArgs_BasicLevelNoVersionOrScripts(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Level: "basic"}
	args := buildNmapArgs(req)

	if contains(args, "-sV") {
		t.Errorf("basic scan should not contain -sV, got: %v", args)
	}
	if contains(args, "-sC") {
		t.Errorf("basic scan should not contain -sC, got: %v", args)
	}
}

func TestBuildNmapArgs_CustomTiming(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Timing: "T4"}
	args := buildNmapArgs(req)

	if !contains(args, "-T4") {
		t.Errorf("custom timing should add -T4, got: %v", args)
	}
	if contains(args, "-T2") {
		t.Errorf("custom timing should not contain default -T2, got: %v", args)
	}
}

func TestBuildNmapArgs_CustomTimeout(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Timeout: "120s"}
	args := buildNmapArgs(req)

	if !containsAll(args, "--host-timeout", "120s") {
		t.Errorf("custom timeout should use 120s, got: %v", args)
	}
}

func TestBuildNmapArgs_Ports(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1", Ports: []string{"22", "80", "443"}}
	args := buildNmapArgs(req)

	if !containsAll(args, "-p", "22,80,443") {
		t.Errorf("ports should add -p 22,80,443, got: %v", args)
	}
}

func TestBuildNmapArgs_NoPorts(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1"}
	args := buildNmapArgs(req)

	if contains(args, "-p") {
		t.Errorf("no ports should not add -p flag, got: %v", args)
	}
}

func TestBuildNmapArgs_TargetIPIsLast(t *testing.T) {
	req := ScanRequest{IP: "10.0.0.1"}
	args := buildNmapArgs(req)

	if len(args) == 0 || args[len(args)-1] != "10.0.0.1" {
		t.Errorf("target IP should be last argument, got: %v", args)
	}
}

func TestBuildNmapArgs_AlwaysHasBaseArgs(t *testing.T) {
	req := ScanRequest{IP: "192.168.1.1"}
	args := buildNmapArgs(req)

	if !containsAll(args, "-oX", "-", "-n") {
		t.Errorf("args should always contain -oX, -, -n, got: %v", args)
	}
}

// --- extractXML tests ---

func TestExtractXML_WithXMLDeclaration(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><nmaprun></nmaprun>`)
	result := extractXML(input)

	if string(result) != `<?xml version="1.0"?><nmaprun></nmaprun>` {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestExtractXML_PrefixGarbage(t *testing.T) {
	input := []byte("some garbage output\n<?xml version=\"1.0\"?><nmaprun></nmaprun>")
	result := extractXML(input)

	if string(result) != "<?xml version=\"1.0\"?><nmaprun></nmaprun>" {
		t.Errorf("should strip prefix garbage, got: %s", result)
	}
}

func TestExtractXML_SuffixGarbage(t *testing.T) {
	input := []byte("<?xml version=\"1.0\"?><nmaprun></nmaprun>\nsome trailing garbage")
	result := extractXML(input)

	if string(result) != "<?xml version=\"1.0\"?><nmaprun></nmaprun>" {
		t.Errorf("should strip suffix garbage, got: %s", result)
	}
}

func TestExtractXML_BothPrefixAndSuffixGarbage(t *testing.T) {
	input := []byte("prefix garbage\n<?xml version=\"1.0\"?><nmaprun></nmaprun>\nsuffix garbage")
	result := extractXML(input)

	if string(result) != "<?xml version=\"1.0\"?><nmaprun></nmaprun>" {
		t.Errorf("should extract only XML, got: %s", result)
	}
}

func TestExtractXML_NoXMLDeclaration(t *testing.T) {
	input := []byte("<nmaprun></nmaprun>")
	result := extractXML(input)

	if string(result) != "<nmaprun></nmaprun>" {
		t.Errorf("no XML declaration should return input as-is, got: %s", result)
	}
}

func TestExtractXML_XMLDeclarationNoClosingTag(t *testing.T) {
	input := []byte("<?xml version=\"1.0\"?><nmaprun>incomplete")
	result := extractXML(input)

	if string(result) != "<?xml version=\"1.0\"?><nmaprun>incomplete" {
		t.Errorf("missing closing tag should return from <?xml to end, got: %s", result)
	}
}

func TestExtractXML_EmptyInput(t *testing.T) {
	result := extractXML([]byte{})

	if len(result) != 0 {
		t.Errorf("empty input should return empty, got: %s", result)
	}
}

// --- ScanRequest struct construction ---

func TestScanRequest_AllFields(t *testing.T) {
	req := ScanRequest{
		IP:            "192.168.1.1",
		Ports:         []string{"22", "80"},
		UseRaw:        true,
		Level:         "custom",
		Timeout:       "120s",
		Timing:        "T3",
		CustomScripts: "http-title,ssh-hostkey",
	}

	if req.IP != "192.168.1.1" {
		t.Errorf("IP field not set correctly")
	}
	if len(req.Ports) != 2 {
		t.Errorf("Ports field not set correctly")
	}
	if !req.UseRaw {
		t.Errorf("UseRaw field not set correctly")
	}
	if req.Level != "custom" {
		t.Errorf("Level field not set correctly")
	}
	if req.Timeout != "120s" {
		t.Errorf("Timeout field not set correctly")
	}
	if req.Timing != "T3" {
		t.Errorf("Timing field not set correctly")
	}
	if req.CustomScripts != "http-title,ssh-hostkey" {
		t.Errorf("CustomScripts field not set correctly")
	}
}
