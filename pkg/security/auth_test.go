package security

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeRouterOSTimestamp converts a Unix second value into a RouterOS "weeks+days+time" string
// so that parseRouterOSTimestamp(result) == unixSecs.
func makeRouterOSTimestamp(unixSecs int64) string {
	weeks := unixSecs / (7 * 24 * 3600)
	rem := unixSecs % (7 * 24 * 3600)
	days := rem / (24 * 3600)
	rem = rem % (24 * 3600)
	hours := rem / 3600
	rem = rem % 3600
	mins := rem / 60
	secs := rem % 60
	return fmt.Sprintf("%dw%dd%02d:%02d:%02d.000", weeks, days, hours, mins, secs)
}

func TestParseRouterOSTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{
			name:  "weeks+days+time",
			input: "2915w1d09:10:02.449936265",
			want:  2915*7*24*3600 + 1*24*3600 + 9*3600 + 10*60 + 2,
		},
		{
			name:  "weeks+time (no days)",
			input: "2925w13:38:18.048259327",
			want:  2925*7*24*3600 + 13*3600 + 38*60 + 18,
		},
		{
			name:  "days+time (no weeks)",
			input: "1d15:00:43.633",
			want:  1*24*3600 + 15*3600 + 0*60 + 43,
		},
		{
			name:  "just time",
			input: "09:10:02.449",
			want:  9*3600 + 10*60 + 2,
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRouterOSTimestamp(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseRouterOSTimestamp(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateAdminToken(t *testing.T) {
	auth := NewAuthenticator("secret-admin-token", "event-token")

	t.Run("empty admin token in authenticator", func(t *testing.T) {
		a := NewAuthenticator("", "event-token")
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Admin-Token", "anything")
		if a.ValidateAdminToken(req) {
			t.Error("expected false when admin token is empty")
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Admin-Token", "wrong-token")
		if auth.ValidateAdminToken(req) {
			t.Error("expected false for wrong token")
		}
	})

	t.Run("correct token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Admin-Token", "secret-admin-token")
		if !auth.ValidateAdminToken(req) {
			t.Error("expected true for correct token")
		}
	})

	t.Run("case-sensitive comparison", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Admin-Token", "Secret-Admin-Token")
		if auth.ValidateAdminToken(req) {
			t.Error("expected false for wrong-case token")
		}
	})
}

func TestValidateSHA512Signature(t *testing.T) {
	eventToken := "test-event-token"
	body := []byte(`{"data":"test"}`)

	t.Run("empty event token", func(t *testing.T) {
		a := NewAuthenticator("admin", "")
		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.RemoteAddr = "192.168.1.1:1234"
		if a.ValidateSHA512Signature(req, body) {
			t.Error("expected false when event token is empty")
		}
	})

	t.Run("missing X-Auth-Signature header", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.Header.Set("X-Auth-Timestamp", "1w0d00:00:01.000")
		req.RemoteAddr = "192.168.1.2:1234"
		if auth.ValidateSHA512Signature(req, body) {
			t.Error("expected false for missing signature header")
		}
	})

	t.Run("missing X-Auth-Timestamp header", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.Header.Set("X-Auth-Signature", "somesig")
		req.RemoteAddr = "192.168.1.3:1234"
		if auth.ValidateSHA512Signature(req, body) {
			t.Error("expected false for missing timestamp header")
		}
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.Header.Set("X-Auth-Signature", "somesig")
		req.Header.Set("X-Auth-Timestamp", "not-a-timestamp")
		req.RemoteAddr = "192.168.1.4:1234"
		if auth.ValidateSHA512Signature(req, body) {
			t.Error("expected false for invalid timestamp format")
		}
	})

	t.Run("correct signature with valid timestamp", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		// Build a RouterOS timestamp string whose parsed value equals time.Now().Unix()
		// so the age check passes (age ≈ 0).
		tsStr := makeRouterOSTimestamp(time.Now().Unix())

		data := string(body) + eventToken + tsStr
		hash := sha512.Sum512([]byte(data))
		sig := hex.EncodeToString(hash[:])

		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.Header.Set("X-Auth-Signature", sig)
		req.Header.Set("X-Auth-Timestamp", tsStr)
		req.RemoteAddr = "192.168.1.10:1234"

		if !auth.ValidateSHA512Signature(req, body) {
			t.Error("expected true for valid signature with in-window timestamp")
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		tsStr := makeRouterOSTimestamp(time.Now().Unix())

		req := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req.Header.Set("X-Auth-Signature", "badbadbadbad")
		req.Header.Set("X-Auth-Timestamp", tsStr)
		req.RemoteAddr = "192.168.1.11:1234"

		if auth.ValidateSHA512Signature(req, body) {
			t.Error("expected false for wrong signature")
		}
	})

	t.Run("replay attack – same timestamp twice", func(t *testing.T) {
		auth := NewAuthenticator("admin", eventToken)
		tsStr := makeRouterOSTimestamp(time.Now().Unix())

		data := string(body) + eventToken + tsStr
		hash := sha512.Sum512([]byte(data))
		sig := hex.EncodeToString(hash[:])

		ip := "192.168.1.20:1234"

		// First call must succeed.
		req1 := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req1.Header.Set("X-Auth-Signature", sig)
		req1.Header.Set("X-Auth-Timestamp", tsStr)
		req1.RemoteAddr = ip
		if !auth.ValidateSHA512Signature(req1, body) {
			t.Fatal("first request should succeed")
		}

		// Second call with the same timestamp must be rejected as a replay.
		req2 := httptest.NewRequest(http.MethodPost, "/event", strings.NewReader(string(body)))
		req2.Header.Set("X-Auth-Signature", sig)
		req2.Header.Set("X-Auth-Timestamp", tsStr)
		req2.RemoteAddr = ip
		if auth.ValidateSHA512Signature(req2, body) {
			t.Error("expected false for replay attack (same timestamp reused)")
		}
	})
}
