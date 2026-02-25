package security

import (
	"testing"
)

func TestAdminRateLimiterDisabled(t *testing.T) {
	arl := NewAdminRateLimiter(false)

	// When disabled, Allow must return true regardless of call count.
	for i := 0; i < 100; i++ {
		if !arl.Allow("192.168.1.1", 1.0) {
			t.Errorf("expected Allow to return true when disabled (call %d)", i)
		}
	}
}

func TestAdminRateLimiterEnabled(t *testing.T) {
	t.Run("first request is allowed", func(t *testing.T) {
		arl := NewAdminRateLimiter(true)
		// burst = max(1, 60) = 60; pre-filled in getLimiter, so first call succeeds.
		if !arl.Allow("192.168.1.1", 60.0) {
			t.Error("expected first request to be allowed (burst should be pre-filled)")
		}
	})

	t.Run("burst exhaustion causes denial", func(t *testing.T) {
		arl := NewAdminRateLimiter(true)
		ip := "192.168.1.2"
		perMinute := 1.0 // burst = max(1, 1) = 1 token

		// First call: consumes the single burst token – must succeed.
		if !arl.Allow(ip, perMinute) {
			t.Fatal("first request should be allowed (burst = 1)")
		}
		// Second call: burst exhausted, rate is 1/60 rps – must be denied immediately.
		if arl.Allow(ip, perMinute) {
			t.Error("expected denial after burst is exhausted")
		}
	})
}

func TestGetLimiterCreatesNew(t *testing.T) {
	arl := NewAdminRateLimiter(true)

	limiter := arl.getLimiter("10.0.0.1", 60.0)
	if limiter == nil {
		t.Fatal("expected a non-nil limiter for a new IP")
	}
}

func TestGetLimiterReturnsSameForSameKey(t *testing.T) {
	arl := NewAdminRateLimiter(true)
	ip := "10.0.0.2"
	perMinute := 60.0

	l1 := arl.getLimiter(ip, perMinute)
	l2 := arl.getLimiter(ip, perMinute)

	if l1 != l2 {
		t.Error("expected the same limiter instance for the same IP+rate key")
	}
}

func TestGetLimiterDifferentForDifferentRate(t *testing.T) {
	arl := NewAdminRateLimiter(true)
	ip := "10.0.0.3"

	l1 := arl.getLimiter(ip, 60.0)
	l2 := arl.getLimiter(ip, 120.0)

	if l1 == l2 {
		t.Error("expected different limiters for different rates on the same IP")
	}
}

func TestMax(t *testing.T) {
	tests := []struct {
		a, b int
		want int
	}{
		{5, 3, 5},
		{3, 5, 5},
		{0, 0, 0},
	}

	for _, tt := range tests {
		got := max(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("max(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
