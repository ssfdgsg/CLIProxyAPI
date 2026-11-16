package helps

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type telemetryMockRoundTripper func(*http.Request) (*http.Response, error)

func (f telemetryMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDeterministicAntigravityMachineID(t *testing.T) {
	id1 := DeterministicAntigravityMachineID("auth-1")
	id2 := DeterministicAntigravityMachineID("auth-1")
	id3 := DeterministicAntigravityMachineID("auth-2")

	if len(id1) != 32 {
		t.Fatalf("expected 32-character hex ID, got: %s (len %d)", id1, len(id1))
	}
	if id1 != id2 {
		t.Fatalf("expected deterministic machine ID for same auth, got %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("expected different machine IDs for different auths, got same %s", id1)
	}
}

func TestBuildAntigravityClearcutLogRequest(t *testing.T) {
	now := time.Now()
	payload := BuildAntigravityClearcutLogRequest("mach123", "1.4.12", "darwin", "arm64", now)

	if len(payload) == 0 {
		t.Fatalf("payload should not be empty")
	}

	// Verify key embedded strings exist in payload bytes
	expectedSubstrings := []string{"ANTIGRAVITY_DESKTOP", "summary_store_perf", "mach123", "1.4.12"}
	for _, sub := range expectedSubstrings {
		if !bytes.Contains(payload, []byte(sub)) {
			t.Errorf("payload missing expected substring %q", sub)
		}
	}
}

func TestMaybeSendAntigravityShadowTelemetry_Mock(t *testing.T) {
	ResetAntigravityTelemetryState()

	var receivedCalls int64
	var lastAuthHeader string
	var lastContentType string
	var lastUserAgent string

	mockClient := &http.Client{
		Transport: telemetryMockRoundTripper(func(r *http.Request) (*http.Response, error) {
			atomic.AddInt64(&receivedCalls, 1)
			lastAuthHeader = r.Header.Get("Authorization")
			lastContentType = r.Header.Get("Content-Type")
			lastUserAgent = r.Header.Get("User-Agent")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("ok"))),
			}, nil
		}),
	}

	auth := &cliproxyauth.Auth{ID: "auth-telemetry-test"}

	// First call: should trigger background telemetry
	MaybeSendAntigravityShadowTelemetry(context.Background(), mockClient, auth, "telemetry-token-123")

	// Allow goroutine to execute
	deadline := time.Now().Add(500 * time.Millisecond)
	for atomic.LoadInt64(&receivedCalls) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if count := atomic.LoadInt64(&receivedCalls); count != 1 {
		t.Fatalf("expected 1 telemetry call, got %d", count)
	}
	if lastAuthHeader != "Bearer telemetry-token-123" {
		t.Errorf("expected Authorization header 'Bearer telemetry-token-123', got %s", lastAuthHeader)
	}
	if lastContentType != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %s", lastContentType)
	}
	if lastUserAgent != "Go-http-client/1.1" {
		t.Errorf("expected User-Agent Go-http-client/1.1, got %s", lastUserAgent)
	}

	// Second immediate call: should be rate-limited
	MaybeSendAntigravityShadowTelemetry(context.Background(), mockClient, auth, "telemetry-token-123")
	time.Sleep(50 * time.Millisecond)

	if count := atomic.LoadInt64(&receivedCalls); count != 1 {
		t.Fatalf("expected rate-limiting to prevent immediate second call, got %d calls", count)
	}
}
