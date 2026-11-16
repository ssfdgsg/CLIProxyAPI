package helps

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type lifecycleMockRoundTripper func(*http.Request) (*http.Response, error)

func (f lifecycleMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEnsureAntigravityClientLifecycle_SequenceAndCache(t *testing.T) {
	ResetAntigravityLifecycleCache()
	ResetAntigravityTelemetryState()

	var (
		callsMu sync.Mutex
		calls   []string
	)

	mockClient := &http.Client{
		Transport: lifecycleMockRoundTripper(func(r *http.Request) (*http.Response, error) {
			callsMu.Lock()
			calls = append(calls, r.URL.Path)
			callsMu.Unlock()

			if authHeader := r.Header.Get("Authorization"); authHeader != "Bearer test-token-123" {
				t.Errorf("unexpected Authorization header: %s", authHeader)
			}
			if ua := r.Header.Get("User-Agent"); ua == "" {
				t.Errorf("missing User-Agent header")
			}

			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				respBody := `{"cloudaicompanionProject":"test-project-999","currentTier":{"id":"g1-pro-tier"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(respBody)),
				}, nil
			case "/v1internal:fetchAdminControls",
				"/v1internal:fetchAvailableModels",
				"/v1internal:retrieveUserQuotaSummary",
				"/v1internal:listExperiments":
				body, _ := io.ReadAll(r.Body)
				var req map[string]string
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("invalid json body on %s: %v", r.URL.Path, err)
				}
				if req["project"] != "test-project-999" {
					t.Errorf("expected project=test-project-999 on %s, got: %v", r.URL.Path, req["project"])
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
		}),
	}

	auth := &cliproxyauth.Auth{
		ID:    "test-auth-1",
		Index: "test-auth-1",
	}

	// First execution: should call all 5 endpoints in sequence
	baseURL := "https://daily-cloudcode-pa.googleapis.com"
	projectID, err := EnsureAntigravityClientLifecycle(context.Background(), mockClient, auth, "test-token-123", baseURL)
	if err != nil {
		t.Fatalf("EnsureAntigravityClientLifecycle failed: %v", err)
	}
	if projectID != "test-project-999" {
		t.Fatalf("expected projectID test-project-999, got: %s", projectID)
	}
	if auth.Metadata["project_id"] != "test-project-999" {
		t.Fatalf("expected auth.Metadata project_id updated, got: %v", auth.Metadata["project_id"])
	}

	expectedPaths := []string{
		"/v1internal:loadCodeAssist",
		"/v1internal:fetchAdminControls",
		"/v1internal:fetchAvailableModels",
		"/v1internal:retrieveUserQuotaSummary",
		"/v1internal:listExperiments",
	}

	callsMu.Lock()
	if len(calls) != len(expectedPaths) {
		t.Fatalf("expected %d calls, got %d: %v", len(expectedPaths), len(calls), calls)
	}
	for i, path := range expectedPaths {
		if calls[i] != path {
			t.Errorf("call %d: expected %s, got %s", i, path, calls[i])
		}
	}
	callsMu.Unlock()

	// Second execution within TTL: should return cached projectID without making any HTTP calls
	projectID2, err2 := EnsureAntigravityClientLifecycle(context.Background(), mockClient, auth, "test-token-123", baseURL)
	if err2 != nil {
		t.Fatalf("cached EnsureAntigravityClientLifecycle failed: %v", err2)
	}
	if projectID2 != "test-project-999" {
		t.Fatalf("expected cached projectID test-project-999, got: %s", projectID2)
	}

	callsMu.Lock()
	if len(calls) != len(expectedPaths) {
		t.Fatalf("expected no extra calls from cache, but total calls became %d", len(calls))
	}
	callsMu.Unlock()
}

func TestEnsureAntigravityClientLifecycle_GracefulPartialFailure(t *testing.T) {
	ResetAntigravityLifecycleCache()

	mockClient := &http.Client{
		Transport: lifecycleMockRoundTripper(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/v1internal:loadCodeAssist":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"project":"my-custom-project"}`)),
				}, nil
			case "/v1internal:fetchAdminControls":
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"error":"permission denied"}`)),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{}`)),
				}, nil
			}
		}),
	}

	auth := &cliproxyauth.Auth{ID: "test-auth-2"}
	projectID, err := EnsureAntigravityClientLifecycle(context.Background(), mockClient, auth, "token-xyz", "https://example.com")
	if err != nil {
		t.Fatalf("warmup should not fail when secondary endpoint fails: %v", err)
	}
	if projectID != "my-custom-project" {
		t.Fatalf("expected projectID my-custom-project, got %s", projectID)
	}
}

func TestEnsureAntigravityClientLifecycle_SingleFlight(t *testing.T) {
	ResetAntigravityLifecycleCache()

	var loadCodeAssistCalls int64
	mockClient := &http.Client{
		Transport: lifecycleMockRoundTripper(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "loadCodeAssist") {
				atomic.AddInt64(&loadCodeAssistCalls, 1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"project":"shared-project"}`)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{}`)),
			}, nil
		}),
	}

	auth := &cliproxyauth.Auth{ID: "test-auth-concurrent"}
	var wg sync.WaitGroup
	concurrentCount := 8

	for i := 0; i < concurrentCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pid, err := EnsureAntigravityClientLifecycle(context.Background(), mockClient, auth, "token", "https://example.com")
			if err != nil || pid != "shared-project" {
				t.Errorf("concurrent warmup error: %v, pid: %s", err, pid)
			}
		}()
	}
	wg.Wait()

	if total := atomic.LoadInt64(&loadCodeAssistCalls); total != 1 {
		t.Fatalf("expected singleflight to coalesce into 1 loadCodeAssist call, got: %d", total)
	}
}
