package helps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

const (
	// AntigravityLifecycleTTL defines how long client lifecycle state remains fresh before re-warming.
	AntigravityLifecycleTTL = 2 * time.Hour
	// antigravityWarmupTimeout bounds the complete pre-flight lifecycle execution.
	antigravityWarmupTimeout  = 15 * time.Second
	defaultAntigravityProject = "aicode-consumers"
)

type antigravityLifecycleEntry struct {
	warmedAt  time.Time
	projectID string
}

var (
	antigravityLifecycleCache = make(map[string]antigravityLifecycleEntry)
	antigravityLifecycleMu    sync.RWMutex
	antigravityLifecycleGroup singleflight.Group
)

// ResetAntigravityLifecycleCache clears the lifecycle cache (used in unit tests).
func ResetAntigravityLifecycleCache() {
	antigravityLifecycleMu.Lock()
	antigravityLifecycleCache = make(map[string]antigravityLifecycleEntry)
	antigravityLifecycleMu.Unlock()
}

func antigravityLifecycleAuthKey(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return "anonymous"
	}
	if idx := strings.TrimSpace(auth.EnsureIndex()); idx != "" {
		return idx
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return id
	}
	return "unknown"
}

// EnsureAntigravityClientLifecycle ensures that the client lifecycle pre-flight sequence
// (loadCodeAssist, fetchAdminControls, fetchAvailableModels, retrieveUserQuotaSummary, listExperiments)
// has been executed for this credential, matching the startup and cache-refresh behavior of native agy.
func EnsureAntigravityClientLifecycle(ctx context.Context, httpClient *http.Client, auth *cliproxyauth.Auth, token, baseURL string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" && auth != nil && auth.Metadata != nil {
		if t, ok := auth.Metadata["access_token"].(string); ok {
			token = strings.TrimSpace(t)
		}
	}
	if token == "" {
		return "", fmt.Errorf("ensure antigravity lifecycle: missing access token")
	}

	authKey := antigravityLifecycleAuthKey(auth)

	antigravityLifecycleMu.RLock()
	entry, exists := antigravityLifecycleCache[authKey]
	antigravityLifecycleMu.RUnlock()
	if exists && time.Since(entry.warmedAt) < AntigravityLifecycleTTL && entry.projectID != "" {
		return entry.projectID, nil
	}

	result, errDo, _ := antigravityLifecycleGroup.Do(authKey, func() (any, error) {
		// Recheck cache inside singleflight
		antigravityLifecycleMu.RLock()
		if e, ok := antigravityLifecycleCache[authKey]; ok && time.Since(e.warmedAt) < AntigravityLifecycleTTL && e.projectID != "" {
			antigravityLifecycleMu.RUnlock()
			return e.projectID, nil
		}
		antigravityLifecycleMu.RUnlock()

		pid, err := executeAntigravityLifecycleWarmup(ctx, httpClient, auth, token, baseURL)
		if pid != "" && auth != nil {
			if auth.Metadata == nil {
				auth.Metadata = make(map[string]any)
			}
			auth.Metadata["project_id"] = pid
		}
		return pid, err
	})

	if errDo != nil {
		return "", errDo
	}

	projectID, _ := result.(string)
	return projectID, nil
}

func executeAntigravityLifecycleWarmup(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, token, baseURL string) (string, error) {
	if client == nil {
		if proxyURL := EffectiveAntigravityProxyURL(ctx, nil, auth); proxyURL != "" {
			client = NewProxyAwareHTTPClient(ctx, nil, auth, 0)
		} else {
			client = http.DefaultClient
		}
	}
	base := strings.TrimSuffix(baseURL, "/")
	if base == "" {
		base = "https://daily-cloudcode-pa.googleapis.com"
	}

	warmupCtx := ctx
	if warmupCtx == nil {
		warmupCtx = context.Background()
	}
	warmupCtx, cancel := context.WithTimeout(context.WithoutCancel(warmupCtx), antigravityWarmupTimeout)
	defer cancel()

	userAgent := misc.AntigravityRequestUserAgent(antigravityConfiguredUA(auth))

	// 1. loadCodeAssist
	projectID, errLoad := doLifecycleLoadCodeAssist(warmupCtx, client, base, userAgent, token)
	if errLoad != nil {
		log.Debugf("antigravity lifecycle: loadCodeAssist error: %v", errLoad)
	}
	if projectID == "" && auth != nil && auth.Metadata != nil {
		if p, ok := auth.Metadata["project_id"].(string); ok {
			projectID = strings.TrimSpace(p)
		}
	}
	if projectID == "" {
		projectID = defaultAntigravityProject
	}

	// 2. fetchAdminControls
	if err := doLifecyclePost(warmupCtx, client, base, "/v1internal:fetchAdminControls", userAgent, token, projectID); err != nil {
		log.Debugf("antigravity lifecycle: fetchAdminControls notice: %v", err)
	}

	// 3. fetchAvailableModels
	if err := doLifecyclePost(warmupCtx, client, base, "/v1internal:fetchAvailableModels", userAgent, token, projectID); err != nil {
		log.Debugf("antigravity lifecycle: fetchAvailableModels notice: %v", err)
	}

	// 4. retrieveUserQuotaSummary
	if err := doLifecyclePost(warmupCtx, client, base, "/v1internal:retrieveUserQuotaSummary", userAgent, token, projectID); err != nil {
		log.Debugf("antigravity lifecycle: retrieveUserQuotaSummary notice: %v", err)
	}

	// 5. listExperiments
	if err := doLifecyclePost(warmupCtx, client, base, "/v1internal:listExperiments", userAgent, token, projectID); err != nil {
		log.Debugf("antigravity lifecycle: listExperiments notice: %v", err)
	}

	authKey := antigravityLifecycleAuthKey(auth)
	antigravityLifecycleMu.Lock()
	antigravityLifecycleCache[authKey] = antigravityLifecycleEntry{
		warmedAt:  time.Now(),
		projectID: projectID,
	}
	antigravityLifecycleMu.Unlock()

	log.Debugf("antigravity lifecycle: warmup completed for auth=%s project=%s", authKey, projectID)

	// Trigger shadow telemetry heartbeat asynchronously after warmup
	MaybeSendAntigravityShadowTelemetry(warmupCtx, client, auth, token)

	return projectID, nil
}

func doLifecycleLoadCodeAssist(ctx context.Context, client *http.Client, baseURL, userAgent, token string) (string, error) {
	url := baseURL + "/v1internal:loadCodeAssist"
	bodyBytes := []byte(`{"metadata":{"ideType":"ANTIGRAVITY"}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, errDo := client.Do(req)
	if errDo != nil {
		return "", errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("antigravity lifecycle: close loadCodeAssist body: %v", errClose)
		}
	}()

	respBytes, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return "", errRead
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("loadCodeAssist status %d: %s", resp.StatusCode, string(respBytes))
	}

	var data map[string]any
	if errUnmarshal := json.Unmarshal(respBytes, &data); errUnmarshal == nil {
		return extractProjectIDFromResponse(data), nil
	}
	return "", nil
}

func doLifecyclePost(ctx context.Context, client *http.Client, baseURL, endpoint, userAgent, token, projectID string) error {
	url := baseURL + endpoint
	reqMap := map[string]string{"project": projectID}
	bodyBytes, _ := json.Marshal(reqMap)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, errDo := client.Do(req)
	if errDo != nil {
		return errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("antigravity lifecycle: close %s body: %v", endpoint, errClose)
		}
	}()

	// Discard body
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s returned status %d", endpoint, resp.StatusCode)
	}
	return nil
}

func extractProjectIDFromResponse(data map[string]any) string {
	if data == nil {
		return ""
	}
	for _, key := range []string{"cloudaicompanionProject", "projectId", "project"} {
		switch value := data[key].(type) {
		case string:
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		case map[string]any:
			if id, ok := value["id"].(string); ok {
				if trimmed := strings.TrimSpace(id); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

func antigravityConfiguredUA(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Attributes != nil {
		if ua := strings.TrimSpace(auth.Attributes["user_agent"]); ua != "" {
			return ua
		}
	}
	if auth.Metadata != nil {
		if ua, ok := auth.Metadata["user_agent"].(string); ok && strings.TrimSpace(ua) != "" {
			return strings.TrimSpace(ua)
		}
		if mode, ok := auth.Metadata["client_mode"].(string); ok && strings.EqualFold(mode, "hub") {
			return misc.AntigravityUserAgent()
		}
	}
	return misc.AntigravityCLIUserAgent()
}
