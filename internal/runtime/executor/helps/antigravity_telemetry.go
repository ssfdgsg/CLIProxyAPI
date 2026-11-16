package helps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	defaultAntigravityClearcutURL     = "https://play.googleapis.com/log"
	antigravityTelemetryMinInterval   = 5 * time.Minute
	antigravityTelemetryClientTimeout = 10 * time.Second
)

var (
	// AntigravityClearcutURL can be overridden in tests.
	AntigravityClearcutURL = defaultAntigravityClearcutURL

	antigravityLastTelemetryTime = make(map[string]time.Time)
	antigravityTelemetryMu       sync.Mutex
)

// ResetAntigravityTelemetryState clears rate limiter and telemetry state (for unit tests).
func ResetAntigravityTelemetryState() {
	antigravityTelemetryMu.Lock()
	antigravityLastTelemetryTime = make(map[string]time.Time)
	AntigravityClearcutURL = defaultAntigravityClearcutURL
	antigravityTelemetryMu.Unlock()
}

// DeterministicAntigravityMachineID generates a consistent 32-character hex machine ID for a given auth credential.
func DeterministicAntigravityMachineID(authKey string) string {
	sum := sha256.Sum256([]byte("cpa:antigravity:machine_id:" + authKey))
	return hex.EncodeToString(sum[:16])
}

// BuildAntigravityClearcutLogRequest serializes a minimal valid Clearcut LogRequest protobuf message.
func BuildAntigravityClearcutLogRequest(machineID, ideVersion, osName, archName string, now time.Time) []byte {
	extMap := map[string]any{
		"machineId":     machineID,
		"ideVersion":    ideVersion,
		"os":            osName,
		"arch":          archName,
		"subclientType": "cli",
		"ideName":       "antigravity",
		"op":            "summary_store_perf",
	}
	extensionBytes, _ := json.Marshal(extMap)

	// Submessage: ClientInfo (field 1)
	clientInfo := protowire.AppendTag(nil, 1, protowire.VarintType)
	clientInfo = protowire.AppendVarint(clientInfo, 1)

	// Submessage: LogEvent (field 3)
	event := protowire.AppendTag(nil, 1, protowire.VarintType)
	event = protowire.AppendVarint(event, uint64(now.UnixMilli()))
	event = protowire.AppendTag(event, 2, protowire.BytesType)
	event = protowire.AppendString(event, "summary_store_perf")
	event = protowire.AppendTag(event, 6, protowire.BytesType)
	event = protowire.AppendBytes(event, extensionBytes)

	// Root message: LogRequest
	reqPayload := protowire.AppendTag(nil, 1, protowire.BytesType)
	reqPayload = protowire.AppendBytes(reqPayload, clientInfo)
	reqPayload = protowire.AppendTag(reqPayload, 4, protowire.VarintType)
	reqPayload = protowire.AppendVarint(reqPayload, uint64(now.UnixMilli()))
	reqPayload = protowire.AppendTag(reqPayload, 6, protowire.BytesType)
	reqPayload = protowire.AppendString(reqPayload, "ANTIGRAVITY_DESKTOP")
	reqPayload = protowire.AppendTag(reqPayload, 3, protowire.BytesType)
	reqPayload = protowire.AppendBytes(reqPayload, event)

	return reqPayload
}

// MaybeSendAntigravityShadowTelemetry sends a non-blocking shadow telemetry / Clearcut heartbeat
// to Google's play.googleapis.com logging service, matching native agy's background metrics cadence.
// It is rate-limited to at most once per 5 minutes per credential and never affects inference requests.
func MaybeSendAntigravityShadowTelemetry(ctx context.Context, client *http.Client, auth *cliproxyauth.Auth, token string) {
	token = strings.TrimSpace(token)
	if token == "" && auth != nil && auth.Metadata != nil {
		if t, ok := auth.Metadata["access_token"].(string); ok {
			token = strings.TrimSpace(t)
		}
	}
	if token == "" {
		return
	}

	authKey := antigravityLifecycleAuthKey(auth)

	antigravityTelemetryMu.Lock()
	lastTime := antigravityLastTelemetryTime[authKey]
	now := time.Now()
	if !lastTime.IsZero() && now.Sub(lastTime) < antigravityTelemetryMinInterval {
		antigravityTelemetryMu.Unlock()
		return
	}
	antigravityLastTelemetryTime[authKey] = now
	antigravityTelemetryMu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Debugf("antigravity shadow telemetry panic recovered: %v", r)
			}
		}()

		sendCtx := context.Background()
		if ctx != nil && ctx.Err() == nil {
			sendCtx = context.WithoutCancel(ctx)
		}
		telemetryCtx, cancel := context.WithTimeout(sendCtx, antigravityTelemetryClientTimeout)
		defer cancel()

		machineID := DeterministicAntigravityMachineID(authKey)
		ideVer := misc.AntigravityLatestVersion()
		osName := runtime.GOOS
		archName := runtime.GOARCH

		payload := BuildAntigravityClearcutLogRequest(machineID, ideVer, osName, archName, time.Now())

		endpoint := AntigravityClearcutURL
		httpReq, errReq := http.NewRequestWithContext(telemetryCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if errReq != nil {
			log.Debugf("antigravity shadow telemetry: build request error: %v", errReq)
			return
		}
		httpReq.Header.Set("Authorization", "Bearer "+token)
		httpReq.Header.Set("Content-Type", "application/octet-stream")
		httpReq.Header.Set("User-Agent", "Go-http-client/1.1")

		httpClient := client
		if httpClient == nil {
			if proxyURL := EffectiveAntigravityProxyURL(telemetryCtx, nil, auth); proxyURL != "" {
				httpClient = NewProxyAwareHTTPClient(telemetryCtx, nil, auth, antigravityTelemetryClientTimeout)
			} else {
				httpClient = http.DefaultClient
			}
		}

		resp, errDo := httpClient.Do(httpReq)
		if errDo != nil {
			log.Debugf("antigravity shadow telemetry: send error: %v", errDo)
			return
		}
		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				log.Debugf("antigravity shadow telemetry: close body error: %v", errClose)
			}
		}()

		_, _ = io.Copy(io.Discard, resp.Body)
		log.Debugf("antigravity shadow telemetry: sent successfully auth=%s status=%d", authKey, resp.StatusCode)
	}()
}
