// Package util contains helpers for the Antigravity provider that need to be
// shared across independent runtime/executor/auth call sites.
package util

import (
	"sync"

	"github.com/google/uuid"
)

// Antigravity OAuth uses a device/installation fingerprint so each refresh
// associates the token exchange with a stable "device" instead of looking
// like a fresh client. agy (the official Antigravity CLI) persists such an
// ID at ~/.gemini/antigravity-cli/installation_id; we mirror that intent
// here by generating a UUID once per process and pinning it on the auth
// metadata so subsequent refreshes reuse it.
var (
	antigravityInstallationOnce sync.Once
	antigravityInstallationID   string
)

// AntigravityInstallationID returns a stable process-local identifier used
// to fingerprint OAuth token requests with Antigravity. The value is safe to
// share across goroutines but is intentionally not persisted; persist it on
// the auth.Metadata map at login time so it survives restarts.
func AntigravityInstallationID() string {
	antigravityInstallationOnce.Do(func() {
		antigravityInstallationID = uuid.NewString()
	})
	return antigravityInstallationID
}
