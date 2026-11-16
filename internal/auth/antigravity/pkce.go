// Package antigravity provides OAuth 2.0 PKCE helpers for the Antigravity
// provider. Google treats Antigravity as a public/native client, so the
// authorization-code flow must use PKCE (RFC 7636) instead of a distributed
// client_secret; the official CLI follows the same pattern.
package antigravity

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/MoeForge/moego/base64"
)

// PKCECodes pairs an OAuth 2.0 code verifier (sent to the token endpoint)
// with its derived code challenge (sent to the authorization endpoint).
type PKCECodes struct {
	CodeVerifier  string
	CodeChallenge string
}

// GeneratePKCECodes produces a fresh (verifier, S256 challenge) pair.
// Returns an error only if the system entropy source fails.
func GeneratePKCECodes() (*PKCECodes, error) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate code verifier: %w", err)
	}
	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: generateCodeChallenge(verifier),
	}, nil
}

// generateCodeVerifier creates 96 random bytes encoded as unpadded URL-safe
// base64 (~128 chars, inside the RFC 7636 range 43–128).
func generateCodeVerifier() (string, error) {
	buf := make([]byte, 96)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// generateCodeChallenge computes S256(verifier) per RFC 7636 §4.2.
func generateCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
