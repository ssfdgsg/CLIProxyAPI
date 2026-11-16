package helps

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestAntigravityCLIClientHelloSpecOmitsALPN(t *testing.T) {
	t.Parallel()

	spec := antigravityCLIClientHelloSpec()
	if spec == nil {
		t.Fatal("antigravityCLIClientHelloSpec() returned nil")
	}

	for _, ext := range spec.Extensions {
		if _, isALPN := ext.(*tls.ALPNExtension); isALPN {
			t.Fatal("antigravity ClientHello unexpectedly contains an ALPNExtension; native agy omits ALPN")
		}
	}

	// RFC 8446 4.2.11: UtlsPreSharedKeyExtension must be the final extension
	last := spec.Extensions[len(spec.Extensions)-1]
	if _, ok := last.(*tls.UtlsPreSharedKeyExtension); !ok {
		t.Fatalf("last extension = %T, want *tls.UtlsPreSharedKeyExtension", last)
	}

	// UtlsPaddingExtension should precede pre_shared_key
	prev := spec.Extensions[len(spec.Extensions)-2]
	if _, ok := prev.(*tls.UtlsPaddingExtension); !ok {
		t.Fatalf("second-to-last extension = %T, want *tls.UtlsPaddingExtension", prev)
	}
}

func TestAntigravityCLIClientHelloCaptureOffline(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	cfg := &tls.Config{
		ServerName:                         "daily-cloudcode-pa.googleapis.com",
		ClientSessionCache:                 tls.NewLRUClientSessionCache(16),
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
	tlsConn := tls.UClient(clientConn, cfg, tls.HelloCustom)
	if errPreset := tlsConn.ApplyPreset(antigravityCLIClientHelloSpec()); errPreset != nil {
		t.Fatalf("apply preset error: %v", errPreset)
	}

	handshakeDone := make(chan error, 1)
	go func() {
		handshakeDone <- tlsConn.Handshake()
	}()

	_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, errRead := io.ReadFull(serverConn, header); errRead != nil {
		t.Fatalf("read ClientHello header: %v", errRead)
	}

	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, errRead := io.ReadFull(serverConn, payload); errRead != nil {
		t.Fatalf("read ClientHello payload: %v", errRead)
	}
	_ = serverConn.Close()

	select {
	case <-handshakeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not complete after server pipe closed")
	}

	record := append(header, payload...)
	fingerprinter := &tls.Fingerprinter{}
	spec, errFingerprint := fingerprinter.FingerprintClientHello(record)
	if errFingerprint != nil {
		t.Fatalf("fingerprint client hello error: %v", errFingerprint)
	}

	for _, ext := range spec.Extensions {
		if _, isALPN := ext.(*tls.ALPNExtension); isALPN {
			t.Fatal("captured ClientHello contains ALPN extension")
		}
	}
}

func TestEffectiveAntigravityProxyURLPriority(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		SDKConfig: config.SDKConfig{
			ProxyURL: "http://global-proxy:8080",
		},
	}

	// 1. cfg fallback when auth has nothing
	if got := EffectiveAntigravityProxyURL(context.Background(), cfg, nil); got != "http://global-proxy:8080" {
		t.Fatalf("expected global proxy, got %q", got)
	}

	// 2. auth.Attributes["proxy_url"]
	authWithAttr := &cliproxyauth.Auth{
		Attributes: map[string]string{"proxy_url": "http://attr-proxy:8080"},
	}
	if got := EffectiveAntigravityProxyURL(context.Background(), cfg, authWithAttr); got != "http://attr-proxy:8080" {
		t.Fatalf("expected attribute proxy, got %q", got)
	}

	// 3. auth.Metadata["proxy_url"] overrides attributes
	authWithMeta := &cliproxyauth.Auth{
		Attributes: map[string]string{"proxy_url": "http://attr-proxy:8080"},
		Metadata:   map[string]any{"proxy_url": "http://meta-proxy:8080"},
	}
	if got := EffectiveAntigravityProxyURL(context.Background(), cfg, authWithMeta); got != "http://meta-proxy:8080" {
		t.Fatalf("expected metadata proxy, got %q", got)
	}

	// 4. auth.ProxyURL struct field overrides metadata
	authWithField := &cliproxyauth.Auth{
		ProxyURL:   "http://field-proxy:8080",
		Metadata:   map[string]any{"proxy_url": "http://meta-proxy:8080"},
		Attributes: map[string]string{"proxy_url": "http://attr-proxy:8080"},
	}
	if got := EffectiveAntigravityProxyURL(context.Background(), cfg, authWithField); got != "http://field-proxy:8080" {
		t.Fatalf("expected field proxy, got %q", got)
	}

	// 5. Request-scoped override overrides everything
	ctxWithReq := cliproxyexecutor.WithRequestProxyURL(context.Background(), "http://req-proxy:8080")
	if got := EffectiveAntigravityProxyURL(ctxWithReq, cfg, authWithField); got != "http://req-proxy:8080" {
		t.Fatalf("expected request-scoped proxy, got %q", got)
	}
}

func TestNewAntigravityUTLSTransportConfiguresHTTP11(t *testing.T) {
	t.Parallel()

	transport := NewAntigravityUTLSTransport("", "agy", nil)
	if transport == nil {
		t.Fatal("NewAntigravityUTLSTransport returned nil")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("transport.ForceAttemptHTTP2 must be false for Antigravity")
	}
	if transport.DialTLSContext == nil {
		t.Fatal("transport.DialTLSContext must not be nil")
	}
}
