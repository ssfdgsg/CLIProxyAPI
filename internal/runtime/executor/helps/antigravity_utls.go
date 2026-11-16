package helps

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const antigravitySessionCacheCapacity = 32
const antigravityProxySessionCacheCapacity = 64

// antigravitySessionCaches maintains one TLS session cache per proxy URL (or direct empty key).
// Scoping by proxy URL prevents session resumption across different proxies or accounts.
var antigravitySessionCaches = internalcache.NewBoundedLRU[string, tls.ClientSessionCache](
	antigravityProxySessionCacheCapacity,
	nil,
)

// AntigravitySessionCache returns the TLS ClientSessionCache for a proxy URL.
func AntigravitySessionCache(proxyURL string) tls.ClientSessionCache {
	return antigravitySessionCaches.GetOrAdd(proxyURL, func() tls.ClientSessionCache {
		return tls.NewLRUClientSessionCache(antigravitySessionCacheCapacity)
	})
}

// EffectiveAntigravityProxyURL resolves the proxy URL for Antigravity requests, adhering to priority:
// 1. Context request proxy override (highest priority)
// 2. auth.ProxyURL
// 3. auth.Metadata["proxy_url"]
// 4. auth.Attributes["proxy_url"]
// 5. cfg.ProxyURL (global proxy fallback)
func EffectiveAntigravityProxyURL(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) string {
	if proxyURL := cliproxyexecutor.RequestProxyURL(ctx); proxyURL != "" {
		return proxyURL
	}
	if auth != nil {
		if proxyURL := strings.TrimSpace(auth.ProxyURL); proxyURL != "" {
			return proxyURL
		}
		if auth.Metadata != nil {
			if proxyURL, ok := auth.Metadata["proxy_url"].(string); ok && strings.TrimSpace(proxyURL) != "" {
				return strings.TrimSpace(proxyURL)
			}
		}
		if auth.Attributes != nil {
			if proxyURL := strings.TrimSpace(auth.Attributes["proxy_url"]); proxyURL != "" {
				return proxyURL
			}
		}
	}
	if cfg != nil {
		return strings.TrimSpace(cfg.ProxyURL)
	}
	return ""
}

// antigravityCLIClientHelloSpec reproduces the authentic ClientHello profile of the native
// agy CLI tool (Node/OpenSSL TLS 1.3 stack). It deliberately omits the ALPN extension to
// match the native client's HTTP/1.1 negotiation with Google Cloud Code (GFE/ESF).
func antigravityCLIClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
		CompressionMethods: []uint8{0},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11)
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

// NewAntigravityUTLSTransport constructs an HTTP/1.1 transport using uTLS fingerprinting
// and configured with the specified proxy URL (or direct dialing if empty).
func NewAntigravityUTLSTransport(proxyURL, profile string, cfg *config.Config) *http.Transport {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("antigravity utls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return NewAntigravityUTLSTransportForDialer(dialer, profile, cfg)
}

// NewAntigravityUTLSTransportForDialer creates an Antigravity uTLS transport using the provided dialer.
func NewAntigravityUTLSTransportForDialer(dialer proxy.Dialer, profile string, cfg *config.Config) *http.Transport {
	return NewAntigravityUTLSTransportForDialerAndRoots(dialer, profile, nil, cfg)
}

// NewAntigravityUTLSTransportForDialerAndRoots creates an Antigravity uTLS transport with custom root CAs (for testing).
func NewAntigravityUTLSTransportForDialerAndRoots(dialer proxy.Dialer, profile string, roots *x509.CertPool, cfg *config.Config) *http.Transport {
	if dialer == nil {
		dialer = proxy.Direct
	}
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = "agy"
	}

	sessionCache := AntigravitySessionCache(fmt.Sprintf("%p", dialer))

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("antigravity utls: dial upstream: %w", err)
			}

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				if errClose := conn.Close(); errClose != nil {
					log.Debugf("antigravity utls: close failed connection: %v", errClose)
				}
				return nil, fmt.Errorf("antigravity utls: split upstream address: %w", errSplit)
			}

			tlsConfig := &tls.Config{
				ServerName:                         host,
				RootCAs:                            roots,
				ClientSessionCache:                 sessionCache,
				OmitEmptyPsk:                       true,
				PreferSkipResumptionOnNilExtension: true,
			}

			var tlsConn *tls.UConn
			switch profile {
			case "chrome":
				tlsConn = tls.UClient(conn, tlsConfig, tls.HelloChrome_Auto)
			case "agy", "cli", "node":
				fallthrough
			default:
				tlsConn = tls.UClient(conn, tlsConfig, tls.HelloCustom)
				if errPreset := tlsConn.ApplyPreset(antigravityCLIClientHelloSpec()); errPreset != nil {
					if errClose := tlsConn.Close(); errClose != nil {
						log.Debugf("antigravity utls: close connection after preset failure: %v", errClose)
					}
					return nil, fmt.Errorf("antigravity utls: apply agy ClientHello: %w", errPreset)
				}
			}

			handshakeCtx, cancelHandshake := handshakeContext(ctx)
			defer cancelHandshake()
			if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
				errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("antigravity utls: close connection after handshake failure: %v", errClose)
				}
				return nil, fmt.Errorf("antigravity utls: handshake upstream: %w", errHandshake)
			}

			return tlsConn, nil
		},
	}
	return transport
}
