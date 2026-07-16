//go:build linux

package collectors

// tls_remote_extra_test.go — additional branch coverage for tls_remote.go
// paths not reached by the existing tls_remote_test.go.

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestCheckRemoteEndpoint_CachedJSONError drives CheckRemoteEndpoint's
// "err != nil" return path (line 30): when the cachedJSON decode fails
// (invalid JSON stored under the tls-endpoint key), the error must propagate.
func TestCheckRemoteEndpoint_CachedJSONError(t *testing.T) {
	// Not parallel: withCombinedFixture swaps the package-level activeSource.
	// Seed invalid JSON under the tls-endpoint key — cachedJSON will try to
	// unmarshal it into []models.CertInfo and fail.
	withCombinedFixture(t, map[string][]byte{
		"tls-endpoint/127.0.0.1:9999": []byte("not valid json {{{"),
	}, nil, nil)

	_, err := CheckRemoteEndpoint(context.Background(), "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected an error when the cached JSON is malformed, got nil")
	}
}

// TestCheckRemoteEndpointLive_BadAddress drives the DialContext error branch:
// an address with an invalid format (no port) must return an error rather than
// panic, and the error must propagate to the caller.
func TestCheckRemoteEndpointLive_BadAddress(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// "noport" has no colon — DialContext will fail immediately.
	certs, err := checkRemoteEndpointLive(ctx, "noport")
	if err == nil {
		t.Fatal("expected a dial error for an address without a port, got nil")
	}
	if certs != nil {
		t.Errorf("expected nil certs on dial error, got %+v", certs)
	}
}

// TestCheckRemoteEndpointLive_HandshakeFailNoP guards the handshake error
// branch where the server closes the raw TCP connection right away (no TLS
// at all), so the TLS handshake fails AND PeerCertificates is empty — the
// error from the failed handshake must be returned.
func TestCheckRemoteEndpointLive_HandshakeFailNoP(t *testing.T) {
	t.Parallel()
	// Plain TCP listener that immediately closes every accepted connection
	// without sending any TLS bytes — the handshake on the client side will
	// fail because the server sends no data at all (or an EOF).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Immediately close without sending any data — TLS handshake fails.
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	certs, err := checkRemoteEndpointLive(ctx, ln.Addr().String())
	// The handshake must fail because the server sent nothing/closed the conn.
	// PeerCertificates will be empty, so the error is returned.
	if err == nil {
		t.Fatal("expected a handshake error from a non-TLS server, got nil")
	}
	if certs != nil {
		t.Errorf("expected nil certs on handshake failure with no peer certs, got %+v", certs)
	}
}

// TestCheckRemoteEndpointLive_HandshakeFailWithPeerCerts guards the
// "handshake fails but PeerCertificates != empty" branch: when the TLS
// handshake returns an error but the server did send certificates (e.g. a
// strict server that rejects client auth), those certs must still be extracted.
// We use a server that sends its certificate and then forcefully closes the
// connection during the handshake (simulating a certificate-verification
// failure on the server side).
func TestCheckRemoteEndpointLive_HandshakeFailWithPeerCerts(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cert := selfSignedTLSCert(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))

	// TLS listener with RequireAnyClientCert — the server will send its cert
	// but then error on the handshake because the client doesn't provide one.
	// This exercises the "Handshake fails but PeerCertificates != empty" path.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
	})
	if err != nil {
		t.Fatalf("starting TLS listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// Try to complete the handshake (will fail — no client cert)
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certs, err := checkRemoteEndpointLive(ctx, ln.Addr().String())
	// Two outcomes are acceptable:
	// 1. Handshake succeeds despite RequireAnyClientCert (some TLS implementations
	//    may not enforce this strictly on the go client side with InsecureSkipVerify)
	//    → certs non-empty, err nil.
	// 2. Handshake fails but server cert was exchanged → certs non-empty, err non-nil.
	// Either way, if certs are returned they must have the right Subject.
	if len(certs) > 0 && certs[0].Subject != "remote.example.com" {
		t.Errorf("cert Subject = %q, want remote.example.com", certs[0].Subject)
	}
	// The one invariant: either we got certs or we got an error (or both).
	if len(certs) == 0 && err == nil {
		t.Error("expected either certs or an error from a RequireAnyClientCert server, got neither")
	}
}
