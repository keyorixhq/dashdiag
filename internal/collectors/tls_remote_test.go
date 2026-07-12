//go:build linux || darwin

package collectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedTLSCert builds an in-memory tls.Certificate (leaf + key) for
// standing up a local TLS listener, distinct from tls_testhelpers_test.go's
// makeTestCertPEM (which only returns the PEM bytes for file-based parser
// tests, not a loadable key pair for a live listener).
func selfSignedTLSCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "remote.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// TestCheckRemoteEndpointLive_Success stands up a real local TLS listener and
// dials it via checkRemoteEndpointLive, guarding the happy path: the peer
// certificate chain must be extracted with the correct Subject/Issuer/
// ExpiresIn/IsSelfSigned fields.
func TestCheckRemoteEndpointLive_Success(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cert := selfSignedTLSCert(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("starting TLS listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and immediately hold the connection open long enough for
			// the client handshake to complete, then close.
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	certs, err := checkRemoteEndpointLive(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("checkRemoteEndpointLive() error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 peer cert, got %d: %+v", len(certs), certs)
	}
	got := certs[0]
	if got.Subject != "remote.example.com" {
		t.Errorf("Subject = %q, want remote.example.com", got.Subject)
	}
	if got.Path != ln.Addr().String() {
		t.Errorf("Path = %q, want endpoint %q (used as display path)", got.Path, ln.Addr().String())
	}
	if !got.IsSelfSigned {
		t.Error("self-signed cert (Subject==Issuer) must be flagged IsSelfSigned")
	}
	if got.ExpiresIn < 29 || got.ExpiresIn > 30 {
		t.Errorf("ExpiresIn = %d, want ~30 (30 day validity window)", got.ExpiresIn)
	}
}

// TestCheckRemoteEndpointLive_DialError guards the DialContext error branch:
// an endpoint nothing is listening on must return an error, not a panic or an
// empty-but-nil-error result.
func TestCheckRemoteEndpointLive_DialError(t *testing.T) {
	t.Parallel()
	// Bind a listener to get a free port, then close it immediately so the
	// port is guaranteed to have nothing listening — avoids flakiness from
	// hardcoding a port that might be in use.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("closing probe listener: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	certs, err := checkRemoteEndpointLive(ctx, addr)
	if err == nil {
		t.Fatal("expected a dial error for an endpoint with nothing listening")
	}
	if certs != nil {
		t.Errorf("expected nil certs on dial error, got %+v", certs)
	}
}
