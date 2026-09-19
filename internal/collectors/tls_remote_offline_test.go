//go:build linux || darwin

package collectors

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// TestTLSEndpointBypassesOfflineGate deterministically proves the known
// violation KV-TLS-OFFLINE-BYPASS (cmd/knownviolations_test.go):
// CheckRemoteEndpoint (dsd tls --endpoint host:port) dials out even with
// DSD_OFFLINE=1 set — the only remote-dialing code path in the repo that
// doesn't check platform.NetworkAllowed()/DSD_OFFLINE first. Uses a loopback
// listener (127.0.0.1, matching TestCheckRemoteEndpointLive_Success's
// pattern), never a real external host — this is a deterministic regression
// proof, not a live-network test.
//
// If this test starts FAILING (the dial gets refused/blocked), the bypass has
// been fixed — delete this test and the KV-TLS-OFFLINE-BYPASS entry together.
func TestTLSEndpointBypassesOfflineGate(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")

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
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = CheckRemoteEndpoint(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("CheckRemoteEndpoint dialed a loopback listener with DSD_OFFLINE=1 set and still failed (%v) — either the environment blocked loopback, or the bypass is already fixed (in which case remove this test and KV-TLS-OFFLINE-BYPASS)", err)
	}
}
