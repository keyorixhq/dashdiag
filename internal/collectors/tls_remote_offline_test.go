//go:build linux || darwin

package collectors

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestTLSEndpointHonoursOfflineGate is the regression proof for the fix to
// KV-TLS-OFFLINE-BYPASS (formerly cmd/knownviolations_test.go, now removed):
// CheckRemoteEndpoint (dsd tls --endpoint host:port) used to dial out even
// with DSD_OFFLINE=1 set — the only remote-dialing code path in the repo that
// didn't check platform.OfflineForced()/platform.NetworkAllowed() first. It
// now must refuse BEFORE ever attempting a connection. Uses a loopback
// listener (127.0.0.1, matching TestCheckRemoteEndpointLive_Success's
// pattern), never a real external host — this is a deterministic regression
// proof, not a live-network test. Not driven by FuzzCommandAllowlist either
// way: a live dial isn't safe to fuzz (see execallowlist_fuzz_test.go's
// header comment), so this direct test is the only coverage for the gate.
func TestTLSEndpointHonoursOfflineGate(t *testing.T) {
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

	var accepted atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Store(true)
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

	certs, err := CheckRemoteEndpoint(ctx, ln.Addr().String())
	if err == nil {
		t.Fatal("expected CheckRemoteEndpoint to refuse with DSD_OFFLINE=1 set, got nil error")
	}
	if !strings.Contains(err.Error(), "DSD_OFFLINE") {
		t.Errorf("error = %q, want it to mention DSD_OFFLINE (actionable, not a generic dial failure)", err.Error())
	}
	if certs != nil {
		t.Errorf("expected nil certs when blocked by DSD_OFFLINE, got %+v", certs)
	}

	// Give the accept loop a moment, then prove the block happened BEFORE any
	// connection attempt — not that the dial merely failed for some other
	// reason (e.g. a listener misconfiguration) that happened to also error.
	time.Sleep(100 * time.Millisecond)
	if accepted.Load() {
		t.Error("CheckRemoteEndpoint connected to the listener despite DSD_OFFLINE=1 — the offline gate ran too late, or not at all")
	}
}
