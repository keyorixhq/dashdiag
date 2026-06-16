//go:build linux

package collectors

import (
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestDialReachableRoutesThroughSource guards service-collector hermeticity: a
// reachability gate must read the captured bundle on replay, not re-dial the
// replaying machine. We record a reachable listener, close it (so a live dial
// would now fail), then assert replay still reports it reachable.
func TestDialReachableRoutesThroughSource(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	rec := source.NewRecorder(source.Live{})
	prev := SetSource(rec)
	if !dialReachable("tcp", addr, time.Second) {
		SetSource(prev)
		t.Fatal("listener should be reachable during capture")
	}
	SetSource(prev)

	// Close the listener so a live dial would now fail.
	_ = ln.Close()

	// Replay must still report reachable — from the bundle, without re-dialing.
	defer SetSource(SetSource(source.NewReplay(rec.Bundle())))
	if !dialReachable("tcp", addr, time.Second) {
		t.Fatal("dialReachable re-dialed the live machine on replay instead of reading the bundle")
	}
}
