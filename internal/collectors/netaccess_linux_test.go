//go:build linux

package collectors

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// liveCachedNetSource mirrors source.Live's Cached semantics (always invoke
// produce) on top of a Bundle-backed Replay — needed to exercise
// httpGetCached's closure body (the httpGetLive call itself), which a plain
// Replay-backed fixture never reaches because Replay.Cached short-circuits
// without invoking produce.
type liveCachedNetSource struct {
	*source.Replay
}

func (liveCachedNetSource) Cached(_ string, produce func() ([]byte, error)) ([]byte, error) {
	return produce()
}

func withLiveCachedNetFixture(t *testing.T) {
	t.Helper()
	prev := SetSource(liveCachedNetSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
}

// TestHttpGetCached_LiveSuccess drives httpGetCached's closure (the actual
// httpGetLive call, success path) against a real local httptest server —
// httpGetLive takes url as a parameter, so it is fully redirectable (unlike
// the AWS/OCI IMDS helpers with hardcoded link-local URLs).
func TestHttpGetCached_LiveSuccess(t *testing.T) {
	withLiveCachedNetFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy"))
	}))
	defer srv.Close()

	body, code, err := httpGetCached(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusOK || string(body) != "healthy" {
		t.Errorf("got body=%q code=%d, want healthy/200", body, code)
	}
}

// TestHttpGetCached_LiveError drives httpGetCached's closure error path: the
// server is closed before the request, so the dial fails and the error must
// propagate rather than being swallowed into an empty success value.
func TestHttpGetCached_LiveError(t *testing.T) {
	withLiveCachedNetFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // closed before use -> connection refused

	_, _, err := httpGetCached(context.Background(), url)
	if err == nil {
		t.Fatal("expected an error dialing a closed server")
	}
}

// TestHttpGetLive_NonOKStatusStillReturnsBody confirms httpGetLive itself (not
// just its Cached wrapper) surfaces a non-2xx status code without treating it
// as an error — the caller decides what a given code means.
func TestHttpGetLive_NonOKStatusStillReturnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("down"))
	}))
	defer srv.Close()

	body, code, err := httpGetLive(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != http.StatusServiceUnavailable || string(body) != "down" {
		t.Errorf("got body=%q code=%d, want down/503", body, code)
	}
}

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
