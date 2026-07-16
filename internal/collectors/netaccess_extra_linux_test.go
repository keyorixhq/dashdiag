//go:build linux

package collectors

// netaccess_extra_linux_test.go — additional branch coverage for
// netaccess_linux.go paths not covered by the existing netaccess_linux_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHttpGetLive_BadURL drives the http.NewRequestWithContext error branch:
// an unparseable URL (invalid scheme) must return an error rather than panic.
func TestHttpGetLive_BadURL(t *testing.T) {
	t.Parallel()
	_, _, err := httpGetLive(context.Background(), "://bad-url")
	if err == nil {
		t.Fatal("expected an error for a malformed URL, got nil")
	}
}

// TestHttpGetLive_ContextCancelled drives the client.Do error path: a
// pre-cancelled context causes the HTTP request to fail immediately, and the
// error must be surfaced (not swallowed).
func TestHttpGetLive_ContextCancelled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, _, err := httpGetLive(ctx, srv.URL)
	if err == nil {
		t.Fatal("expected an error when context is cancelled before the request")
	}
}

// TestHttpGetCached_ReplayHit drives the cachedJSON replay path: the Cached
// key is pre-seeded in the combined fixture so cachedJSON short-circuits to
// the stored bytes without invoking produce (httpGetLive never called).
// Body is a []byte — JSON-marshalled as base64.
func TestHttpGetCached_ReplayHit(t *testing.T) {
	// Not parallel: withCombinedFixture swaps the package-level activeSource.
	// json.Marshal encodes []byte fields as base64 automatically, which is
	// exactly what cachedJSON/json.Unmarshal expects for httpGetResult.Body.
	var r httpGetResult
	r.Body = []byte("healthy")
	r.Code = 200
	canonical, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshaling canonical fixture: %v", err)
	}

	const testURL = "http://127.0.0.1:9999/test"
	withCombinedFixture(t, map[string][]byte{
		"http/" + testURL: canonical,
	}, nil, nil)

	body, code, err := httpGetCached(context.Background(), testURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 200 {
		t.Errorf("code = %d, want 200", code)
	}
	if string(body) != "healthy" {
		t.Errorf("body = %q, want healthy", body)
	}
}
