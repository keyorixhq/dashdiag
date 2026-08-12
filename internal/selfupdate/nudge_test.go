package selfupdate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func withTempCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := cachePath
	cachePath = func() string { return filepath.Join(dir, "update-check.json") }
	t.Cleanup(func() { cachePath = old })
}

func TestCacheRoundTrip(t *testing.T) {
	withTempCache(t)
	if loadCache() != nil {
		t.Fatal("expected no cache initially")
	}
	c := &checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v1.2.3"}
	if err := saveCache(c); err != nil {
		t.Fatal(err)
	}
	got := loadCache()
	if got == nil || got.LatestVersion != "v1.2.3" {
		t.Fatalf("round-trip failed: %+v", got)
	}
}

func TestMaybeNudge_FromFreshCache(t *testing.T) {
	withTempCache(t)
	// Fresh cache (now) so no network refresh is attempted.
	_ = saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v0.7.0"})

	// Newer available → nudge.
	if line := MaybeNudge("v0.6.1"); line == "" {
		t.Error("expected a nudge when newer version is cached")
	}
	// Up to date → no nudge.
	if line := MaybeNudge("v0.7.0"); line != "" {
		t.Errorf("expected no nudge when up to date, got %q", line)
	}
	// Dev build → never nudge.
	if line := MaybeNudge("dev"); line != "" {
		t.Errorf("dev build must not nudge, got %q", line)
	}
}

func TestMaybeNudge_DisabledByEnv(t *testing.T) {
	withTempCache(t)
	_ = saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v0.7.0"})
	t.Setenv("DSD_NO_UPDATE_CHECK", "1")
	if line := MaybeNudge("v0.6.1"); line != "" {
		t.Errorf("DSD_NO_UPDATE_CHECK must silence the nudge, got %q", line)
	}
}

// TestMaybeNudge_DSD_OFFLINE_SkipsNetworkRefresh is a regression guard for
// egress-gate-01 / cmd-07-02: on a cold or stale cache, MaybeNudge used to
// unconditionally issue an HTTPS GET to api.github.com (via RefreshCache),
// with no way to opt out short of the nudge-specific DSD_NO_UPDATE_CHECK.
// DSD_OFFLINE (the shared "make no outbound network calls" switch) must also
// suppress that refresh. apiBase is pointed at a local server that records
// whether it was ever hit -- with no cache seeded, the only way MaybeNudge
// could return a nudge is by completing that refresh, so a passing "no
// nudge" result alone wouldn't prove the network call was skipped rather
// than attempted-and-ignored. Asserting the server saw zero requests does.
func TestMaybeNudge_DSD_OFFLINE_SkipsNetworkRefresh(t *testing.T) {
	withTempCache(t)
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		fmt.Fprint(w, `{"tag_name":"v8.0.0","html_url":"https://example/r","assets":[]}`)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	t.Setenv("DSD_OFFLINE", "1")
	if line := MaybeNudge("v0.6.1"); line != "" {
		t.Errorf("DSD_OFFLINE must silence the nudge (and skip the network refresh), got %q", line)
	}
	if hit {
		t.Error("DSD_OFFLINE must prevent RefreshCache from making any request to the update-check endpoint")
	}
	if loadCache() != nil {
		t.Error("DSD_OFFLINE must prevent RefreshCache from ever running (no cache should be written)")
	}
}
