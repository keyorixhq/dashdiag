package selfupdate

import (
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
