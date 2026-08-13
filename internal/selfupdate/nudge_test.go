package selfupdate

import (
	"os"
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

// TestSaveCache_EmptyPathFailsClosed guards internal-selfupdate-01-04:
// saveCache must fail closed with NO filesystem side effects when
// cachePath() returns "" (the defaultCachePath()-unresolved sentinel) —
// not merely return a non-nil error after already having written a stray
// ".tmp" file into the CWD (path="" -> filepath.Dir("")="." ->
// os.WriteFile(".tmp", ...) succeeds; only the final os.Rene(".tmp", "")
// would fail, after the write already landed).
func TestSaveCache_EmptyPathFailsClosed(t *testing.T) {
	t.Chdir(t.TempDir())
	old := cachePath
	cachePath = func() string { return "" }
	t.Cleanup(func() { cachePath = old })

	if err := saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v1.0.0"}); err == nil {
		t.Error(`saveCache should fail when cachePath() returns ""`)
	}
	if _, err := os.Stat(".tmp"); !os.IsNotExist(err) {
		t.Errorf(`saveCache must not write ".tmp" into the CWD when cachePath() is "", stat err = %v`, err)
	}
}

// TestSaveCache_RefusesSymlinkedTmp guards the O_NOFOLLOW half of
// internal-selfupdate-01-04: saveCache's tmp-file write previously used
// plain os.WriteFile (follows an existing symlink, no O_EXCL). A pre-planted
// symlink at update-check.json.tmp must not have its target overwritten.
func TestSaveCache_RefusesSymlinkedTmp(t *testing.T) {
	dir := t.TempDir()
	old := cachePath
	cachePath = func() string { return filepath.Join(dir, "update-check.json") }
	t.Cleanup(func() { cachePath = old })

	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "update-check.json.tmp")); err != nil {
		t.Fatal(err)
	}

	if err := saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v1.0.0"}); err == nil {
		t.Fatal("saveCache should refuse to write through the symlinked tmp file")
	}
	data, err := os.ReadFile(victim) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Errorf("victim file was overwritten: %q", data)
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
