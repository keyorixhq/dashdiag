package selfupdate

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultCachePath(t *testing.T) {
	t.Run("HOME resolvable", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		got := defaultCachePath()
		want := filepath.Join(home, ".dsd", "update-check.json")
		if got != want {
			t.Errorf("defaultCachePath() = %q, want %q", got, want)
		}
	})

	t.Run("HOME unresolvable falls back to relative path", func(t *testing.T) {
		// On unix, os.UserHomeDir returns an error when $HOME is empty.
		t.Setenv("HOME", "")
		got := defaultCachePath()
		want := filepath.Join(".dsd", "update-check.json")
		if got != want {
			t.Errorf("defaultCachePath() = %q, want %q", got, want)
		}
	})
}

func TestLoadCache_MalformedJSON(t *testing.T) {
	withTempCache(t)
	dir := filepath.Dir(cachePath())
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath(), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadCache(); got != nil {
		t.Errorf("loadCache() with malformed JSON = %+v, want nil", got)
	}
}

func TestSaveCache_MkdirFails(t *testing.T) {
	// Point cachePath at a path where a parent path segment is a regular file,
	// so os.MkdirAll(filepath.Dir(path), ...) fails.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := cachePath
	cachePath = func() string { return filepath.Join(blocker, "sub", "update-check.json") }
	t.Cleanup(func() { cachePath = old })

	err := saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v1.0.0"})
	if err == nil {
		t.Fatal("expected saveCache to fail when MkdirAll cannot create the parent dir")
	}
}

func TestRefreshCache_Success(t *testing.T) {
	withTempCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v3.4.5","html_url":"https://example/r","assets":[]}`)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	tag, err := RefreshCache(context.Background())
	if err != nil {
		t.Fatalf("RefreshCache: %v", err)
	}
	if tag != "v3.4.5" {
		t.Errorf("RefreshCache tag = %q, want v3.4.5", tag)
	}
	c := loadCache()
	if c == nil || c.LatestVersion != "v3.4.5" {
		t.Fatalf("cache not updated after RefreshCache: %+v", c)
	}
}

func TestRefreshCache_Error(t *testing.T) {
	withTempCache(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	tag, err := RefreshCache(context.Background())
	if err == nil {
		t.Fatalf("expected RefreshCache error, got tag %q", tag)
	}
	if loadCache() != nil {
		t.Error("cache must not be written on a failed refresh")
	}
}

func TestMaybeNudge_StaleCacheTriggersRefresh(t *testing.T) {
	withTempCache(t)
	// Cache older than the TTL: MaybeNudge must attempt a (short, bounded)
	// refresh. Point apiBase at a server that responds fast with a newer tag.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v8.0.0","html_url":"https://example/r","assets":[]}`)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	stale := &checkCache{CheckedAt: time.Now().UTC().Add(-48 * time.Hour), LatestVersion: "v0.1.0"}
	if err := saveCache(stale); err != nil {
		t.Fatal(err)
	}

	line := MaybeNudge("v1.0.0")
	if line == "" {
		t.Error("expected a nudge after a successful stale-cache refresh finds a newer version")
	}
}

func TestMaybeNudge_NoCacheRefreshFails(t *testing.T) {
	withTempCache(t)
	// No cache at all, and the refresh endpoint fails — MaybeNudge must not
	// panic and must return "" (no cache to compare against).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	if line := MaybeNudge("v1.0.0"); line != "" {
		t.Errorf("expected no nudge when refresh fails and no cache exists, got %q", line)
	}
}
