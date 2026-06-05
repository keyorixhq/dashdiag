package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// nudgeTTL is how long a cached check is trusted before a refresh is attempted.
const nudgeTTL = 24 * time.Hour

// nudgeTimeout bounds the at-most-once-per-TTL refresh so an interactive run is
// never delayed by more than this.
const nudgeTimeout = 800 * time.Millisecond

type checkCache struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

// cachePath is overridable in tests.
var cachePath = defaultCachePath

func defaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".dsd", "update-check.json")
	}
	return filepath.Join(home, ".dsd", "update-check.json")
}

func loadCache() *checkCache {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return nil
	}
	var c checkCache
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	return &c
}

func saveCache(c *checkCache) error {
	path := cachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // public version string, not a secret
		return err
	}
	return os.Rename(tmp, path)
}

// RefreshCache fetches the latest release and records it. Returns the tag.
func RefreshCache(ctx context.Context) (string, error) {
	rel, err := LatestRelease(ctx)
	if err != nil {
		return "", err
	}
	_ = saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: rel.TagName})
	return rel.TagName, nil
}

// MaybeNudge returns a one-line "update available" message for interactive use,
// or "" when up to date / disabled / a dev build. It reads the cache (no
// network); if the cache is missing or stale it does a single best-effort
// refresh bounded by nudgeTimeout so the next run is accurate. Fully silenced by
// DSD_NO_UPDATE_CHECK.
func MaybeNudge(current string) string {
	if os.Getenv("DSD_NO_UPDATE_CHECK") != "" {
		return ""
	}
	if !isCleanRelease(current) { // dev/describe build — never nag
		return ""
	}
	c := loadCache()
	if c == nil || time.Since(c.CheckedAt) > nudgeTTL {
		ctx, cancel := context.WithTimeout(context.Background(), nudgeTimeout)
		_, _ = RefreshCache(ctx)
		cancel()
		c = loadCache()
	}
	if c != nil && IsNewer(current, c.LatestVersion) {
		return fmt.Sprintf("ℹ️  dsd %s available — run `dsd update`  (silence: DSD_NO_UPDATE_CHECK=1)", c.LatestVersion)
	}
	return ""
}
