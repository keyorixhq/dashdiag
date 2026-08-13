package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
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

// defaultCachePath returns the update-check cache's absolute path, or "" if
// it can't be determined ($HOME unset). "" is a deliberate sentinel
// loadCache/saveCache check for, never a relative fallback: a relative
// ".dsd/update-check.json" would resolve against whatever — possibly
// attacker-writable — CWD dsd happens to run from.
func defaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dsd", "update-check.json")
}

func loadCache() *checkCache {
	path := cachePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
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
	if path == "" {
		return fmt.Errorf("selfupdate: cannot determine cache path ($HOME unresolved)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// O_NOFOLLOW: refuse to write through a pre-existing symlink at tmp
	// rather than following it — same hazard cmd/root.go's createOutFile
	// guards for --out.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644) //nolint:gosec // public version string, not a secret
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("selfupdate: refusing to write through a symlink at %q", tmp)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
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
