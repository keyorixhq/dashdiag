package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// LoadHistory loads the last n timestamped baseline snapshots for the current
// host, sorted oldest-first. Ignores -latest and -prev symlink files.
func LoadHistory(n int) ([]*Snapshot, error) {
	hostname, _ := os.Hostname()
	dir := baselineDir()

	// SafeHostname: same sanitizer latestPath/prevPath/goldenPath use. The
	// kernel hostname normally requires privilege to change, but nothing
	// downstream should assume that — a glob pattern built from an
	// unsanitized hostname could match or (via '/') traverse outside
	// baselineDir() if it ever did contain glob metacharacters or separators.
	pattern := filepath.Join(dir, SafeHostname(hostname)+"-[0-9]*-[0-9]*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Sort by filename (timestamp is embedded: hostname-YYYYMMDD-HHMMSS.json)
	sort.Strings(matches)

	// Take last n
	if len(matches) > n {
		matches = matches[len(matches)-n:]
	}

	snaps := make([]*Snapshot, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		snaps = append(snaps, &snap)
	}
	return snaps, nil
}
