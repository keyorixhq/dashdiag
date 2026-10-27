package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// LoadHistory loads the last n timestamped baseline snapshots for the current
// host, sorted oldest-first. Ignores -latest and -prev symlink files.
func LoadHistory(n int) ([]*Snapshot, error) {
	hostname, _ := os.Hostname()
	dir, err := baselineDir()
	if err != nil {
		return nil, fmt.Errorf("resolving baseline dir: %w", err)
	}

	// SafeHostname: same sanitizer latestPath/prevPath/goldenPath use. The
	// kernel hostname normally requires privilege to change, but nothing
	// downstream should assume that — a glob pattern built from an
	// unsanitized hostname could match or (via '/') traverse outside
	// baselineDir() if it ever did contain glob metacharacters or separators.
	pattern := filepath.Join(dir, SafeHostname(hostname)+"-[0-9]*-[0-9]*.json")
	// GlobChecked, not filepath.Glob: an unreadable baseline dir must not read
	// as "no history yet".
	matches, dirUnreadable, err := source.GlobChecked(source.Live{}, pattern)
	if err != nil {
		return nil, err
	}
	if dirUnreadable {
		return nil, fmt.Errorf("could not read baseline dir %s", dir)
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
