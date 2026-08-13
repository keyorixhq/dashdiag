package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// LargestDirs returns the top 8 largest immediate subdirectories under mount.
func LargestDirs(ctx context.Context, mount string) (*models.Details, error) {
	if mount == "" {
		mount = "/"
	}

	// Use du on each immediate child (files + directories) so that large files
	// at the mount root are visible, not just subdirectories.
	children, err := os.ReadDir(mount)
	if err != nil {
		d, err := largestDirsFallback(ctx, mount)
		return sanitizeDetails(d), err
	}

	type entry struct {
		size string
		path string
		// raw value for sorting (parse human size)
		rawKB int64
	}
	var entries []entry
	skipped := 0
	for _, child := range children {
		full := filepath.Join(mount, child.Name())
		// -x: do not cross filesystem boundaries. Without it, a child that is a
		// separate mount (e.g. /mnt on a host where /mnt/data is a different disk)
		// reports the entire remote filesystem's size instead of its mountpoint
		// overhead, making it appear as a giant consumer of the scanned filesystem.
		out, err := runCmd(ctx, "du", "-xsh", full)
		if err != nil {
			// A permission-denied child (another user's home dir, a service's
			// private data dir) is silently invisible here — count it rather
			// than dropping it with no trace, so the largest-dirs table can't
			// misrepresent smaller readable dirs as the top disk consumers
			// while the real hog is an unreadable one.
			skipped++
			continue
		}
		fields := strings.Fields(out)
		if len(fields) < 1 {
			continue
		}
		size := fields[0]
		entries = append(entries, entry{size: size, path: full, rawKB: parseDuSize(size)})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rawKB > entries[j].rawKB })
	if len(entries) > 8 {
		entries = entries[:8]
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{e.size, e.path})
	}

	d := &models.Details{
		Type:    "directory_sizes",
		Title:   fmt.Sprintf("Largest directories under %s", mount),
		Columns: []string{"SIZE", "PATH"},
		Rows:    rows,
	}
	if skipped > 0 {
		d.Note = fmt.Sprintf("%d entr%s could not be measured (often a permission-denied subdirectory) and may be hidden from this list — run as root for full visibility",
			skipped, pluralIes(skipped))
	}
	// Filenames are attacker-writable by any local user who can create a file
	// under the drilled-down mount and can embed control/ANSI-escape bytes
	// (up to 255 bytes on Linux) — strip them before the path reaches the
	// rendered table.
	return sanitizeDetails(d), nil
}

func pluralIes(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// parseDuSize converts du human-readable size to approximate KB for sorting.
func parseDuSize(s string) int64 {
	if len(s) == 0 {
		return 0
	}
	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]
	var v float64
	_, _ = fmt.Sscanf(numStr, "%f", &v)
	// du -h emits IEC (1024-based) units; scale everything to bytes with base
	// 1024. Used only for sort ordering, but the right base keeps cross-unit
	// comparisons exact (the old base-1000 mix could misorder near boundaries).
	switch suffix {
	case 'T', 't':
		return int64(v * 1024 * 1024 * 1024 * 1024)
	case 'G', 'g':
		return int64(v * 1024 * 1024 * 1024)
	case 'M', 'm':
		return int64(v * 1024 * 1024)
	case 'K', 'k':
		return int64(v * 1024)
	default:
		return int64(v)
	}
}

func largestDirsFallback(ctx context.Context, mount string) (*models.Details, error) {
	entries, err := os.ReadDir(mount)
	if err != nil {
		return nil, err
	}

	type entry struct {
		path  string
		bytes int64
	}
	var dirs []entry
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		full := filepath.Join(mount, e.Name())
		size, _ := dirSize(full)
		dirs = append(dirs, entry{path: full, bytes: size})
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].bytes > dirs[j].bytes })
	if len(dirs) > 8 {
		dirs = dirs[:8]
	}

	rows := make([][]string, 0, len(dirs))
	for _, d := range dirs {
		rows = append(rows, []string{formatBytes(d.bytes), d.path})
	}
	return &models.Details{
		Type:    "directory_sizes",
		Title:   fmt.Sprintf("Largest directories under %s", mount),
		Columns: []string{"SIZE", "PATH"},
		Rows:    rows,
	}, nil
}

func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}
