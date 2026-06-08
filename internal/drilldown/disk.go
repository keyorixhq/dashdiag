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
		return largestDirsFallback(ctx, mount)
	}

	type entry struct {
		size string
		path string
		// raw value for sorting (parse human size)
		rawKB int64
	}
	var entries []entry
	for _, child := range children {
		full := filepath.Join(mount, child.Name())
		out, err := runCmd(ctx, "du", "-sh", full)
		if err != nil {
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

	return &models.Details{
		Type:    "directory_sizes",
		Title:   fmt.Sprintf("Largest directories under %s", mount),
		Columns: []string{"SIZE", "PATH"},
		Rows:    rows,
	}, nil
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
