package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Prune atomically rewrites path, keeping at most maxEntries for hostname.
// Entries belonging to other hostnames are preserved unchanged.
// Returns nil (no-op) when the store is missing, empty, or already within limit.
func Prune(path string, hostname string, maxEntries int) error {
	if maxEntries <= 0 {
		return nil
	}

	all, err := ReadAll(path, "", 0)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return nil
	}

	// Find indices of entries belonging to hostname (chronological order).
	var hostIdx []int
	for i, e := range all {
		if e.Hostname == hostname {
			hostIdx = append(hostIdx, i)
		}
	}
	if len(hostIdx) <= maxEntries {
		return nil // within limit — nothing to do
	}

	// Mark the oldest entries for removal.
	drop := len(hostIdx) - maxEntries
	remove := make(map[int]struct{}, drop)
	for _, idx := range hostIdx[:drop] {
		remove[idx] = struct{}{}
	}

	// Write to a temp file in the same directory so os.Rename is atomic.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".store-prune-*") //nolint:gosec // dir from StorePath(), not user input
	if err != nil {
		return fmt.Errorf("store: prune: creating temp: %w", err)
	}
	tmpPath := tmp.Name()

	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	w := bufio.NewWriter(tmp)
	for i, e := range all {
		if _, skip := remove[i]; skip {
			continue
		}
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: prune: marshalling entry: %w", err)
		}
		line = append(line, '\n')
		if _, err := w.Write(line); err != nil {
			return fmt.Errorf("store: prune: writing: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("store: prune: flushing: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("store: prune: syncing: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: prune: closing temp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("store: prune: replacing store: %w", err)
	}
	ok = true
	return nil
}
