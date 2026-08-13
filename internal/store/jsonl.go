package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const maxLineSizeBytes = 1 << 20 // 1 MiB

// maxReadAllEntries bounds how many entries ReadAll(path, "", 0) — the
// "return everything" mode used by Prune — will accumulate in memory. Retention
// is otherwise only enforced by Prune itself (365 entries per hostname, and
// only when a caller opts into --persist), so a store file with many distinct
// hostnames, or one that's simply never been pruned, is not bounded in
// aggregate without this.
const maxReadAllEntries = 200_000

// JSONLStore is an append-only JSONL file store. Concurrent Append calls within
// a process are safe (mutex-guarded). Cross-process safety relies on the OS
// guaranteeing that writes smaller than PIPE_BUF are atomic at the VFS layer
// — each entry is one line, which is well under 4 KB in practice.
type JSONLStore struct {
	mu sync.Mutex
	f  *os.File
}

// Open opens (creating if necessary) the JSONL store at path. The directory is
// created with 0750 permissions if it does not exist.
func Open(path string) (*JSONLStore, error) {
	if path == "" {
		return nil, fmt.Errorf("store: cannot determine store path ($HOME unresolved)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: creating dir: %w", err)
	}
	// O_NOFOLLOW: refuse to append through a pre-existing symlink at path
	// rather than following it — same hazard cmd/root.go's createOutFile
	// guards for --out. Relevant when StorePath() falls back to a
	// CWD-relative-turned-absolute location a co-located user could plant a
	// symlink into before dsd runs.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // path comes from StorePath(), not user input
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("store: refusing to open a symlink at %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &JSONLStore{f: f}, nil
}

// StorePath returns the canonical JSONL store path for the current user, or
// "" if it can't be determined ($HOME unset for a non-root process — a
// stripped cron/systemd/CI/container environment). "" is a deliberate
// sentinel Open() checks for and refuses, never a relative fallback: a
// relative "./.dsd/store.jsonl" would resolve against whatever — possibly
// attacker-writable — CWD dsd happens to run from.
// Root writes to /var/lib/dashdiag/ to avoid filling home dirs on servers;
// non-root writes to ~/.dsd/.
func StorePath() string {
	if os.Getuid() == 0 {
		return "/var/lib/dashdiag/store.jsonl"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dsd", "store.jsonl")
}

// Append encodes e as a single JSON line and writes it to the store file.
func (s *JSONLStore) Append(_ context.Context, e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("store: marshalling entry: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("store: writing entry: %w", err)
	}
	return nil
}

// History returns the last n entries for hostname, oldest-first.
// It reads the entire file; for typical retention sizes this is fast enough.
func (s *JSONLStore) History(_ context.Context, hostname string, n int) ([]Entry, error) {
	s.mu.Lock()
	path := s.f.Name()
	s.mu.Unlock()
	return ReadAll(path, hostname, n)
}

// ReadAll reads the last n entries for hostname from path without opening a
// write handle — safe for concurrent callers and for read-only contexts (e.g.
// dsd history). Pass n<=0 to return all matching entries, up to
// maxReadAllEntries.
func ReadAll(path, hostname string, n int) ([]Entry, error) {
	if path == "" {
		return nil, nil // StorePath() couldn't be determined — treat as "no store yet"
	}
	f, err := os.Open(path) //nolint:gosec // path comes from StorePath(), not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: reading %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	var matches []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLineSizeBytes)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue // skip malformed lines rather than aborting
		}
		if hostname != "" && e.Hostname != hostname {
			continue
		}
		switch {
		case n > 0:
			// A bounded tail request (the common case — dsd history/diff/health
			// all ask for a small n) is kept as a fixed-size window as we scan,
			// instead of accumulating every match in the whole file before
			// truncating at the end. Slicing off the front on overflow keeps
			// len(matches) <= n at all times; Go's append growth is driven by
			// current len/cap, not lifetime append count, so the backing array
			// stays O(n) regardless of how large the store file has grown.
			matches = append(matches, e)
			if len(matches) > n {
				matches = matches[1:]
			}
		case len(matches) >= maxReadAllEntries:
			// n<=0 ("return everything", used by Prune): cap total entries
			// accumulated so an unpruned or many-hostname store file can't
			// grow memory use without bound. Keep scanning (not breaking) so
			// a later oversized-line error is still reported below.
		default:
			matches = append(matches, e)
		}
	}
	if err := sc.Err(); err != nil {
		if !errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("store: scanning %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "dsd: store: oversized line in %s skipped (line > %d bytes)\n", path, maxLineSizeBytes)
		// fall through and return what we have, as before
	}

	return matches, nil
}

// Close flushes and closes the underlying file.
func (s *JSONLStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		return fmt.Errorf("store: syncing: %w", err)
	}
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("store: closing: %w", err)
	}
	return nil
}
