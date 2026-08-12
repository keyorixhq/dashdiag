package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const maxLineSizeBytes = 1 << 20 // 1 MiB

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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: creating dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // user-controlled path, not attacker-controlled
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &JSONLStore{f: f}, nil
}

// StorePath returns the canonical JSONL store path for the current user.
// Root writes to /var/lib/dashdiag/ to avoid filling home dirs on servers;
// non-root writes to ~/.dsd/.
func StorePath() string {
	if os.Getuid() == 0 {
		return "/var/lib/dashdiag/store.jsonl"
	}
	home, _ := os.UserHomeDir()
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
// dsd history). Pass n<=0 to return all matching entries.
func ReadAll(path, hostname string, n int) ([]Entry, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from StorePath(), not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: reading %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	// internal-store-01-03: bufio.Scanner (the previous implementation here)
	// treats a too-long line as a fatal, non-resumable error — once Scan()
	// returns false there is no way to skip past the offending line and keep
	// reading, so ANY oversized line silently discarded every entry AFTER it
	// in the file too, not just the bad one. Since History() reads oldest-first
	// and callers usually want the LAST n entries, that meant one corrupted
	// early line silently erased all of dsd's more recent, more relevant
	// history — while still returning (matches, nil), a clean success. Read
	// with bufio.Reader.ReadBytes instead: it can resume after an oversized
	// line, so only that one entry is skipped, not everything after it.
	var matches []Entry
	var oversized int
	br := bufio.NewReaderSize(f, 64*1024)
	for {
		lineBytes, rerr := br.ReadBytes('\n')
		line := bytes.TrimRight(lineBytes, "\n")
		switch {
		case len(line) > maxLineSizeBytes:
			oversized++
		case len(line) > 0:
			var e Entry
			// Malformed JSON is skipped rather than aborting, same as before.
			if err := json.Unmarshal(line, &e); err == nil && (hostname == "" || e.Hostname == hostname) {
				matches = append(matches, e)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("store: reading %s: %w", path, rerr)
		}
	}
	if oversized > 0 {
		fmt.Fprintf(os.Stderr, "dsd: store: %d oversized line(s) in %s skipped (line > %d bytes) — later entries were still read\n", oversized, path, maxLineSizeBytes)
	}

	if n <= 0 || len(matches) <= n {
		return matches, nil
	}
	return matches[len(matches)-n:], nil
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
