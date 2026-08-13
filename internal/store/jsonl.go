package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
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

	var matches []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLineSizeBytes)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue // skip malformed lines rather than aborting
		}
		if err := validateEntry(&e); err != nil {
			continue // skip entries whose content doesn't match the documented vocabulary
		}
		if hostname == "" || e.Hostname == hostname {
			matches = append(matches, e)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			fmt.Fprintf(os.Stderr, "dsd: store: oversized line in %s skipped (line > %d bytes)\n", path, maxLineSizeBytes)
			return matches, nil // return what we have
		}
		return nil, fmt.Errorf("store: scanning %s: %w", path, err)
	}

	if n <= 0 || len(matches) <= n {
		return matches, nil
	}
	return matches[len(matches)-n:], nil
}

// validVerdicts is Entry.Verdict's documented vocabulary (store.go: "OK |
// WARN | CRIT" — VerdictFromInsights never produces anything else).
var validVerdicts = map[string]bool{"OK": true, "WARN": true, "CRIT": true}

// validCheckStatuses is Entry.Checks' documented per-check status
// vocabulary — the same five values CLAUDE.md's model contract defines for
// any Status field ("OK"|"WARN"|"CRIT"|"INFO"|"PENDING"), broader than
// Verdict's three because an individual check (not the overall rollup) can
// be INFO (a collector that errored) or PENDING.
var validCheckStatuses = map[string]bool{"OK": true, "WARN": true, "CRIT": true, "INFO": true, "PENDING": true}

// validateEntry rejects an Entry whose content doesn't match the vocabulary
// this package documents, and sanitizes the two fields with no fixed
// vocabulary (Hostname, and Checks' keys — check names). The store file is
// meant to be produced only by this package's own Append, but ReadAll treats
// it as a trust boundary like every other read path in the codebase: a
// shared/NFS-mounted home directory read by multiple hosts, a restored
// backup, a downgraded/upgraded dsd version with different field semantics,
// or direct tampering by any local process with write access to the file
// could all produce a line that decodes as valid JSON but carries content
// this package never wrote. Hostname/Checks reach cmd/history.go and
// cmd/diff.go, which print them straight to the terminal with no
// sanitization of their own.
func validateEntry(e *Entry) error {
	if !validVerdicts[e.Verdict] {
		return fmt.Errorf("store: verdict %q not in {OK,WARN,CRIT}", e.Verdict)
	}
	for name, status := range e.Checks {
		if !validCheckStatuses[status] {
			return fmt.Errorf("store: check %q status %q not in {OK,WARN,CRIT,INFO,PENDING}", name, status)
		}
	}
	e.Hostname = stripControl(e.Hostname)
	// Checks map keys (check names) have no fixed vocabulary — rebuild the
	// map with sanitized keys. Values are already vocabulary-checked above,
	// so nothing to strip there.
	clean := make(map[string]string, len(e.Checks))
	for name, status := range e.Checks {
		clean[stripControl(name)] = status
	}
	e.Checks = clean
	return nil
}

// stripControl removes control characters (including ESC, which starts
// ANSI/OSC/DCS terminal escape sequences) from s, leaving printable text
// unchanged. store/ has no dependency on internal/output today, so this
// duplicates the small amount of logic in output.SanitizeControl rather than
// adding a new cross-package import for one helper.
func stripControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
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
