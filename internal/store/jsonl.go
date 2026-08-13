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
	"strings"
	"sync"
	"syscall"
	"unicode"
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
			// Malformed JSON, or content outside the documented vocabulary, is
			// skipped rather than aborting.
			if err := json.Unmarshal(line, &e); err == nil {
				if verr := validateEntry(&e); verr == nil && (hostname == "" || e.Hostname == hostname) {
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
						// grow memory use without bound. Keep scanning (not appending
						// more) so a later oversized-line count is still reported below.
					default:
						matches = append(matches, e)
					}
				}
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

	return matches, nil
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
