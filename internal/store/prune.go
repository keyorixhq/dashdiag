package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// pruneNoticeWriter receives the notice that Prune kept lines it could not
// parse. A var so tests can capture it.
var pruneNoticeWriter io.Writer = os.Stderr

// Prune atomically rewrites path, keeping at most maxEntries for hostname.
// Entries belonging to other hostnames are preserved unchanged.
// Returns nil (no-op) when the store is missing, empty, or already within limit.
//
// Prune only ever removes the OLDEST PARSEABLE entries of hostname. Every other
// line is carried over byte-for-byte and in place: a line it cannot parse
// (malformed JSON, a verdict/status outside this version's vocabulary such as
// one written by a newer dsd, a line over maxLineSizeBytes) is kept, not
// dropped, and so are the fields a newer dsd added to a line that does parse.
// It deliberately does not go through ReadAll, which skips such lines (and
// caps its result at maxReadAllEntries): rewriting the file from ReadAll's
// output deleted them for good once a host passed maxEntries. The number of
// lines kept this way is reported on pruneNoticeWriter.
func Prune(path string, hostname string, maxEntries int) error {
	if maxEntries <= 0 {
		return nil
	}

	raw, err := readRawLines(path)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}

	// Find the lines that parse to an entry of hostname (chronological order).
	var hostIdx []int
	unparsed := 0
	for i, l := range raw {
		e, ok := parseStoreLine(l)
		if !ok {
			unparsed++
			continue
		}
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
	for i, l := range raw {
		if _, skip := remove[i]; skip {
			continue
		}
		if _, err := w.Write(l); err != nil {
			return fmt.Errorf("store: prune: writing: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
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
	if unparsed > 0 {
		fmt.Fprintf(pruneNoticeWriter, "dsd: store: pruned %s, kept %d line(s) it could not parse (corrupt, oversized, or written by a newer dsd) — left in place, not deleted\n", path, unparsed)
	}
	return nil
}

// readRawLines returns every non-empty line of path, without its terminator and
// with no size limit (an oversized line must survive a prune). A missing file is
// "no store yet": (nil, nil), the same contract as ReadAll.
func readRawLines(path string) ([][]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) //nolint:gosec // path comes from StorePath(), not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: prune: reading %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	var lines [][]byte
	br := bufio.NewReaderSize(f, 64*1024)
	for {
		b, rerr := br.ReadBytes('\n')
		if line := bytes.TrimRight(b, "\n"); len(line) > 0 {
			lines = append(lines, line)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return lines, nil
			}
			return nil, fmt.Errorf("store: prune: reading %s: %w", path, rerr)
		}
	}
}

// parseStoreLine applies exactly the acceptance ReadAll applies to one line
// (size limit, JSON, vocabulary), so "parseable" means the same thing in both.
func parseStoreLine(line []byte) (Entry, bool) {
	var e Entry
	if len(line) > maxLineSizeBytes {
		return e, false
	}
	if err := json.Unmarshal(line, &e); err != nil {
		return e, false
	}
	if err := validateEntry(&e); err != nil {
		return e, false
	}
	return e, true
}
