package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// FuzzReadAll fuzzes ReadAll(path, hostname, n) against attacker-controlled
// JSONL file content — the store file can be shared over NFS, restored from a
// backup, written by a different dsd version, or tampered with by any local
// process with write access, per validateEntry's doc comment. ReadAll must
// treat every line as untrusted: a corrupt or hostile line is skipped or
// errors, never surfaces an Entry whose fields fall outside the documented
// vocabulary or carry attacker-chosen control characters, and the n bound is
// honoured regardless of file contents.
func FuzzReadAll(f *testing.F) {
	good := `{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":{}}` + "\n"
	badVerdict := `{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"WORSE","checks":{}}` + "\n"
	badCheck := `{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":{"disk":"UHOH"}}` + "\n"
	evil := "evil\x1b[2Jname"
	controlHost := `{"ts":"2026-01-01T00:00:00Z","host":"` + evil + `","version":"v1","verdict":"OK","checks":{}}` + "\n"
	controlCheckKey := `{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":{"` + evil + `":"OK"}}` + "\n"

	seeds := []string{
		"",
		good,
		strings.Repeat(good, 5),
		badVerdict,
		badCheck,
		controlHost,
		controlCheckKey,
		"not json at all\n",
		"{\n",
		`{"ts":"bad-timestamp","host":"h","version":"v1","verdict":"OK","checks":{}}` + "\n",
		`{"host":"h"}` + "\n", // missing verdict — rejected by vocabulary check
		strings.Repeat("x", maxLineSizeBytes+10) + "\n" + good, // oversized line, resumable
		good + "\x00\x00\x00\n" + good,
		`[]` + "\n", // valid JSON, wrong shape (array not object)
		`{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":null}` + "\n",
		good[:len(good)-2], // truncated mid-object, no trailing newline
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "store.jsonl")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing fuzz store file: %v", err)
		}

		checkEntries := func(entries []Entry, label string) {
			for _, e := range entries {
				if !validVerdicts[e.Verdict] {
					t.Fatalf("%s: ReadAll returned Entry with out-of-vocabulary verdict %q", label, e.Verdict)
				}
				for name, status := range e.Checks {
					if !validCheckStatuses[status] {
						t.Fatalf("%s: ReadAll returned Entry with out-of-vocabulary check status %q for %q", label, status, name)
					}
					if strings.ContainsFunc(name, unicode.IsControl) {
						t.Fatalf("%s: ReadAll returned Entry with a control character in check name %q", label, name)
					}
				}
				if strings.ContainsFunc(e.Hostname, unicode.IsControl) {
					t.Fatalf("%s: ReadAll returned Entry with a control character in Hostname %q", label, e.Hostname)
				}
			}
		}

		unbounded, err := ReadAll(path, "", 0)
		if err != nil {
			return // an I/O-level error (not malformed content, which ReadAll skips) is fine
		}
		if len(unbounded) > maxReadAllEntries {
			t.Fatalf("unbounded ReadAll returned %d entries, exceeding maxReadAllEntries (%d)", len(unbounded), maxReadAllEntries)
		}
		checkEntries(unbounded, "unbounded")

		const boundedN = 3
		bounded, err := ReadAll(path, "", boundedN)
		if err != nil {
			t.Fatalf("bounded ReadAll errored after unbounded ReadAll succeeded: %v", err)
		}
		if len(bounded) > boundedN {
			t.Fatalf("ReadAll(path, \"\", %d) returned %d entries — n bound not honoured", boundedN, len(bounded))
		}
		checkEntries(bounded, "bounded")

		const filterHost = "h"
		filtered, err := ReadAll(path, filterHost, 0)
		if err != nil {
			t.Fatalf("hostname-filtered ReadAll errored after unbounded ReadAll succeeded: %v", err)
		}
		for _, e := range filtered {
			if e.Hostname != filterHost {
				t.Fatalf("ReadAll(path, %q, 0) returned an Entry for a different host %q — hostname filter not honoured", filterHost, e.Hostname)
			}
		}
		checkEntries(filtered, "hostname-filtered")
	})
}
