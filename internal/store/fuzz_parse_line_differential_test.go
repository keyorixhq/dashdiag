package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzStoreLineDifferential checks the two parse paths of the history store
// (~/.local/share/dsd store JSONL, read by `dsd history`/`dsd diff` through
// ReadAll and rewritten by `dsd health --persist` through Prune) against each
// other on one untrusted line.
//
// parseStoreLine's doc comment promises "exactly the acceptance ReadAll
// applies to one line", and Prune relies on that to decide which lines it may
// delete. Oracles:
//
//  1. Differential: ReadAll on a file holding just this line returns one entry
//     iff parseStoreLine accepts it, and the two entries are identical.
//  2. Determinism: parsing the same bytes repeatedly yields the same entry
//     every time (validateEntry rebuilds the Checks map after sanitising its
//     keys; two keys that sanitise to the same name must not make the result
//     depend on map iteration order).
//  3. Idempotence / round trip: an accepted entry, re-encoded with
//     json.Marshal (what Append writes), parses back to the same entry.
//
// Entries are compared through their json.Marshal encoding (map keys sorted,
// time in RFC 3339 with its offset), which is the store's own on-disk form.
//
// What it does NOT verify: multi-line files, line ordering or the n window of
// ReadAll (FuzzReadAll covers those), lines over maxLineSizeBytes (the fuzzer
// does not reach 1 MiB), Prune's rewrite and locking, or the vocabulary and
// control-character rules themselves (FuzzReadAll).
func FuzzStoreLineDifferential(f *testing.F) {
	for _, s := range []string{
		`{"ts":"2026-01-01T00:00:00Z","host":"h","version":"v1","verdict":"OK","checks":{}}`,
		`{"ts":"2026-01-01T00:00:00+02:00","host":"h","version":"v1","verdict":"WARN","checks":{"disk":"WARN","cpu":"OK"},"metrics":{"load":1.5}}`,
		`{"ts":"2026-01-01T00:00:00Z","host":"web\u0007","verdict":"CRIT","checks":{"disk\u0001":"CRIT"}}`,
		`{"Verdict":"OK","verdict":"WARN"}`,
		`{"verdict":"OK","checks":null}`,
		`{"verdict":"OK"} trailing`,
		`[1,2]`,
		`{"verdict":"OK","metrics":{"x":1e308}}`,
	} {
		f.Add([]byte(s))
	}
	path := filepath.Join(f.TempDir(), "store.jsonl")
	f.Fuzz(func(t *testing.T, line []byte) {
		if bytes.ContainsRune(line, '\n') || len(line) == 0 {
			return // one line per input; ReadAll and readRawLines split on '\n'
		}
		checkStoreLine(t, line, path)
	})
}

func entryKey(t *testing.T, e Entry) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("re-encoding an accepted entry failed: %v (%#v)", err, e)
	}
	return string(b)
}

func checkStoreLine(t *testing.T, line []byte, path string) {
	t.Helper()
	e, ok := parseStoreLine(bytes.Clone(line))

	// Oracle 2: determinism.
	for range 8 {
		e2, ok2 := parseStoreLine(bytes.Clone(line))
		if ok2 != ok {
			t.Fatalf("parseStoreLine acceptance flips between calls on %q", line)
		}
		if ok && entryKey(t, e2) != entryKey(t, e) {
			t.Fatalf("parseStoreLine is nondeterministic on %q:\n %s\n %s", line, entryKey(t, e), entryKey(t, e2))
		}
	}

	// Oracle 1: ReadAll on the same single line.
	if err := os.WriteFile(path, append(bytes.Clone(line), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAll(path, "", 0)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if (len(got) == 1) != ok || len(got) > 1 {
		t.Fatalf("acceptance differs: parseStoreLine ok=%v, ReadAll returned %d entries for %q", ok, len(got), line)
	}
	if !ok {
		return
	}
	if entryKey(t, got[0]) != entryKey(t, e) {
		t.Fatalf("ReadAll and parseStoreLine decode %q differently:\n ReadAll        %s\n parseStoreLine %s", line, entryKey(t, got[0]), entryKey(t, e))
	}

	// Oracle 3: round trip through the on-disk encoding.
	enc := entryKey(t, e)
	back, ok3 := parseStoreLine([]byte(enc))
	if !ok3 {
		t.Fatalf("accepted entry does not re-parse after json.Marshal: %s (from %q)", enc, line)
	}
	if entryKey(t, back) != enc {
		t.Fatalf("round trip changes the entry:\n first  %s\n second %s", enc, entryKey(t, back))
	}
}
