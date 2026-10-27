package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DD-VERDICT-1 item 2: Prune used to rewrite the file from ReadAll, which
// skips malformed, unknown-vocabulary and oversized lines — so once a host
// passed maxEntries, every prune permanently deleted those lines (a newer
// dsd's entries, a hand-edited line, evidence of corruption). It also
// re-marshalled the lines it did keep, dropping fields a newer dsd had added.
// Prune must never destroy what it could not parse.
func TestPrune_KeepsLinesItCouldNotParse(t *testing.T) {
	line := func(ts, verdict, extra string) string {
		return `{"ts":"` + ts + `","host":"h","version":"v","verdict":"` + verdict + `","checks":{"Disk":"OK"}` + extra + `}`
	}
	futureVersion := line("2026-01-02T00:00:00Z", "ESCALATED", `,"schema":9`) // verdict outside the vocabulary
	corrupt := `{"ts":"2026-01-02T12:00:00Z","host":"h","verd`                // truncated write
	oversized := `{"pad":"` + strings.Repeat("x", maxLineSizeBytes+10) + `"}` // > maxLineSizeBytes
	newestWithNewField := line("2026-01-05T00:00:00Z", "OK", `,"added_by_newer_dsd":{"a":1}`)

	lines := []string{
		line("2026-01-01T00:00:00Z", "OK", ""), // oldest valid: the only one over the limit
		futureVersion,
		line("2026-01-03T00:00:00Z", "OK", ""),
		corrupt,
		oversized,
		line("2026-01-04T00:00:00Z", "WARN", ""),
		newestWithNewField,
	}
	path := filepath.Join(t.TempDir(), "store.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var notice bytes.Buffer
	old := pruneNoticeWriter
	pruneNoticeWriter = &notice
	t.Cleanup(func() { pruneNoticeWriter = old })

	if err := Prune(path, "h", 3); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly the oldest valid entry is gone; everything else is byte-for-byte
	// where it was — including the unparseable lines and the new field.
	want := strings.Join(lines[1:], "\n") + "\n"
	if string(got) != want {
		t.Errorf("prune must remove only the oldest parseable entry and keep every other line verbatim, in place.\n got: %d bytes\nwant: %d bytes\nfuture kept=%v corrupt kept=%v oversized kept=%v new-field kept=%v",
			len(got), len(want),
			strings.Contains(string(got), futureVersion), strings.Contains(string(got), corrupt),
			strings.Contains(string(got), oversized), strings.Contains(string(got), newestWithNewField))
	}

	// The customer-journey rule: say what was kept and why.
	if !strings.Contains(notice.String(), "kept 3 line(s) it could not parse") {
		t.Errorf("prune must tell the user it kept the 3 unparseable lines (future-version, corrupt, oversized); notice = %q", notice.String())
	}
}

func TestPrune_NoNoticeWhenEverythingParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.jsonl")
	seedPruneStore(t, path, []Entry{
		{Hostname: "h", Verdict: "OK", Checks: map[string]string{}},
		{Hostname: "h", Verdict: "OK", Checks: map[string]string{}},
		{Hostname: "h", Verdict: "OK", Checks: map[string]string{}},
	})
	var notice bytes.Buffer
	old := pruneNoticeWriter
	pruneNoticeWriter = &notice
	t.Cleanup(func() { pruneNoticeWriter = old })
	if err := Prune(path, "h", 2); err != nil {
		t.Fatal(err)
	}
	if notice.Len() != 0 {
		t.Errorf("a clean store must prune silently, got %q", notice.String())
	}
}
