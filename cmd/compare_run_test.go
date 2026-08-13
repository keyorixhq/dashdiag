package cmd

// compare_run_test.go — covers runCompare's file/stdin loading path
// (loadCompareSnapshots, readCompareStream) and the >=2-snapshot success path
// of runCompare itself. The <2-snapshot branch calls os.Exit(1) directly and
// is not exercised here — see the package-level os.Exit carve-out.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newBareCompareCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("all", false, "")
	return c
}

const compareSnapA = `{"hostname":"web01","timestamp":"2026-01-01T00:00:00Z","checks":[{"name":"Disk","status":"OK"}]}`
const compareSnapB = `{"hostname":"web02","timestamp":"2026-01-01T00:00:00Z","checks":[{"name":"Disk","status":"CRIT"}]}`

func TestRunCompare_TwoFilesSucceeds(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.json")
	f2 := filepath.Join(dir, "b.json")
	if err := os.WriteFile(f1, []byte(compareSnapA), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte(compareSnapB), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareCompareCmd()
	_ = cmd.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runCompare(cmd, []string{f1, f2}); err != nil {
			t.Fatalf("runCompare: %v", err)
		}
	})
	if !strings.Contains(out, "Fleet comparison") {
		t.Errorf("expected the comparison header, got:\n%s", out)
	}
	if !strings.Contains(out, "1 check(s) differ") {
		t.Errorf("expected the diverging Disk check to be reported, got:\n%s", out)
	}
}

func TestRunCompare_StdinDashAndFileMixed(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.json")
	if err := os.WriteFile(f1, []byte(compareSnapA), 0o600); err != nil {
		t.Fatal(err)
	}
	withHookStdin(t, compareSnapB)
	cmd := newBareCompareCmd()
	_ = cmd.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runCompare(cmd, []string{f1, "-"}); err != nil {
			t.Fatalf("runCompare: %v", err)
		}
	})
	if !strings.Contains(out, "web01") || !strings.Contains(out, "web02") {
		t.Errorf("both the file snapshot and the stdin snapshot should appear, got:\n%s", out)
	}
}

func TestRunCompare_NoArgsReadsStdin(t *testing.T) {
	// Newline-delimited JSON on stdin with no file args at all.
	ndjson := compareSnapA + "\n" + compareSnapB
	withHookStdin(t, ndjson)
	cmd := newBareCompareCmd()
	_ = cmd.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runCompare(cmd, nil); err != nil {
			t.Fatalf("runCompare: %v", err)
		}
	})
	if !strings.Contains(out, "2 hosts") {
		t.Errorf("both NDJSON snapshots should be parsed, got:\n%s", out)
	}
}

// TestRunCompare_LoadErrorPropagates covers the branch where
// loadCompareSnapshots itself fails (returned before the <2-snapshot /
// os.Exit branch, which is not exercised here — see the package-level
// os.Exit carve-out).
func TestRunCompare_LoadErrorPropagates(t *testing.T) {
	t.Parallel()
	cmd := newBareCompareCmd()
	err := runCompare(cmd, []string{filepath.Join(t.TempDir(), "nope.json")})
	if err == nil {
		t.Fatal("a nonexistent snapshot file should propagate the load error")
	}
}

// TestLoadCompareSnapshots_StdinNoArgsErrors covers loadCompareSnapshots' own
// stdin error-wrap branch (no file args at all, so it reads os.Stdin
// directly) — distinct from the "-" mixed-with-files case in
// TestRunCompare_StdinDashAndFileMixed and the file-path error case below.
func TestLoadCompareSnapshots_StdinNoArgsErrors(t *testing.T) {
	withHookStdin(t, "not json, not ndjson either {{{")
	_, err := loadCompareSnapshots(nil)
	if err == nil {
		t.Fatal("garbage stdin input with no args should error")
	}
	if !strings.Contains(err.Error(), "reading stdin") {
		t.Errorf("error should be wrapped with 'reading stdin' context, got: %v", err)
	}
}

func TestLoadCompareSnapshots_MissingFileErrors(t *testing.T) {
	t.Parallel()
	_, err := loadCompareSnapshots([]string{filepath.Join(t.TempDir(), "nope.json")})
	if err == nil {
		t.Fatal("a nonexistent file path should error")
	}
}

func TestLoadCompareSnapshots_UnparsableFileErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCompareSnapshots([]string{p})
	if err == nil {
		t.Fatal("an unparsable file should error")
	}
}

func TestReadCompareStream_NoValidJSONErrors(t *testing.T) {
	t.Parallel()
	_, err := readCompareStream(strings.NewReader("not json, not ndjson either {{{"))
	if err == nil {
		t.Fatal("garbage input should error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

func TestReadCompareStream_ReaderErrorPropagates(t *testing.T) {
	t.Parallel()
	if _, err := readCompareStream(errReader{}); err == nil {
		t.Fatal("a failing reader should propagate its error")
	}
}

// TestReadCompareStream_RejectsOversizedInput covers cmd-02-03:
// readCompareStream must not buffer an unbounded amount of memory reading a
// remote/untrusted snapshot stream (stdin or a file argument). A stream far
// larger than any real multi-host snapshot batch must be refused, not read
// fully into memory first.
func TestReadCompareStream_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	huge := strings.NewReader(strings.Repeat("a", maxCompareStreamBytes+(2<<20)))
	_, err := readCompareStream(huge)
	if err == nil {
		t.Fatal("expected an error for input exceeding maxCompareStreamBytes, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected a size-cap error, got: %v", err)
	}
}

// TestReadCompareStream_EmptyInputErrors covers the len(out)==0 guard: when
// input is not a valid JSON object AND the NDJSON decoder finds no tokens
// (empty string), the function returns "no valid JSON snapshots found".
func TestReadCompareStream_EmptyInputErrors(t *testing.T) {
	t.Parallel()
	_, err := readCompareStream(strings.NewReader(""))
	if err == nil {
		t.Fatal("empty input should error")
	}
	if !strings.Contains(err.Error(), "no valid JSON snapshots found") {
		t.Errorf("error = %q, want 'no valid JSON snapshots found'", err)
	}
}

// TestLoadCompareSnapshots_DashStdinErrors covers the "-" stdin-error branch
// in loadCompareSnapshots (line 103-105): when "-" is given as a file arg but
// stdin content is invalid, the error is wrapped with "reading stdin".
func TestLoadCompareSnapshots_DashStdinErrors(t *testing.T) {
	withHookStdin(t, "not json, not ndjson either {{{")
	_, err := loadCompareSnapshots([]string{"-"})
	if err == nil {
		t.Fatal("garbage stdin via '-' arg should error")
	}
	if !strings.Contains(err.Error(), "reading stdin") {
		t.Errorf("error = %q, want 'reading stdin' context", err)
	}
}

func TestReadCompareStream_SingleObject(t *testing.T) {
	t.Parallel()
	snaps, err := readCompareStream(strings.NewReader(compareSnapA))
	if err != nil {
		t.Fatalf("single JSON object should parse: %v", err)
	}
	if len(snaps) != 1 || snaps[0].Hostname != "web01" {
		t.Errorf("unexpected snapshots: %+v", snaps)
	}
}
