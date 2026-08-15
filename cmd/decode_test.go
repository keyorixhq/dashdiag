package cmd

// decode_test.go — covers runDecode: file-arg and stdin input, --json and
// human rendering, and the error paths (bad blob markers, invalid payload
// JSON). Reuses withHookStdin (hook_run_test.go) and captureStdout
// (net_dns_test.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/share"
)

func newBareDecodeCmd() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().Bool("json", false, "")
	return c
}

const decodeReportJSON = `{"hostname":"web01","os":"Ubuntu 24.04","version":"1.2.3","verdict":"WARN",` +
	`"counts":{"crit":0,"warn":1,"info":0},"checks":[{"name":"Disk","status":"WARN"}],` +
	`"insights":[{"check":"Disk","level":"WARN","message":"80% full"}]}`

func TestRunDecode_FromFileHuman(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob.txt")
	blob := share.Encode([]byte(decodeReportJSON))
	if err := os.WriteFile(p, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareDecodeCmd()
	out := captureStdout(t, func() {
		if err := runDecode(cmd, []string{p}); err != nil {
			t.Fatalf("runDecode: %v", err)
		}
	})
	if !strings.Contains(out, "web01") {
		t.Errorf("decoded report should mention the hostname, got:\n%s", out)
	}
}

func TestRunDecode_FromFileJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob.txt")
	blob := share.Encode([]byte(decodeReportJSON))
	if err := os.WriteFile(p, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareDecodeCmd()
	_ = cmd.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runDecode(cmd, []string{p}); err != nil {
			t.Fatalf("runDecode --json: %v", err)
		}
	})
	if !strings.Contains(out, `"hostname":"web01"`) {
		t.Errorf("--json should print the raw decoded JSON, got: %q", out)
	}
}

func TestRunDecode_FromStdin(t *testing.T) {
	blob := share.Encode([]byte(decodeReportJSON))
	withHookStdin(t, blob)
	cmd := newBareDecodeCmd()
	out := captureStdout(t, func() {
		if err := runDecode(cmd, nil); err != nil {
			t.Fatalf("runDecode (stdin): %v", err)
		}
	})
	if !strings.Contains(out, "web01") {
		t.Errorf("decoded report from stdin should mention the hostname, got:\n%s", out)
	}
}

func TestRunDecode_DashArgReadsStdin(t *testing.T) {
	blob := share.Encode([]byte(decodeReportJSON))
	withHookStdin(t, blob)
	cmd := newBareDecodeCmd()
	out := captureStdout(t, func() {
		if err := runDecode(cmd, []string{"-"}); err != nil {
			t.Fatalf("runDecode (dash arg): %v", err)
		}
	})
	if !strings.Contains(out, "web01") {
		t.Errorf("'-' arg should read from stdin, got:\n%s", out)
	}
}

// TestRunDecode_RejectsOversizedFile covers cmd-03-02: runDecode must not
// read an unbounded amount of raw (pre-decode) input from a file or stdin.
// Before the blob is even base64/gzip-decoded, the raw bytes were read with
// a bare os.ReadFile/io.ReadAll — a huge file (not even a valid blob) would
// be fully buffered just to find that out.
func TestRunDecode_RejectsOversizedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20) // 1MiB, reused
	for written := 0; written < maxRawBlobBytes+(2<<20); written += len(chunk) {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := newBareDecodeCmd()
	err = runDecode(cmd, []string{p})
	if err == nil {
		t.Fatal("expected an error decoding a file exceeding maxRawBlobBytes, got nil")
	}
	// The oversized-input rejection must fire, not just "no blob markers found"
	// (which an unbounded read of the same all-zero content would also hit,
	// masking a missing cap as a false pass).
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected a size-cap error, got: %v", err)
	}
}

func TestRunDecode_MissingFileErrors(t *testing.T) {
	t.Parallel()
	cmd := newBareDecodeCmd()
	if err := runDecode(cmd, []string{filepath.Join(t.TempDir(), "nope.txt")}); err == nil {
		t.Fatal("a nonexistent file should error")
	}
}

func TestRunDecode_NoBlobMarkersErrors(t *testing.T) {
	withHookStdin(t, "just some chat text, no blob here")
	cmd := newBareDecodeCmd()
	if err := runDecode(cmd, nil); err == nil {
		t.Fatal("text without BEGIN/END markers should error")
	}
}

func TestRunDecode_InvalidPayloadJSONErrors(t *testing.T) {
	blob := share.Encode([]byte("not valid json"))
	withHookStdin(t, blob)
	cmd := newBareDecodeCmd()
	if err := runDecode(cmd, nil); err == nil {
		t.Fatal("a blob whose payload isn't valid dsd JSON should error")
	}
}

// TestRunDecode_JSONFlagRejectsInvalidPayload is the regression test for
// cmd-03-03: the --json branch used to write the decoded payload straight to
// stdout with no validation, unlike the human-rendered path. A corrupted or
// hostile blob must be rejected the same way regardless of --json.
func TestRunDecode_JSONFlagRejectsInvalidPayload(t *testing.T) {
	blob := share.Encode([]byte("not valid json"))
	withHookStdin(t, blob)
	cmd := newBareDecodeCmd()
	_ = cmd.Flags().Set("json", "true")
	var runErr error
	out := captureStdout(t, func() {
		runErr = runDecode(cmd, nil)
	})
	if runErr == nil {
		t.Fatal("--json with a blob whose payload isn't valid dsd JSON should error")
	}
	if out != "" {
		t.Errorf("nothing should reach stdout before validation fails, got: %q", out)
	}
}
