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
