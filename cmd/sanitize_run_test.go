package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// captureStderr runs f with os.Stderr redirected to a pipe and returns what
// was written — the stderr counterpart to captureStdout (net_dns_test.go).
// Not parallel-safe for the same reason captureStdout isn't (shared os.Stderr
// swap); callers must not run in t.Parallel().
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// newTestBundleTarball writes a minimal, realistic bundle (one secret, one
// clean file) to a fresh tarball at dir/name.tar.gz and returns its path —
// mirrors internal/source/sanitize_roundtrip_test.go's TestSanitizeTarballRoundTrip
// setup, the exact flow `dsd sanitize` drives.
func newTestBundleTarball(t *testing.T, dir, name string) string {
	t.Helper()
	b := source.NewBundle()
	b.Manifest = source.Manifest{Format: source.FormatVersion, Host: "test-host"}
	b.PutFile("/etc/app.conf", []byte("api_key=PLANTED_SECRET_XYZ\nport=9090"))
	b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 1234"))
	path := filepath.Join(dir, name)
	if err := b.SaveTarball(path); err != nil {
		t.Fatalf("SaveTarball: %v", err)
	}
	return path
}

// newBareSanitizeCmd builds a bare cobra.Command with the flags runSanitize
// reads via cmd.Flags().GetBool/GetString.
func newBareSanitizeCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.StringP("out", "o", "", "")
	f.Bool("identifiers", false, "")
	return c
}

// TestRunSanitizeDefaultOutPath exercises runSanitize with no --out flag: the
// sanitized bundle should land at the default "-sanitized" suffixed path.
func TestRunSanitizeDefaultOutPath(t *testing.T) {
	dir := t.TempDir()
	in := newTestBundleTarball(t, dir, "raw.tar.gz")

	c := newBareSanitizeCmd()
	errOut := captureStderr(t, func() {
		if err := runSanitize(c, []string{in}); err != nil {
			t.Fatalf("runSanitize: %v", err)
		}
	})

	wantOut := sanitizedOutPath(in)
	if _, err := os.Stat(wantOut); err != nil {
		t.Errorf("expected sanitized bundle at %s, got: %v", wantOut, err)
	}
	if !strings.Contains(errOut, "Sanitized bundle written") {
		t.Errorf("should confirm the write on stderr, got:\n%s", errOut)
	}
	if !strings.Contains(errOut, "redaction") {
		t.Errorf("should report the redaction count, got:\n%s", errOut)
	}
	if !strings.Contains(errOut, "Identifiers (hostname, IPs, serials) kept") {
		t.Errorf("without --identifiers, should note identifiers were kept, got:\n%s", errOut)
	}
}

// TestRunSanitizeExplicitOutAndIdentifiers exercises the --out and
// --identifiers flags together.
func TestRunSanitizeExplicitOutAndIdentifiers(t *testing.T) {
	dir := t.TempDir()
	in := newTestBundleTarball(t, dir, "raw2.tar.gz")
	out := filepath.Join(dir, "clean.tar.gz")

	c := newBareSanitizeCmd()
	_ = c.Flags().Set("out", out)
	_ = c.Flags().Set("identifiers", "true")
	errOut := captureStderr(t, func() {
		if err := runSanitize(c, []string{in}); err != nil {
			t.Fatalf("runSanitize: %v", err)
		}
	})

	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected sanitized bundle at explicit --out path %s, got: %v", out, err)
	}
	if !strings.Contains(errOut, "Identifiers redacted") {
		t.Errorf("--identifiers should note identifiers were redacted, got:\n%s", errOut)
	}
}

// TestRunSanitizeMissingBundle exercises the load-error path: a nonexistent
// input file must produce a wrapped error, not panic.
func TestRunSanitizeMissingBundle(t *testing.T) {
	t.Parallel()
	c := newBareSanitizeCmd()
	err := runSanitize(c, []string{"/nonexistent/bundle.tar.gz"})
	if err == nil || !strings.Contains(err.Error(), "loading bundle") {
		t.Errorf("a missing bundle should error with load context, got: %v", err)
	}
}
