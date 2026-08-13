package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteReportFileNoFollow_RefusesSymlink guards internal-render-01-03 /
// internal-render-04-03: the fleet and wave HTML report generators derive a
// fully predictable filename (a second-resolution timestamp) and write it
// into the current working directory. Plain os.WriteFile opens with
// O_CREATE|O_TRUNC and follows an existing symlink at that path — if another
// local user in a shared working directory pre-plants a symlink at the
// predictable filename pointing at a file the report-generating user can
// write but the attacker cannot, the write would silently clobber that
// target. writeReportFileNoFollow must refuse to write through a
// pre-existing symlink.
func TestWriteReportFileNoFollow_RefusesSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// The attacker's intended overwrite target, OUTSIDE dir.
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("original contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The predictable report path, pre-planted as a symlink to victim.
	reportPath := filepath.Join(dir, "dsd-fleet-report-20260101-000000.html")
	if err := os.Symlink(victim, reportPath); err != nil {
		t.Fatal(err)
	}

	err := writeReportFileNoFollow(reportPath, []byte("<html>attacker-controlled report body</html>"), 0o644)
	if err == nil {
		t.Fatal("expected an error refusing to write through the symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error = %v, want a message naming the symlink refusal", err)
	}

	// The victim file must be untouched.
	data, readErr := os.ReadFile(victim) //nolint:gosec // test-controlled path
	if readErr != nil {
		t.Fatalf("reading victim: %v", readErr)
	}
	if string(data) != "original contents" {
		t.Errorf("victim file was overwritten: %q", data)
	}
}

// TestWriteReportFileNoFollow_OverwritesRegularFile confirms the common case —
// a re-run overwriting a prior REGULAR-file report at the same path — still
// works; the fix must only refuse symlinks, not idempotent re-runs.
func TestWriteReportFileNoFollow_OverwritesRegularFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "dsd-fleet-report-20260101-000000.html")
	if err := os.WriteFile(path, []byte("old report"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFileNoFollow(path, []byte("new report"), 0o644); err != nil {
		t.Fatalf("writeReportFileNoFollow: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new report" {
		t.Errorf("content = %q, want the re-run to overwrite a regular file", data)
	}
}
