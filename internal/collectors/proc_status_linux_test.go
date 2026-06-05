//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestParseProcStatusNameWithSpace verifies a comm containing a space (e.g.
// Firefox's "Web Content") is not truncated at the first token.
func TestParseProcStatusNameWithSpace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const status = "Name:\tWeb Content\n" +
		"State:\tS (sleeping)\n" +
		"Pid:\t4242\n" +
		"PPid:\t1\n"
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	var info models.ProcInfo
	parseProcStatus(dir, &info)
	if info.Name != "Web Content" {
		t.Errorf("Name: got %q, want %q", info.Name, "Web Content")
	}
	if info.PID != 4242 {
		t.Errorf("PID: got %d, want 4242", info.PID)
	}
}
