package init_pkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// t.Setenv panics if called from a parallel test, so these intentionally skip
// t.Parallel() — same convention as internal/tips/state_test.go.

func TestIsFirstRun_NoStateFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if !IsFirstRun() {
		t.Error("expected IsFirstRun() to be true when ~/.dsd/state.json does not exist")
	}
}

func TestIsFirstRun_StateFileExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, ".dsd"), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".dsd", "state.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if IsFirstRun() {
		t.Error("expected IsFirstRun() to be false when ~/.dsd/state.json exists")
	}
}

func TestWriteProfileConfig_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	writeProfileConfig("web")

	path := filepath.Join(dir, ".dsd.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected %s to be written: %v", path, err)
	}
	if got := string(data); !strings.Contains(got, "Profile: web") {
		t.Errorf("config content = %q, want it to mention Profile: web", got)
	}
}

func TestWriteProfileConfig_DoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	path := filepath.Join(dir, ".dsd.yaml")
	const original = "# hand-edited config\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	writeProfileConfig("database")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != original {
		t.Errorf("existing config was overwritten: got %q, want %q", string(data), original)
	}
}

// RunWizard reads a profile choice from stdin. With stdin at EOF (as in this
// test), the text-mode selector returns an empty choice and RunWizard bails
// out before writing anything — this exercises that early-return path without
// needing a real TTY or bubbletea harness.
func TestRunWizard_EOFStdinNoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	w.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	if err := RunWizard(output.ModeHuman); err != nil {
		t.Errorf("RunWizard() = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".dsd.yaml")); !os.IsNotExist(err) {
		t.Error("expected no config file to be written when stdin has no selection")
	}
}
