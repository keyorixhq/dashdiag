package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/store"
)

// DD-VERDICT-1 item 3 (audit findings 5 and 6). "I could not read it" is not
// "there is none": a corrupt or unreadable baseline/history must be reported as
// such, with the error and what to do, not folded into the first-run message.
func TestPrintHealthDiffNotice_CorruptBaselineIsNotCalledMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hostname, _ := os.Hostname()
	if err := baseline.SaveBaseline(&baseline.Snapshot{Hostname: hostname, Timestamp: time.Now()}); err != nil {
		t.Fatalf("seeding a baseline: %v", err)
	}
	home, _ := os.UserHomeDir()
	latest := filepath.Join(home, ".dsd", "baselines", baseline.SafeHostname(hostname)+"-latest.json")
	if err := os.WriteFile(latest, []byte("{this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		printHealthDiffNotice(os.Stderr, true, &baseline.Snapshot{Hostname: hostname}, output.ModePlain)
	})
	if strings.Contains(stderr, "No previous baseline") {
		t.Errorf("a corrupt baseline was reported as absent: %q", stderr)
	}
	for _, want := range []string{"Could not read the previous baseline", "parsing baseline"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("notice must carry %q (the actual error), got: %q", want, stderr)
		}
	}
	if !strings.Contains(stderr, "replace") {
		t.Errorf("notice must say what happens next (this run replaces the file), got: %q", stderr)
	}
}

func TestPrintHealthDiffNotice_MissingBaselineStillFirstRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stderr := captureStderr(t, func() {
		printHealthDiffNotice(os.Stderr, true, &baseline.Snapshot{Hostname: "h"}, output.ModePlain)
	})
	if !strings.Contains(stderr, "No previous baseline") {
		t.Errorf("a genuinely missing baseline keeps the first-run notice, got: %q", stderr)
	}
}

func TestPersistHealthRun_UnreadableHistoryWarnsInsteadOfSilentFirstRun(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("StorePath is /var/lib/dashdiag as root")
	}
	t.Setenv("HOME", t.TempDir())
	// A directory where the history file should be: opening it works, reading
	// it fails — the "exists but unreadable" shape (ErrNotExist it is not).
	if err := os.MkdirAll(store.StorePath(), 0o700); err != nil {
		t.Fatal(err)
	}
	snap := &baseline.Snapshot{Hostname: "h", Timestamp: time.Now()}
	stderr := captureStderr(t, func() {
		persistHealthRun(context.Background(), snap, nil, nil)
	})
	if !strings.Contains(stderr, "history is unreadable") {
		t.Errorf("an unreadable history must warn on stderr (not read as a silent first run), got: %q", stderr)
	}
}
