package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for processes.go's report renderers. printProcessesReport
// calls drilldown.ZombiesWithParent/HungProcesses/TopProcessesByCPU/
// TopProcessesByRSS internally — real but cheap (fast on macOS, a 200ms
// two-sample delta on Linux), same cost the live command already pays. These
// tests assert only on the deterministic counters/hints/verdict text, not the
// live table contents (which vary by host). No t.Parallel() (corrupts
// captureStdout's shared os.Stdout swap).

func TestZombiesTable(t *testing.T) {
	if got := zombiesTable(&models.ProcessInfo{}); got != nil {
		t.Errorf("no zombie procs should return nil, got %+v", got)
	}
	d := zombiesTable(&models.ProcessInfo{ZombieProcs: []models.ProcessState{{PID: 123, PPID: 1, ParentName: "systemd"}}})
	if d == nil || len(d.Rows) != 1 || d.Rows[0][0] != "123" {
		t.Errorf("a zombie proc should produce one row with its PID, got %+v", d)
	}
}

func TestHungTable(t *testing.T) {
	if got := hungTable(&models.ProcessInfo{}); got != nil {
		t.Errorf("no hung procs should return nil, got %+v", got)
	}
	d := hungTable(&models.ProcessInfo{HungProcs: []models.ProcessState{{PID: 456, Name: "nfsd", WChan: "nfs_wait"}}})
	if d == nil || len(d.Rows) != 1 || d.Rows[0][2] != "nfs_wait" {
		t.Errorf("a hung proc should produce one row with its wchan, got %+v", d)
	}
}

// TestZombiesTable_StripsControlChars guards terminal escape injection:
// ParentName comes from /proc/<pid>/stat's comm field, which any process can
// set to arbitrary bytes (e.g. via prctl(PR_SET_NAME) or argv[0]).
func TestZombiesTable_StripsControlChars(t *testing.T) {
	evil := "\x1b[2Jscreen-clear evil"
	d := zombiesTable(&models.ProcessInfo{ZombieProcs: []models.ProcessState{{PID: 1, PPID: 2, ParentName: evil}}})
	out := captureStdout(t, func() {
		printProcessTable(d)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("zombiesTable/printProcessTable output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "[2Jscreen-clear evil") {
		t.Errorf("output missing sanitized-but-present evil text:\n%s", out)
	}
}

// TestHungTable_StripsControlChars mirrors TestZombiesTable_StripsControlChars
// for hungTable's Name and WChan fields, both sourced from untrusted /proc data.
func TestHungTable_StripsControlChars(t *testing.T) {
	evil := "\x1b[2Jscreen-clear evil"
	d := hungTable(&models.ProcessInfo{HungProcs: []models.ProcessState{{PID: 1, Name: evil, WChan: evil}}})
	out := captureStdout(t, func() {
		printProcessTable(d)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("hungTable/printProcessTable output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "[2Jscreen-clear evil") {
		t.Errorf("output missing sanitized-but-present evil text:\n%s", out)
	}
}

func TestPrintProcessTable(t *testing.T) {
	out := captureStdout(t, func() {
		printProcessTable(&models.Details{
			Title:   "Zombie processes",
			Columns: []string{"PID", "PPID", "PARENT"},
			Rows:    [][]string{{"123", "1", "systemd"}},
		})
	})
	if !strings.Contains(out, "Zombie processes:") || !strings.Contains(out, "123") || !strings.Contains(out, "systemd") {
		t.Errorf("the table should render its title, header, and row, got:\n%s", out)
	}
}

func TestPrintProcessesReportCounters(t *testing.T) {
	clean := captureStdout(t, func() {
		printProcessesReport(context.Background(), &models.ProcessInfo{}, output.ModePlain, 0)
	})
	if !strings.Contains(clean, "Zombie Processes: 0") || !strings.Contains(clean, "Hung (D-state) Processes: 0") {
		t.Errorf("counters should be shown even at zero, got:\n%s", clean)
	}
	if !strings.Contains(clean, "Processes healthy") {
		t.Errorf("no zombies/hung processes should read healthy, got:\n%s", clean)
	}

	zombies := captureStdout(t, func() {
		printProcessesReport(context.Background(), &models.ProcessInfo{ZombieCount: 3}, output.ModePlain, 0)
	})
	if !strings.Contains(zombies, "Zombie Processes: 3") {
		t.Errorf("the zombie count should be shown, got:\n%s", zombies)
	}
	if !strings.Contains(zombies, "restart the parent process") {
		t.Errorf("a nonzero zombie count should show the remediation hint, got:\n%s", zombies)
	}
	if !strings.Contains(zombies, "process concern(s) found") {
		t.Errorf("zombies present should count as a concern, got:\n%s", zombies)
	}

	hung := captureStdout(t, func() {
		printProcessesReport(context.Background(), &models.ProcessInfo{HungCount: 2}, output.ModePlain, 0)
	})
	if !strings.Contains(hung, "Hung (D-state) Processes: 2") {
		t.Errorf("the hung count should be shown, got:\n%s", hung)
	}
	if !strings.Contains(hung, "/proc/PID/wchan") {
		t.Errorf("a nonzero hung count should show the inspection hint, got:\n%s", hung)
	}
}

// TestRunProcesses exercises runProcesses's real (read-only) collector wiring
// in --plain and --json mode. Same real-I/O precedent as cpu_report_test.go.
func TestRunProcesses(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runProcesses(plainCmd, nil); err != nil {
			t.Fatalf("runProcesses (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Zombie Processes") {
		t.Errorf("plain mode should render the zombie count, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runProcesses(jsonCmd, nil); err != nil {
			t.Fatalf("runProcesses (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}

// TestWatchProcesses exercises watchProcesses's one-shot run (real collector,
// same cost as TestRunProcesses) plus its ctx.Done() exit path — an
// already-cancelled context makes the select loop return immediately after
// the first run instead of blocking on the ticker.
func TestWatchProcesses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := captureStdout(t, func() {
		if err := watchProcesses(ctx, time.Millisecond, output.ModePlain); err != nil {
			t.Fatalf("watchProcesses: %v", err)
		}
	})
	if !strings.Contains(out, "Zombie Processes") {
		t.Errorf("watchProcesses should render one report before exiting, got: %q", out)
	}
}
