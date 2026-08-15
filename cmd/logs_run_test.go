package cmd

// logs_run_test.go covers runLogs's real (read-only) LogsCollector wiring
// (--plain/--json/--since) plus the printLogsReport family's remaining
// branches not already hit by logs_test.go's formatAgeMin table test —
// same real-I/O precedent as cpu_report_test.go.

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// newBareLogsCmd builds a bare cobra.Command with the flags runLogs reads.
func newBareLogsCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.String("since", "1h", "")
	return c
}

func TestRunLogsPlain(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareLogsCmd()
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runLogs(c, nil); err != nil {
			t.Fatalf("runLogs (plain): %v", err)
		}
	})
	if !strings.Contains(out, "Log health") {
		t.Errorf("plain mode should render the log health report, got: %q", out)
	}
}

func TestRunLogsJSON(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareLogsCmd()
	_ = c.Flags().Set("json", "true")
	_ = c.Flags().Set("since", "24h")
	out := captureStdout(t, func() {
		if err := runLogs(c, nil); err != nil {
			t.Fatalf("runLogs (json): %v", err)
		}
	})
	if !strings.Contains(out, "{") {
		t.Errorf("json mode should emit JSON, got: %q", out)
	}
}

// TestPrintLogsSeverityBranches exercises printLogsSeverity's remaining
// coverage: the TopCritical-present path (formatAgeMin both known and
// unknown) and the TopErrors fallback when TopCritical is empty.
func TestPrintLogsSeverityBranches(t *testing.T) {
	noneOut := captureStdout(t, func() {
		printLogsSeverity(&models.LogsInfo{}, output.ModePlain)
	})
	if noneOut != "" {
		t.Errorf("zero errors/warnings should print nothing, got:\n%s", noneOut)
	}

	withTopCritical := captureStdout(t, func() {
		printLogsSeverity(&models.LogsInfo{
			ErrorCount:   2,
			WarningCount: 1,
			TopCritical: []models.TopError{
				{Source: "kernel", Message: "oops", AgeMin: 5},
				{Source: "sshd", Message: "auth failure", AgeMin: -1},
			},
		}, output.ModePlain)
	})
	if !strings.Contains(withTopCritical, "kernel") || !strings.Contains(withTopCritical, "5m ago") {
		t.Errorf("a known-age critical event should show source and age, got:\n%s", withTopCritical)
	}
	if !strings.Contains(withTopCritical, "sshd: auth failure") || strings.Contains(withTopCritical, "sshd: auth failure —") {
		t.Errorf("an unknown-age critical event should show source/message with no trailing age, got:\n%s", withTopCritical)
	}
	if !strings.Contains(withTopCritical, "Warnings: 1") {
		t.Errorf("the warning count should be shown, got:\n%s", withTopCritical)
	}

	withTopErrorsFallback := captureStdout(t, func() {
		printLogsSeverity(&models.LogsInfo{
			ErrorCount: 1,
			TopErrors:  []string{"disk write error"},
		}, output.ModePlain)
	})
	if !strings.Contains(withTopErrorsFallback, "disk write error") {
		t.Errorf("TopErrors should be used when TopCritical is empty, got:\n%s", withTopErrorsFallback)
	}
}

// TestPrintLogsSeverity_StripsControlChars guards terminal escape injection:
// TopCritical Source/Message come from journal SYSLOG_IDENTIFIER and log
// text (sourceAndMessage in logs_linux.go), attacker-influenced via
// systemd-cat, unlike the other print sites in this file that already
// sanitize (printLogsOOM/Segfaults/CrashLoops/CrashFiles).
func TestPrintLogsSeverity_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printLogsSeverity(&models.LogsInfo{
			ErrorCount: 1,
			TopCritical: []models.TopError{
				{Source: "evil\x1b]0;pwned\x07", Message: "boom\x1b[2Jscreen-clear evil", AgeMin: -1},
			},
		}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printLogsSeverity output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printLogsSeverity output missing sanitized source:\n%s", out)
	}
	if !strings.Contains(out, "boom[2Jscreen-clear evil") {
		t.Errorf("printLogsSeverity output missing sanitized message:\n%s", out)
	}
}

func TestPrintLogsOOMBranches(t *testing.T) {
	none := captureStdout(t, func() { printLogsOOM(&models.LogsInfo{}, output.ModePlain) })
	if !strings.Contains(none, "none") {
		t.Errorf("zero OOM kills should say none, got:\n%s", none)
	}
	withKills := captureStdout(t, func() {
		printLogsOOM(&models.LogsInfo{OOMKills: 2, OOMProcesses: []string{"chrome (pid 123)"}}, output.ModePlain)
	})
	if !strings.Contains(withKills, "chrome (pid 123)") || !strings.Contains(withKills, "dmesg") {
		t.Errorf("OOM kills should list the process and an inspect hint, got:\n%s", withKills)
	}
}

// TestPrintLogsOOM_StripsControlChars guards terminal escape injection:
// OOM process names come from the kernel log (dmesg), which is
// attacker-influenced (a process can name itself anything).
func TestPrintLogsOOM_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printLogsOOM(&models.LogsInfo{OOMKills: 1, OOMProcesses: []string{"evil\x1b]0;pwned\x07"}}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printLogsOOM output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printLogsOOM output missing sanitized process name:\n%s", out)
	}
}

func TestPrintLogsSegfaultsBranches(t *testing.T) {
	none := captureStdout(t, func() { printLogsSegfaults(&models.LogsInfo{}, output.ModePlain) })
	if !strings.Contains(none, "none") {
		t.Errorf("zero segfaults should say none, got:\n%s", none)
	}
	with := captureStdout(t, func() {
		printLogsSegfaults(&models.LogsInfo{Segfaults: 1, SegfaultProcs: []string{"myapp (pid 42)"}}, output.ModePlain)
	})
	if !strings.Contains(with, "myapp (pid 42)") {
		t.Errorf("segfaults should list the process, got:\n%s", with)
	}
}

// TestPrintLogsSegfaults_StripsControlChars mirrors the OOM case for segfault
// process names.
func TestPrintLogsSegfaults_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printLogsSegfaults(&models.LogsInfo{Segfaults: 1, SegfaultProcs: []string{"evil\x1b]0;pwned\x07"}}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printLogsSegfaults output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printLogsSegfaults output missing sanitized process name:\n%s", out)
	}
}

func TestPrintLogsCrashLoopsBranches(t *testing.T) {
	none := captureStdout(t, func() { printLogsCrashLoops(&models.LogsInfo{}, output.ModePlain) })
	if !strings.Contains(none, "none") {
		t.Errorf("no crash loops should say none, got:\n%s", none)
	}
	with := captureStdout(t, func() {
		printLogsCrashLoops(&models.LogsInfo{CrashLoops: []string{"myapp.service (5 restarts)"}}, output.ModePlain)
	})
	if !strings.Contains(with, "myapp.service") || !strings.Contains(with, "journalctl -u myapp.service") {
		t.Errorf("a crash loop should show the unit and a journalctl hint, got:\n%s", with)
	}
}

// TestPrintLogsCrashLoops_StripsControlChars guards terminal escape
// injection on the crash-loop unit line (sourced from systemd unit state).
func TestPrintLogsCrashLoops_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printLogsCrashLoops(&models.LogsInfo{CrashLoops: []string{"evil.service\x1b]0;pwned\x07 (5 restarts)"}}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printLogsCrashLoops output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil.service]0;pwned") {
		t.Errorf("printLogsCrashLoops output missing sanitized unit text:\n%s", out)
	}
}

func TestPrintLogsCrashFilesBranches(t *testing.T) {
	none := captureStdout(t, func() { printLogsCrashFiles(&models.LogsInfo{}, output.ModePlain) })
	if none != "" {
		t.Errorf("no crash dumps should print nothing, got:\n%s", none)
	}
	with := captureStdout(t, func() {
		printLogsCrashFiles(&models.LogsInfo{
			CoreDumpCount: 2,
			CrashFiles: []models.CrashFile{
				{Path: "/var/crash/core.1", SizeMB: 12.5, AgeDays: 0},
				{Path: "/var/crash/core.2", SizeMB: 4.0, AgeDays: 3},
			},
		}, output.ModePlain)
	})
	if !strings.Contains(with, "today") || !strings.Contains(with, "3d ago") {
		t.Errorf("crash files should show 'today' for age 0 and 'Nd ago' otherwise, got:\n%s", with)
	}
}

// TestPrintLogsCrashFiles_StripsControlChars guards terminal escape
// injection on the crash-dump file path — a path under an attacker-writable
// crash directory could carry control bytes.
func TestPrintLogsCrashFiles_StripsControlChars(t *testing.T) {
	out := captureStdout(t, func() {
		printLogsCrashFiles(&models.LogsInfo{
			CoreDumpCount: 1,
			CrashFiles:    []models.CrashFile{{Path: "/var/crash/evil\x1b]0;pwned\x07", SizeMB: 1, AgeDays: 0}},
		}, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printLogsCrashFiles output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "evil]0;pwned") {
		t.Errorf("printLogsCrashFiles output missing sanitized path:\n%s", out)
	}
}

func TestPrintLogsJournalSizeBranches(t *testing.T) {
	small := captureStdout(t, func() { printLogsJournalSize(&models.LogsInfo{JournalSizeGB: 0.0001}) })
	if !strings.Contains(small, "< 1 MB") {
		t.Errorf("a tiny journal should show < 1 MB, got:\n%s", small)
	}
	mb := captureStdout(t, func() { printLogsJournalSize(&models.LogsInfo{JournalSizeGB: 0.5}) })
	if !strings.Contains(mb, "MB") {
		t.Errorf("a sub-GB journal should show MB, got:\n%s", mb)
	}
	gb := captureStdout(t, func() {
		printLogsJournalSize(&models.LogsInfo{JournalSizeGB: 2.5, LogSource: "/var/log/syslog"})
	})
	if !strings.Contains(gb, "GB") || !strings.Contains(gb, "/var/log/syslog") {
		t.Errorf("a multi-GB journal with a non-journald source should show both, got:\n%s", gb)
	}
}

func TestFormatDurationBranches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Minute, "30m"},
		{6 * time.Hour, "6h"},
		{48 * time.Hour, "2d"},
	}
	for _, c := range cases {
		if got := formatDuration(c.d); got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// TestPrintLogsReportSummaryLines covers the four mutually-exclusive summary
// branches at the tail of printLogsReport (issues / unverified / needs-root /
// clean).
func TestPrintLogsReportSummaryLines(t *testing.T) {
	issues := captureStdout(t, func() {
		printLogsReport(&models.LogsInfo{Segfaults: 1}, output.ModePlain, time.Second, time.Hour)
	})
	if !strings.Contains(issues, "log issue(s) found") {
		t.Errorf("a segfault should be reported as an issue, got:\n%s", issues)
	}

	// The summary tally's own OOMKills>0 branch — distinct from Segfaults
	// above and from printLogsOOM's own direct test (TestPrintLogsOOMBranches).
	oomIssue := captureStdout(t, func() {
		printLogsReport(&models.LogsInfo{OOMKills: 1}, output.ModePlain, time.Second, time.Hour)
	})
	if !strings.Contains(oomIssue, "log issue(s) found") {
		t.Errorf("an OOM kill should be reported as an issue in the summary tally, got:\n%s", oomIssue)
	}

	unverified := captureStdout(t, func() {
		printLogsReport(&models.LogsInfo{ErrorCountUnverified: true}, output.ModePlain, time.Second, time.Hour)
	})
	if !strings.Contains(unverified, "NOT verified") {
		t.Errorf("an unverified error scan should say so, got:\n%s", unverified)
	}

	needsRoot := captureStdout(t, func() {
		printLogsReport(&models.LogsInfo{NeedsRoot: true}, output.ModePlain, time.Second, time.Hour)
	})
	if !strings.Contains(needsRoot, "run as root") {
		t.Errorf("a non-root run should note the limitation, got:\n%s", needsRoot)
	}

	clean := captureStdout(t, func() {
		printLogsReport(&models.LogsInfo{}, output.ModePlain, time.Second, time.Hour)
	})
	if !strings.Contains(clean, "Checks passed") {
		t.Errorf("a clean report should say checks passed, got:\n%s", clean)
	}
}
