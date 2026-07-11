package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for cron.go's printCron branches not already covered by
// falseok_verdict_test.go's unverified-failures guard. No t.Parallel()
// (corrupts captureStdout's shared os.Stdout swap).

// TestPrintCronDaemonStates covers the daemon-status branches: anacron-only,
// systemd-timers-only, and the "nothing schedules jobs" warn (which also
// drives the "Next" remediation section).
func TestPrintCronDaemonStates(t *testing.T) {
	anacronOnly := captureStdout(t, func() {
		printCron(&models.CronInfo{AnacronPresent: true, FailureScanOK: true}, output.ModeHuman)
	})
	if !strings.Contains(anacronOnly, "anacron only") {
		t.Errorf("anacron-only host should say so, got:\n%s", anacronOnly)
	}
	if !strings.Contains(anacronOnly, "Anacron") {
		t.Errorf("anacron-present should also print the Anacron: present line, got:\n%s", anacronOnly)
	}

	timers := captureStdout(t, func() {
		printCron(&models.CronInfo{SystemdTimers: 3, FailureScanOK: true}, output.ModeHuman)
	})
	if !strings.Contains(timers, "3 systemd timer(s)") {
		t.Errorf("systemd-timers-only host should report the count, got:\n%s", timers)
	}

	noScheduler := captureStdout(t, func() {
		printCron(&models.CronInfo{FailureScanOK: true}, output.ModeHuman)
	})
	if !strings.Contains(noScheduler, "not running") {
		t.Errorf("no daemon/anacron/timers should warn not running, got:\n%s", noScheduler)
	}
	if !strings.Contains(noScheduler, "Next:") || !strings.Contains(noScheduler, "systemctl enable --now crond") {
		t.Errorf("no scheduler at all should suggest enabling crond in Next steps, got:\n%s", noScheduler)
	}
}

// TestPrintCronFailuresAndQuality covers the failures list (with and without a
// human-only message line) and the quality-issues list.
func TestPrintCronFailuresAndQuality(t *testing.T) {
	failures := captureStdout(t, func() {
		printCron(&models.CronInfo{
			DaemonActive: true, FailureScanOK: true,
			Failures: []models.CronFailure{{Job: "backup.sh", Message: "exit 1", AgoMin: 15}},
		}, output.ModeHuman)
	})
	if !strings.Contains(failures, "1 job(s)") || !strings.Contains(failures, "15m ago") {
		t.Errorf("a recent failure should show its count and age, got:\n%s", failures)
	}
	if !strings.Contains(failures, "exit 1") {
		t.Errorf("human mode should show the failure message, got:\n%s", failures)
	}
	if !strings.Contains(failures, "Next:") || !strings.Contains(failures, "journalctl -u crond") {
		t.Errorf("a failure present should suggest the journalctl next-step, got:\n%s", failures)
	}

	// Plain mode must not print the message detail line (human-only).
	plainFailures := captureStdout(t, func() {
		printCron(&models.CronInfo{
			DaemonActive: true, FailureScanOK: true,
			Failures: []models.CronFailure{{Job: "backup.sh", Message: "exit 1", AgoMin: 0}},
		}, output.ModePlain)
	})
	if strings.Contains(plainFailures, "exit 1") {
		t.Errorf("plain mode must not show the failure message detail, got:\n%s", plainFailures)
	}
	if !strings.Contains(plainFailures, "?") {
		t.Errorf("an AgoMin of 0 should render as unknown age (?), got:\n%s", plainFailures)
	}

	quality := captureStdout(t, func() {
		printCron(&models.CronInfo{
			DaemonActive: true, FailureScanOK: true,
			QualityIssues: []models.CronJob{{Source: "/etc/crontab", Issues: []string{"missing PATH"}}},
		}, output.ModeHuman)
	})
	if !strings.Contains(quality, "1 file(s)") || !strings.Contains(quality, "/etc/crontab") || !strings.Contains(quality, "missing PATH") {
		t.Errorf("quality issues should list the file and its problems, got:\n%s", quality)
	}
}

// TestPrintCronAnacronJobs covers every AnacronJobs status branch: never run,
// overdue, ran recently (<48h), and ran long ago (>=48h, days formatting).
func TestPrintCronAnacronJobs(t *testing.T) {
	out := captureStdout(t, func() {
		printCron(&models.CronInfo{
			DaemonActive: true, FailureScanOK: true,
			AnacronJobs: []models.AnacronJob{
				{Name: "daily", LastRunH: -1},
				{Name: "weekly", LastRunH: 200, OverdueH: 24},
				{Name: "monthly", LastRunH: 10},
				{Name: "quarterly", LastRunH: 96},
			},
		}, output.ModeHuman)
	})
	if !strings.Contains(out, "[Anacron schedules]") {
		t.Errorf("anacron jobs present should print the schedules header, got:\n%s", out)
	}
	if !strings.Contains(out, "cron.daily") || !strings.Contains(out, "never run") {
		t.Errorf("a never-run job should say so, got:\n%s", out)
	}
	if !strings.Contains(out, "cron.weekly") || !strings.Contains(out, "overdue by 24h") {
		t.Errorf("an overdue job should show its overdue hours, got:\n%s", out)
	}
	if !strings.Contains(out, "cron.monthly") || !strings.Contains(out, "ran 10h ago") {
		t.Errorf("a recently-run job should show hours ago, got:\n%s", out)
	}
	if !strings.Contains(out, "cron.quarterly") || !strings.Contains(out, "ran 4d ago") {
		t.Errorf("a job run >=48h ago should show days ago, got:\n%s", out)
	}
}

// TestRunCron exercises runCron's real (read-only) collector wiring in
// --plain and --json mode. Same real-I/O precedent as cpu_report_test.go.
func TestRunCron(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runCron(plainCmd, nil); err != nil {
			t.Fatalf("runCron (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runCron (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runCron(jsonCmd, nil); err != nil {
			t.Fatalf("runCron (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
