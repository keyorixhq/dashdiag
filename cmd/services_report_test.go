package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for services.go's report renderers — plain data
// structs, no live I/O. No t.Parallel() (corrupts captureStdout's shared
// os.Stdout swap).

func TestTruncateRunes(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string should pass through unchanged, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello…" {
		t.Errorf("truncate(11 chars, 5) = %q, want hello…", got)
	}
	// Multibyte characters at the boundary must not be split.
	if got := truncate("héllo world", 2); got != "hé…" {
		t.Errorf("truncate must slice by rune not byte, got %q", got)
	}
}

func TestCapSlice(t *testing.T) {
	if got := capSlice([]string{"a", "b"}, 5); len(got) != 2 {
		t.Errorf("a shorter slice should pass through unchanged, got %v", got)
	}
	if got := capSlice([]string{"a", "b", "c", "d"}, 2); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("capSlice(4, 2) = %v, want [a b]", got)
	}
}

func TestPrintServicesEmpty(t *testing.T) {
	out := captureStdout(t, func() { printServicesEmpty(output.ModePlain) })
	if !strings.Contains(out, "No services configured") {
		t.Errorf("empty services should explain how to configure some, got:\n%s", out)
	}
}

func TestPrintServicesResults(t *testing.T) {
	results := []models.ServiceResult{
		{Name: "web", Host: "localhost", Port: 80, Reachable: true, LatencyMs: 5, StatusCode: 200},
		{Name: "db", Host: "localhost", Port: 5432, Reachable: false, Error: "connection refused"},
		{Name: "api", Host: "localhost", Port: 8080, Reachable: true, Status: "CRIT"},
	}
	out := captureStdout(t, func() { printServicesResults(results, output.ModePlain) })
	if !strings.Contains(out, "HTTP 200") {
		t.Errorf("a reachable HTTP service should show the status code, got:\n%s", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("an unreachable service should show its error, got:\n%s", out)
	}
	if !strings.Contains(out, "CRIT") {
		t.Errorf("a Status=CRIT result must render CRIT even though reachable, got:\n%s", out)
	}
}

// TestPrintSystemdHealthFailedUnitsQueried guards the not-queried vs none-failed
// distinction: a non-systemd host or a systemctl error must NOT render the same
// "none" as a genuinely clean systemd host (the false-OK this flag exists for).
func TestPrintSystemdHealthFailedUnitsQueried(t *testing.T) {
	notQueried := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: false}, output.ModePlain)
	})
	if !strings.Contains(notQueried, "not queried") {
		t.Errorf("unqueried failed-units must say so, not read as none, got:\n%s", notQueried)
	}

	none := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: true}, output.ModePlain)
	})
	if !strings.Contains(none, "none") {
		t.Errorf("a genuinely queried, clean host should say none, got:\n%s", none)
	}
	if strings.Contains(none, "not queried") {
		t.Errorf("a queried clean host must not say not queried, got:\n%s", none)
	}
}

func TestPrintSystemdHealthFailedUnitDetail(t *testing.T) {
	info := &models.ServicesDeepInfo{
		FailedUnitsQueried: true,
		FailedUnits: []models.SystemdUnit{
			{Name: "nginx.service", ExitCode: 1, SubState: "failed", LastLogLines: []string{"bind: address already in use"}},
		},
		JournalHealthy: true,
	}
	out := captureStdout(t, func() { printSystemdHealth(info, output.ModePlain) })
	if !strings.Contains(out, "nginx.service") || !strings.Contains(out, "exit 1") {
		t.Errorf("a failed unit should show its name and exit code, got:\n%s", out)
	}
	if !strings.Contains(out, "bind: address already in use") {
		t.Errorf("the last log line should be included, got:\n%s", out)
	}
}

func TestPrintSystemdHealthJournalCorruption(t *testing.T) {
	out := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: false, JournalLastValid: "2026-01-01"}, output.ModePlain)
	})
	if !strings.Contains(out, "corruption detected") {
		t.Errorf("an unhealthy journal should say corruption detected, got:\n%s", out)
	}
	if !strings.Contains(out, "2026-01-01") {
		t.Errorf("the last valid timestamp should be shown, got:\n%s", out)
	}
}

func TestPrintSystemdHealthMaskedUnitsCapped(t *testing.T) {
	out := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{
			FailedUnitsQueried: true, JournalHealthy: true,
			MaskedUnits: []string{"a.service", "b.service", "c.service", "d.service"},
		}, output.ModePlain)
	})
	if !strings.Contains(out, "4:") {
		t.Errorf("the total masked count should be shown even when the list is capped, got:\n%s", out)
	}
	if strings.Contains(out, "d.service") {
		t.Errorf("the masked unit list should be capped to 3 entries, got:\n%s", out)
	}
}

func TestPrintSystemdHealthUserUnits(t *testing.T) {
	noDaemon := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: true,
			UserUnits: &models.UserUnitsInfo{Available: false}}, output.ModePlain)
	})
	if !strings.Contains(noDaemon, "no user systemd daemon running") {
		t.Errorf("an unavailable user daemon should say so, got:\n%s", noDaemon)
	}

	failed := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: true,
			UserUnits: &models.UserUnitsInfo{Available: true, Failed: []models.SystemdUnit{{Name: "pulseaudio.service"}}}}, output.ModePlain)
	})
	if !strings.Contains(failed, "1 failed") || !strings.Contains(failed, "pulseaudio.service") {
		t.Errorf("a failed user unit should be named, got:\n%s", failed)
	}
}

// TestPrintSystemdHealthDaemonReload covers the NeedsDaemonReload branch
// (both the printLine and, in ModeHuman, the extra fix-hint line).
func TestPrintSystemdHealthDaemonReload(t *testing.T) {
	info := &models.ServicesDeepInfo{
		FailedUnitsQueried: true, JournalHealthy: true,
		NeedsDaemonReload: []string{"nginx.service", "postgresql.service"},
	}
	plain := captureStdout(t, func() { printSystemdHealth(info, output.ModePlain) })
	if !strings.Contains(plain, "nginx.service, postgresql.service") {
		t.Errorf("units needing reload should be listed, got:\n%s", plain)
	}
	if strings.Contains(plain, "daemon-reload") {
		t.Errorf("plain mode should not print the human-only fix hint, got:\n%s", plain)
	}

	human := captureStdout(t, func() { printSystemdHealth(info, output.ModeHuman) })
	if !strings.Contains(human, "systemctl daemon-reload") {
		t.Errorf("ModeHuman should print the daemon-reload fix hint, got:\n%s", human)
	}
}

// TestPrintSystemdHealthJournalCorruption_Human covers the ModeHuman-only
// journalctl fix-hint lines under journal corruption.
func TestPrintSystemdHealthJournalCorruption_Human(t *testing.T) {
	out := captureStdout(t, func() {
		printSystemdHealth(&models.ServicesDeepInfo{FailedUnitsQueried: true, JournalHealthy: false}, output.ModeHuman)
	})
	if !strings.Contains(out, "journalctl --verify") || !strings.Contains(out, "journalctl --rotate") {
		t.Errorf("ModeHuman should print the journal fix hints, got:\n%s", out)
	}
}

// TestPrintSystemdHealthBootOffenders covers the BootOffenders block,
// including its ModeHuman-only section header.
func TestPrintSystemdHealthBootOffenders(t *testing.T) {
	info := &models.ServicesDeepInfo{
		FailedUnitsQueried: true, JournalHealthy: true,
		BootOffenders: []models.BootOffender{{Unit: "cloud-init.service", DurationMs: 4200}},
	}
	human := captureStdout(t, func() { printSystemdHealth(info, output.ModeHuman) })
	if !strings.Contains(human, "Boot top offenders") || !strings.Contains(human, "cloud-init.service") {
		t.Errorf("ModeHuman should show the boot-offenders section header and unit, got:\n%s", human)
	}
	if !strings.Contains(human, "4200ms") {
		t.Errorf("boot offender duration should be shown, got:\n%s", human)
	}

	plain := captureStdout(t, func() { printSystemdHealth(info, output.ModePlain) })
	if strings.Contains(plain, "Boot top offenders") {
		t.Errorf("plain mode should not print the human-only section header, got:\n%s", plain)
	}
	if !strings.Contains(plain, "cloud-init.service") {
		t.Errorf("plain mode should still list the offender itself, got:\n%s", plain)
	}
}

// TestPrintSystemdHealthNextSteps covers the ModeHuman-only "Next:" block
// printed after failed units.
func TestPrintSystemdHealthNextSteps(t *testing.T) {
	info := &models.ServicesDeepInfo{
		FailedUnitsQueried: true, JournalHealthy: true,
		FailedUnits: []models.SystemdUnit{{Name: "nginx.service", SubState: "failed"}},
	}
	human := captureStdout(t, func() { printSystemdHealth(info, output.ModeHuman) })
	if !strings.Contains(human, "Next:") || !strings.Contains(human, "systemctl status nginx.service") ||
		!strings.Contains(human, "journalctl -u nginx.service") {
		t.Errorf("ModeHuman should print the Next steps block for failed units, got:\n%s", human)
	}

	plain := captureStdout(t, func() { printSystemdHealth(info, output.ModePlain) })
	if strings.Contains(plain, "Next:") {
		t.Errorf("plain mode should not print the human-only Next steps block, got:\n%s", plain)
	}
}

// TestPrintServicesDeepDispatch_Human covers printServicesDeep's ModeHuman-only
// section headers ("Services deep", "[Port health]", "[Systemd health]").
func TestPrintServicesDeepDispatch_Human(t *testing.T) {
	info := &models.ServicesDeepInfo{
		PortResults:        []models.ServiceResult{{Name: "web", Host: "localhost", Port: 80, Reachable: true}},
		FailedUnitsQueried: true, JournalHealthy: true,
	}
	out := captureStdout(t, func() { printServicesDeep(info, output.ModeHuman) })
	if !strings.Contains(out, "Services deep") || !strings.Contains(out, "[Port health]") || !strings.Contains(out, "[Systemd health]") {
		t.Errorf("ModeHuman should print all section headers, got:\n%s", out)
	}
}

func TestPrintServicesDeepDispatch(t *testing.T) {
	info := &models.ServicesDeepInfo{
		PortResults:        []models.ServiceResult{{Name: "web", Host: "localhost", Port: 80, Reachable: true}},
		FailedUnitsQueried: true, JournalHealthy: true,
	}
	out := captureStdout(t, func() { printServicesDeep(info, output.ModePlain) })
	if !strings.Contains(out, "web") {
		t.Errorf("port results should be rendered, got:\n%s", out)
	}
	if !strings.Contains(out, "none") {
		t.Errorf("systemd health should also be rendered (failed units: none), got:\n%s", out)
	}
}

// TestRunServices exercises runServices's real (read-only) collector wiring
// in --plain and --json mode. No services are configured on this test host,
// so both should render the empty-services help without error — the same
// real-I/O precedent as cpu_report_test.go / hardware_test.go.
func TestRunServices(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runServices(plainCmd, nil); err != nil {
			t.Fatalf("runServices (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "No services configured") {
		t.Errorf("no configured services should show the setup help, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runServices(jsonCmd, nil); err != nil {
			t.Fatalf("runServices (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}

// TestRunServicesDeep exercises runServicesDeep's real (read-only) systemd
// collector wiring. It reads flags off cmd.Parent() (it's wired as `dsd
// services deep`), so the test constructs a parent/child cobra relationship.
func TestRunServicesDeep(t *testing.T) {
	parent := newBareCloudCmd()
	child := &cobra.Command{}
	parent.AddCommand(child)
	child.SetContext(context.Background())
	_ = parent.Flags().Set("plain", "true")

	out := captureStdout(t, func() {
		if err := runServicesDeep(child, nil); err != nil {
			t.Fatalf("runServicesDeep (plain): %v", err)
		}
	})
	if !strings.Contains(out, "Failed units") {
		t.Errorf("plain mode should render the systemd-health section, got: %q", out)
	}

	jsonParent := newBareCloudCmd()
	jsonChild := &cobra.Command{}
	jsonParent.AddCommand(jsonChild)
	jsonChild.SetContext(context.Background())
	_ = jsonParent.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runServicesDeep(jsonChild, nil); err != nil {
			t.Fatalf("runServicesDeep (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
