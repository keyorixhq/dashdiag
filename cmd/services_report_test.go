package cmd

import (
	"strings"
	"testing"

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
