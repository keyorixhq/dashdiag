//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// NOTE: withFixtureSource swaps a package-level global (activeSource) — these
// tests deliberately do NOT call t.Parallel(), matching the established
// convention in security_linux_source_test.go / nginx_linux_test.go.

func TestServicesDeepCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewServicesDeepCollector()
	if c.Name() != "ServicesDeep" {
		t.Errorf("Name() = %q, want ServicesDeep", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
}

// TestServicesDeepCollector_Collect_SystemctlAbsent guards the non-systemd
// host path: `systemctl list-units --failed` fails to run, so
// FailedUnitsQueried must be false (NOT "zero failed units").
func TestServicesDeepCollector_Collect_SystemctlAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if info.FailedUnitsQueried {
		t.Error("FailedUnitsQueried = true, want false when systemctl cannot run")
	}
	if len(info.FailedUnits) != 0 {
		t.Errorf("FailedUnits = %+v, want none", info.FailedUnits)
	}
	if !info.JournalHealthy {
		t.Error("JournalHealthy = false, want true (no journal dir seeded -> fileExists false -> stays healthy)")
	}
}

// TestServicesDeepCollector_Collect_HappyPath exercises the full pipeline: one
// real failed unit (with journal lines + exit code enrichment), a masked
// unit, a needs-reload unit, boot offenders via systemd-analyze blame, and no
// user daemon.
func TestServicesDeepCollector_Collect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			"postgresql.service loaded failed failed PostgreSQL Database\n", 0)
		b.PutCmd("journalctl", []string{"-u", "postgresql.service", "-n", "8", "--no-pager", "--output=short", "--no-hostname"},
			"May 19 10:00:00 host postgresql[123]: FATAL: could not bind IPv4 socket\n", 0)
		b.PutCmd("systemctl", []string{"show", "postgresql.service", "--property=ExecMainStatus,ActiveState,SubState"},
			"ExecMainStatus=1\nActiveState=failed\nSubState=failed\n", 0)

		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"},
			"cron.service loaded active running Cron\n", 0)
		b.PutCmd("systemctl", []string{"show", "--property=Id,NeedDaemonReload", "cron.service"},
			"Id=cron.service\nNeedDaemonReload=yes\n", 0)

		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"},
			"bluetooth.service masked masked masked\n", 0)

		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"},
			"4.210s postgresql.service\n2.000s cron.service\n", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "postgresql.service"}, "", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "cron.service"}, "", 0)

		// "degraded" (exit 1) is the normal non-zero outcome for a LIVE user
		// daemon — it doesn't contain the "Failed to connect"/"No such file"
		// disconnect text, so collectUserUnits treats it as reachable.
		b.PutCmd("systemctl", []string{"--user", "is-system-running"}, "degraded\n", 1)
		b.PutCmd("systemctl", []string{"--user", "list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			"\n", 0)
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)

	if !info.FailedUnitsQueried {
		t.Fatal("FailedUnitsQueried = false, want true")
	}
	if len(info.FailedUnits) != 1 {
		t.Fatalf("FailedUnits = %+v, want 1", info.FailedUnits)
	}
	fu := info.FailedUnits[0]
	if fu.Name != "postgresql.service" || fu.ExitCode != 1 {
		t.Errorf("FailedUnits[0] = %+v, want postgresql.service exit=1", fu)
	}
	if len(fu.LastLogLines) != 1 || fu.LastLogLines[0] != "FATAL: could not bind IPv4 socket" {
		t.Errorf("LastLogLines = %+v, want the parsed journal message", fu.LastLogLines)
	}

	if len(info.NeedsDaemonReload) != 1 || info.NeedsDaemonReload[0] != "cron.service" {
		t.Errorf("NeedsDaemonReload = %+v, want [cron.service]", info.NeedsDaemonReload)
	}

	if len(info.MaskedUnits) != 1 || info.MaskedUnits[0] != "bluetooth.service" {
		t.Errorf("MaskedUnits = %+v, want [bluetooth.service]", info.MaskedUnits)
	}

	if len(info.BootOffenders) != 2 {
		t.Fatalf("BootOffenders = %+v, want 2", info.BootOffenders)
	}
	if info.BootOffenders[0].Unit != "postgresql.service" || info.BootOffenders[0].DurationMs != 4210 {
		t.Errorf("BootOffenders[0] = %+v, want postgresql.service 4210ms", info.BootOffenders[0])
	}

	// "degraded" (exit 1, no recognizable disconnect text) reads as a LIVE
	// user daemon.
	if info.UserUnits == nil || !info.UserUnits.Available {
		t.Errorf("UserUnits = %+v, want non-nil with Available=true (degraded is not a disconnect)", info.UserUnits)
	}
}

// TestServicesDeepCollector_Collect_FailedUnitsInspectCap guards
// internal-collectors-30-04: with more failed units than
// svcFailedUnitInspectMax, the per-unit journalctl/systemctl-show
// enrichment loop must stop at the cap (so later Collect() fields —
// NeedsDaemonReload/MaskedUnits/BootOffenders/UserUnits — still get a
// ctx budget) and FailedUnitsInspectTruncated must disclose the cut-off
// rather than silently under-enriching the tail of the list.
func TestServicesDeepCollector_Collect_FailedUnitsInspectCap(t *testing.T) {
	const numUnits = svcFailedUnitInspectMax + 5 // 25 units, 5 over the cap

	withFixtureSource(t, func(b *source.Bundle) {
		var listOut strings.Builder
		for i := 0; i < numUnits; i++ {
			name := fmt.Sprintf("unit%d.service", i)
			listOut.WriteString(name + " loaded failed failed Unit\n")
			// Every unit has a valid seeded journalctl/systemctl-show response —
			// if the cap didn't stop the loop, ALL of them would get enriched.
			b.PutCmd("journalctl", []string{"-u", name, "-n", "8", "--no-pager", "--output=short", "--no-hostname"},
				"May 19 10:00:00 host unit["+fmt.Sprint(i)+"]: boom\n", 0)
			b.PutCmd("systemctl", []string{"show", name, "--property=ExecMainStatus,ActiveState,SubState"},
				"ExecMainStatus=1\nActiveState=failed\nSubState=failed\n", 0)
		}
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"}, listOut.String(), 0)
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)

	if len(info.FailedUnits) != numUnits {
		t.Fatalf("FailedUnits = %d, want %d (the cap only limits ENRICHMENT, not the list itself)", len(info.FailedUnits), numUnits)
	}
	if !info.FailedUnitsInspectTruncated {
		t.Error("FailedUnitsInspectTruncated = false, want true when the failed-unit count exceeds the cap")
	}

	enriched := 0
	for _, u := range info.FailedUnits {
		if len(u.LastLogLines) > 0 || u.ExitCode != 0 {
			enriched++
		}
	}
	if enriched != svcFailedUnitInspectMax {
		t.Errorf("enriched units = %d, want exactly %d (the cap)", enriched, svcFailedUnitInspectMax)
	}
	// The units within the cap must be the ones enriched (in order), not an
	// arbitrary subset.
	for i := 0; i < svcFailedUnitInspectMax; i++ {
		if len(info.FailedUnits[i].LastLogLines) == 0 {
			t.Errorf("FailedUnits[%d] should be enriched (within the cap), got %+v", i, info.FailedUnits[i])
		}
	}
	for i := svcFailedUnitInspectMax; i < numUnits; i++ {
		if len(info.FailedUnits[i].LastLogLines) != 0 || info.FailedUnits[i].ExitCode != 0 {
			t.Errorf("FailedUnits[%d] should NOT be enriched (beyond the cap), got %+v", i, info.FailedUnits[i])
		}
	}
}

// TestServicesDeepCollector_Collect_BenignFailedUnitsFiltered guards the
// filterBenignFailedUnits wiring: a cloud-init-noise unit must be dropped so
// `dsd services deep` agrees with the health SystemdCollector verdict.
func TestServicesDeepCollector_Collect_BenignFailedUnitsFiltered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			"casper-md5check.service loaded failed failed Casper MD5 check\n", 0)
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if len(info.FailedUnits) != 0 {
		t.Errorf("FailedUnits = %+v, want none (casper-md5check is benign noise)", info.FailedUnits)
	}
}

// TestServicesDeepCollector_Collect_NonBenignSSHDAddedBack guards the sshd@
// re-inclusion path: a per-connection sshd@ instance that failed for a REAL
// (non-255) reason must be added back even though the general sshd@ template
// is suppressed by filterBenignFailedUnits.
func TestServicesDeepCollector_Collect_NonBenignSSHDAddedBack(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			"sshd@10.0.0.1:22-10.0.0.2:5555.service loaded failed failed OpenSSH per-connection\n", 0)
		b.PutCmd("systemctl", []string{"show", "sshd@10.0.0.1:22-10.0.0.2:5555.service", "-p", "ExecMainStatus", "--value"},
			"1\n", 0)
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if len(info.FailedUnits) != 1 || info.FailedUnits[0].Name != "sshd@10.0.0.1:22-10.0.0.2:5555.service" {
		t.Errorf("FailedUnits = %+v, want the non-benign sshd@ instance added back", info.FailedUnits)
	}
}

// TestServicesDeepCollector_Collect_SSHDStatusUnverified mirrors the health
// SystemdCollector's fail-toward-suppression disclosure gap: a suppressed
// sshd@ instance whose exit status lookup itself fails must set
// SSHDStatusUnverified, not silently stay suppressed with no signal.
func TestServicesDeepCollector_Collect_SSHDStatusUnverified(t *testing.T) {
	const sshdUnit = "sshd@10.0.0.1:22-10.0.0.2:5555.service"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			sshdUnit+" loaded failed failed OpenSSH per-connection\n", 0)
		b.PutCmdNotFound("systemctl", []string{"show", sshdUnit, "-p", "ExecMainStatus", "--value"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if !info.SSHDStatusUnverified {
		t.Error("expected SSHDStatusUnverified=true when the sshd@ instance's ExecMainStatus lookup fails")
	}
	if len(info.FailedUnits) != 0 {
		t.Errorf("the unverifiable sshd@ instance must stay suppressed (fail-safe), got %+v", info.FailedUnits)
	}
}

// TestServicesDeepCollector_Collect_SSHDAliasingBug is the regression guard
// for the filterBenignFailedUnits in-place slice-filter aliasing bug: Collect()
// passes `parsed` through filterBenignFailedUnits (which used to filter via
// units[:0], aliasing parsed's backing array) and THEN reads the original
// `parsed` again to rebuild the name list for nonBenignSSHDInstances.
// Filtering in place silently corrupted parsed's later entries with
// shifted-down duplicates whenever a dropped unit sits at an earlier array
// index than a kept one — TestServicesDeepCollector_Collect_NonBenignSSHDAddedBack
// doesn't catch this because its single-unit fixture never triggers the
// overwrite. This fixture puts the blanket-suppressed sshd@ instance FIRST
// and a real kept failure second, which does.
func TestServicesDeepCollector_Collect_SSHDAliasingBug(t *testing.T) {
	const sshdUnit = "sshd@10.0.0.1:22-10.0.0.2:5555.service"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			sshdUnit+" loaded failed failed OpenSSH per-connection\n"+
				"my-real.service loaded failed failed my real service\n", 0)
		b.PutCmd("systemctl", []string{"show", sshdUnit, "-p", "ExecMainStatus", "--value"}, "1\n", 0)
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)

	foundReal, foundSSHD := false, false
	for _, u := range info.FailedUnits {
		if u.Name == "my-real.service" {
			foundReal = true
		}
		if u.Name == sshdUnit {
			foundSSHD = true
		}
	}
	if !foundReal {
		t.Errorf("expected my-real.service in FailedUnits, got %+v", info.FailedUnits)
	}
	if !foundSSHD {
		t.Errorf("expected %s (non-benign exit status) to be added back to FailedUnits, got %+v — the aliasing bug erases it from parsed before nonBenignSSHDInstances can inspect it", sshdUnit, info.FailedUnits)
	}
}

// TestServicesDeepCollector_Collect_UserUnitsAvailable guards the "user
// systemd daemon IS running" path, including per-unit journal enrichment.
func TestServicesDeepCollector_Collect_UserUnitsAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})

		b.PutCmd("systemctl", []string{"--user", "is-system-running"}, "degraded\n", 1)
		b.PutCmd("systemctl", []string{"--user", "list-units", "--failed", "--plain", "--no-legend", "--no-pager"},
			"pipewire.service loaded failed failed PipeWire\n", 0)
		b.PutCmd("journalctl", []string{"--user", "-u", "pipewire.service", "-n", "5", "--no-pager", "--output=short"},
			"May 19 10:00:00 host pipewire[456]: connection refused\n", 0)
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if info.UserUnits == nil || !info.UserUnits.Available {
		t.Fatalf("UserUnits = %+v, want Available=true", info.UserUnits)
	}
	if len(info.UserUnits.Failed) != 1 || info.UserUnits.Failed[0].Name != "pipewire.service" {
		t.Errorf("UserUnits.Failed = %+v, want [pipewire.service]", info.UserUnits.Failed)
	}
	if len(info.UserUnits.Failed[0].LastLogLines) != 1 {
		t.Errorf("LastLogLines = %+v, want 1 parsed line", info.UserUnits.Failed[0].LastLogLines)
	}
}

// TestServicesDeepCollector_Collect_JournalCorruption guards the archived-
// journal corruption wiring end-to-end: an archived (*.journal~) file whose
// journalctl --verify reports FAIL must flip JournalHealthy false.
func TestServicesDeepCollector_Collect_JournalCorruption(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-units", "--failed", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=masked", "--plain", "--no-legend", "--no-pager"})
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})

		b.PutStat("/var/log/journal", source.FileMeta{IsDir: true, Mode: 0o755})
		b.PutDir("/var/log/journal", []string{"corrupt.journal~"})
		b.PutCmd("journalctl", []string{"--verify", "--file=/var/log/journal/corrupt.journal~"},
			"File corruption detected: FAIL\n", 1)
	})
	c := NewServicesDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ServicesDeepInfo)
	if info.JournalHealthy {
		t.Error("JournalHealthy = true, want false when an archived journal fails verification")
	}
}

// ── pure parser tests ──────────────────────────────────────────────────

func TestParseFailedUnits(t *testing.T) {
	t.Parallel()
	out := "postgresql.service loaded failed failed PostgreSQL Database\n" +
		"0 loaded units listed.\n" +
		"\n"
	got := parseFailedUnits(out)
	if len(got) != 1 || got[0].Name != "postgresql.service" {
		t.Fatalf("got %+v, want 1 unit named postgresql.service", got)
	}
	if got[0].ActiveState != "failed" || got[0].SubState != "failed" {
		t.Errorf("got %+v, want ActiveState/SubState = failed/failed", got[0])
	}
}

func TestParseFailedUnits_Empty(t *testing.T) {
	t.Parallel()
	if got := parseFailedUnits(""); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

func TestParseJournalLines(t *testing.T) {
	t.Parallel()
	out := "May 19 10:00:00 host postgresql[123]: FATAL: could not bind IPv4 socket\n" +
		"a fallback line with no bracket-colon separator\n" +
		"\n"
	got := parseJournalLines(out)
	if len(got) != 2 {
		t.Fatalf("got %+v, want 2 lines", got)
	}
	if got[0] != "FATAL: could not bind IPv4 socket" {
		t.Errorf("got[0] = %q, want the stripped message", got[0])
	}
	if got[1] != "a fallback line with no bracket-colon separator" {
		t.Errorf("got[1] = %q, want the raw fallback line", got[1])
	}
}

func TestParseUnitShow(t *testing.T) {
	t.Parallel()
	unit := &models.SystemdUnit{}
	parseUnitShow("ExecMainStatus=1\nActiveState=failed\nSubState=failed\n", unit)
	if unit.ExitCode != 1 || unit.ActiveState != "failed" || unit.SubState != "failed" {
		t.Errorf("unit = %+v, want ExitCode=1 ActiveState=failed SubState=failed", unit)
	}
}

// TestParseUnitShow_DoesNotOverwriteExisting guards the "if unit.ActiveState
// == ”" guard: a pre-populated field (e.g. set from the earlier
// parseFailedUnits pass) must not be overwritten by a later parse.
func TestParseUnitShow_DoesNotOverwriteExisting(t *testing.T) {
	t.Parallel()
	unit := &models.SystemdUnit{ActiveState: "failed", SubState: "failed"}
	parseUnitShow("ExecMainStatus=0\nActiveState=inactive\nSubState=dead\n", unit)
	if unit.ActiveState != "failed" || unit.SubState != "failed" {
		t.Errorf("unit = %+v, want ActiveState/SubState preserved as failed/failed", unit)
	}
	if unit.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", unit.ExitCode)
	}
}

// NOTE: parseNeedsDaemonReload and parseMaskedUnits already have dedicated
// parser tests (TestParseNeedsDaemonReload, TestParseMaskedUnits) in
// misc_parsers_test.go — not duplicated here. This file adds Collect()-level
// coverage for them instead (see TestServicesDeepCollector_Collect_HappyPath).

func TestParseBlame(t *testing.T) {
	t.Parallel()
	out := "4.210s postgresql.service\n" +
		"2.000s dev-sda1.device\n" + // skipped: non-service unit type
		"1.500s apt-daily.service\n" + // excluded by predicate
		"1.000s cron.service\n"
	exclude := func(u string) bool { return u == "apt-daily.service" }
	got := parseBlame(out, 5, exclude)
	if len(got) != 2 {
		t.Fatalf("got %+v, want 2 offenders", got)
	}
	if got[0].Unit != "postgresql.service" || got[0].DurationMs != 4210 {
		t.Errorf("got[0] = %+v, want postgresql.service 4210ms", got[0])
	}
	if got[1].Unit != "cron.service" || got[1].DurationMs != 1000 {
		t.Errorf("got[1] = %+v, want cron.service 1000ms", got[1])
	}
}

func TestParseBlame_TopNCap(t *testing.T) {
	t.Parallel()
	out := "3.000s a.service\n2.000s b.service\n1.000s c.service\n"
	got := parseBlame(out, 2, nil)
	if len(got) != 2 {
		t.Fatalf("got %+v, want exactly 2 (topN cap)", got)
	}
}

func TestParseDurationMs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"4.210s", 4210},
		{"450ms", 450},
		{"2min 4.210s", 124210},
		{"1h 2min 3.000s", 3723000},
		{"", 0},
	}
	for _, tt := range tests {
		if got := parseDurationMs(tt.in); got != tt.want {
			t.Errorf("parseDurationMs(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// TestCollectUserUnits_ConnectionRefused guards the "no user daemon
// reachable" detection: systemctl --user is-system-running prints "Failed to
// connect to bus: No such file or directory" and exits non-zero when there's
// no user bus. collectUserUnits uses runCmdCombined (not runCmd) precisely so
// this diagnostic text — which lands on stdout/stderr, not in the Go error —
// is visible to the substring check; runCmd's cmdError only ever carries the
// exit code, never the command's own output.
func TestCollectUserUnits_ConnectionRefused(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"--user", "is-system-running"},
			"Failed to connect to bus: No such file or directory\n", 1)
	})
	got := collectUserUnits(context.Background())
	if got == nil || got.Available {
		t.Errorf("got %+v, want Available=false (no user bus reachable)", got)
	}
}

// TestCollectUserUnits_SpawnFailure guards the other non-nil-err path:
// systemctl itself is absent (spawn failure). This isn't the "no user bus"
// signal — the tool couldn't even run — so it falls through to Available=true
// rather than being misread as a disconnect.
func TestCollectUserUnits_SpawnFailure(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"--user", "is-system-running"})
		b.PutCmdNotFound("systemctl", []string{"--user", "list-units", "--failed", "--plain", "--no-legend", "--no-pager"})
	})
	got := collectUserUnits(context.Background())
	if got == nil || !got.Available {
		t.Errorf("got %+v, want Available=true (spawn failure isn't a disconnect signal)", got)
	}
}

func TestCollectNeedsDaemonReload_ListFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"})
	})
	if got := collectNeedsDaemonReload(context.Background()); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestCollectNeedsDaemonReload_NoServiceUnits(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"},
			"0 loaded units listed.\n", 0)
	})
	if got := collectNeedsDaemonReload(context.Background()); got != nil {
		t.Errorf("got %+v, want nil (no .service-suffixed unit names)", got)
	}
}

func TestCollectNeedsDaemonReload_ShowFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"},
			"cron.service loaded active running Cron\n", 0)
		b.PutCmdNotFound("systemctl", []string{"show", "--property=Id,NeedDaemonReload", "cron.service"})
	})
	if got := collectNeedsDaemonReload(context.Background()); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}
