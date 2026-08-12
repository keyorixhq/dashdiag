//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── collectBootTimes ─────────────────────────────────────────────────────────

func TestCollectBootTimes_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.234s (kernel) + 5.678s (userspace) = 6.912s\n", 0)
		// parseBlameSlowUnits filters out sub-5.0s entries (the 1.200s
		// some-fast.service line), so only the two >=5.0s entries surface as
		// slow units.
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"},
			"         8.500s NetworkManager-wait-online.service\n"+
				"         5.200s systemd-udev-settle.service\n"+
				"         1.200s some-fast.service\n", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "NetworkManager-wait-online.service"}, "", 0)
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "systemd-udev-settle.service"}, "", 0)
	})
	units, total := collectBootTimes(context.Background())
	if total != 6.912 {
		t.Errorf("total boot time = %v, want 6.912", total)
	}
	if len(units) != 2 {
		t.Fatalf("expected 2 slow units, got %d: %+v", len(units), units)
	}
}

// TestCollectBootTimes_TimeFails guards the first error return: a failed
// `systemd-analyze time` must short-circuit to (nil, 0) without attempting
// the blame query at all.
func TestCollectBootTimes_TimeFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemd-analyze", []string{"time"})
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"}, "should not be called", 0)
	})
	units, total := collectBootTimes(context.Background())
	if units != nil || total != 0 {
		t.Errorf("collectBootTimes = (%+v, %v), want (nil, 0) when systemd-analyze time fails", units, total)
	}
}

// TestCollectBootTimes_BlameFailsStillReturnsTotal guards the second error
// return: a failed blame query must still surface the total boot time already
// parsed, just with a nil slow-unit list — not discard everything.
func TestCollectBootTimes_BlameFailsStillReturnsTotal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.000s (kernel) + 2.000s (userspace) = 3.000s\n", 0)
		b.PutCmdNotFound("systemd-analyze", []string{"blame", "--no-pager"})
	})
	units, total := collectBootTimes(context.Background())
	if total != 3.0 {
		t.Errorf("total = %v, want 3.0 (parsed before the blame failure)", total)
	}
	if units != nil {
		t.Errorf("units = %+v, want nil when blame fails", units)
	}
}

// ── timerTriggeredExcluder ───────────────────────────────────────────────────

func TestTimerTriggeredExcluder_TimerTriggered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "apt-daily-upgrade.service"},
			"TriggeredBy=apt-daily-upgrade.timer\n", 0)
	})
	excluder := timerTriggeredExcluder(context.Background())
	if !excluder("apt-daily-upgrade.service") {
		t.Error("expected true for a unit triggered by a .timer")
	}
}

func TestTimerTriggeredExcluder_NotTimerTriggered(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "sshd.service"}, "", 0)
	})
	excluder := timerTriggeredExcluder(context.Background())
	if excluder("sshd.service") {
		t.Error("expected false for a unit with no TriggeredBy timer")
	}
}

// TestTimerTriggeredExcluder_QueryFailsOpen guards the fail-open contract: a
// systemctl query error must return false (unit kept, not hidden) so a
// genuine boot offender is never silently excluded just because systemctl
// couldn't be queried.
func TestTimerTriggeredExcluder_QueryFailsOpen(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "-p", "TriggeredBy", "--value", "mystery.service"})
	})
	excluder := timerTriggeredExcluder(context.Background())
	if excluder("mystery.service") {
		t.Error("expected false (fail open, unit kept) when systemctl can't be queried")
	}
}

// ── listUnits ────────────────────────────────────────────────────────────────

// TestListUnits_Success guards the happy path: systemctl output is parsed via
// parseUnitList into the unit-name slice.
func TestListUnits_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"nginx.service loaded failed failed nginx\n", 0)
	})
	units, err := listUnits(context.Background(), "failed")
	if err != nil {
		t.Fatalf("listUnits: unexpected error: %v", err)
	}
	if len(units) != 1 || units[0] != "nginx.service" {
		t.Errorf("units = %v, want [nginx.service]", units)
	}
}

// TestListUnits_CommandFails guards the error-propagation contract: listUnits
// must surface the systemctl error rather than collapsing it into an empty,
// confident "no units" list — the caller (Collect) relies on this to set
// FailedUnitsUnknown honestly instead of reading a timeout as zero failures.
func TestListUnits_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"})
	})
	units, err := listUnits(context.Background(), "failed")
	if err == nil {
		t.Fatal("expected an error when systemctl list-units fails, got nil")
	}
	if units != nil {
		t.Errorf("units = %v, want nil on error", units)
	}
}

// ── sysupdateUnconfigured ────────────────────────────────────────────────────

// TestSysupdateUnconfigured guards both outcomes directly (rather than only
// via the dropSysupdateIf/filterBenignFailedUnits callers): no *.transfer
// files anywhere reports unconfigured=true, and a transfer file in EITHER
// candidate directory reports unconfigured=false.
func TestSysupdateUnconfigured(t *testing.T) {
	t.Run("no transfer files in either directory", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/sysupdate.d/*.transfer", nil)
			b.PutGlob("/usr/lib/sysupdate.d/*.transfer", nil)
		})
		if !sysupdateUnconfigured() {
			t.Error("expected true when no *.transfer files exist in either directory")
		}
	})

	t.Run("transfer file present in /etc", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/sysupdate.d/*.transfer", []string{"/etc/sysupdate.d/example.transfer"})
		})
		if sysupdateUnconfigured() {
			t.Error("expected false when a transfer file exists in /etc/sysupdate.d")
		}
	})

	t.Run("transfer file present only in /usr/lib", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/sysupdate.d/*.transfer", nil)
			b.PutGlob("/usr/lib/sysupdate.d/*.transfer", []string{"/usr/lib/sysupdate.d/example.transfer"})
		})
		if sysupdateUnconfigured() {
			t.Error("expected false when a transfer file exists in /usr/lib/sysupdate.d")
		}
	})
}

// ── Collect (happy path) ─────────────────────────────────────────────────────

// TestSystemdCollect_HappyPath guards the full successful Collect assembly:
// systemd present, a real failed unit surfaces, cloud-init/sshd@ noise is
// suppressed, and the boot-time/system-state fields are populated from their
// respective systemd-analyze/systemctl outputs.
func TestSystemdCollect_HappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/private", source.FileMeta{})
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"my-real.service loaded failed failed my real service\n"+
				"console-getty.service loaded failed failed noise\n", 0)
		b.PutGlob("/etc/sysupdate.d/*.transfer", nil)
		b.PutGlob("/usr/lib/sysupdate.d/*.transfer", nil)
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.000s (kernel) + 2.000s (userspace) = 3.000s\n", 0)
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"}, "", 0)
		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"}, "", 0)
		b.PutCmd("systemctl", []string{"is-system-running"}, "running\n", 0)
	})

	c := &SystemdCollector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := res.(*models.SystemdInfo)
	if !ok {
		t.Fatalf("expected *models.SystemdInfo, got %T", res)
	}
	if !info.Available {
		t.Fatal("expected Available=true")
	}
	if info.FailedUnitsUnknown {
		t.Error("expected FailedUnitsUnknown=false on a successful listUnits call")
	}
	if len(info.FailedUnits) != 1 || info.FailedUnits[0] != "my-real.service" {
		t.Errorf("FailedUnits = %v, want only my-real.service (console-getty noise suppressed)", info.FailedUnits)
	}
	if info.TotalBootSec != 3.0 {
		t.Errorf("TotalBootSec = %v, want 3.0", info.TotalBootSec)
	}
	if info.SystemState != "running" {
		t.Errorf("SystemState = %q, want running", info.SystemState)
	}
}

// TestSystemdCollect_SSHDAliasingBug is the regression guard for the
// filterUnits/filterBenignFailedUnits in-place slice-filter aliasing bug:
// Collect() passes failedRaw through suppressCloudInitNoise (which used to
// filter via units[:0], aliasing failedRaw's backing array) and THEN reads
// the original failedRaw again for nonBenignSSHDInstances. Filtering in
// place silently corrupted failedRaw's later entries with shifted-down
// duplicates, erasing the blanket-suppressed sshd@ unit nonBenignSSHDInstances
// needed to find — so a genuinely-failed sshd@ connection (non-255/0 exit)
// never got added back, silently vanishing from the verdict.
func TestSystemdCollect_SSHDAliasingBug(t *testing.T) {
	const sshdUnit = "sshd@10.0.0.1:22-10.0.0.2:33.service"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/private", source.FileMeta{})
		// sshd@ instance FIRST (blanket-suppressed by cloudInitUnits), then a
		// real kept failure — this ordering is what triggers the aliasing
		// corruption (the dropped entry's array slot gets overwritten by the
		// kept entry shifting down).
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			sshdUnit+" loaded failed failed noise\n"+
				"my-real.service loaded failed failed my real service\n", 0)
		// A non-benign exit status (not 0/255/"") — this sshd@ instance failed
		// for a REAL reason and must be added back to FailedUnits.
		b.PutCmd("systemctl", []string{"show", sshdUnit, "-p", "ExecMainStatus", "--value"}, "1\n", 0)
		b.PutGlob("/etc/sysupdate.d/*.transfer", nil)
		b.PutGlob("/usr/lib/sysupdate.d/*.transfer", nil)
		b.PutCmd("systemd-analyze", []string{"time"},
			"Startup finished in 1.000s (kernel) + 2.000s (userspace) = 3.000s\n", 0)
		b.PutCmd("systemd-analyze", []string{"blame", "--no-pager"}, "", 0)
		b.PutCmd("systemctl", []string{"list-units", "--type=service", "--state=loaded", "--plain", "--no-legend", "--no-pager"}, "", 0)
		b.PutCmd("systemctl", []string{"is-system-running"}, "running\n", 0)
	})

	c := &SystemdCollector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.SystemdInfo)

	foundReal, foundSSHD := false, false
	for _, u := range info.FailedUnits {
		if u == "my-real.service" {
			foundReal = true
		}
		if u == sshdUnit {
			foundSSHD = true
		}
	}
	if !foundReal {
		t.Errorf("expected my-real.service in FailedUnits, got %v", info.FailedUnits)
	}
	if !foundSSHD {
		t.Errorf("expected %s (non-benign exit status) to be added back to FailedUnits, got %v — the aliasing bug erases it from failedRaw before nonBenignSSHDInstances can inspect it", sshdUnit, info.FailedUnits)
	}
}

// TestSystemdCollect_NotPresent guards the early gate: when neither
// /run/systemd/private nor /run/systemd/system exists (non-systemd init —
// e.g. Alpine/OpenRC, a minimal container), Collect must short-circuit to
// Available=false without attempting any systemctl/systemd-analyze query.
func TestSystemdCollect_NotPresent(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // neither marker file seeded

	c := &SystemdCollector{}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := res.(*models.SystemdInfo)
	if !ok {
		t.Fatalf("expected *models.SystemdInfo, got %T", res)
	}
	if info.Available {
		t.Error("expected Available=false when systemd is not present")
	}
	if len(info.FailedUnits) != 0 || info.TotalBootSec != 0 {
		t.Errorf("expected a zero-value SystemdInfo, got %+v", info)
	}
}
