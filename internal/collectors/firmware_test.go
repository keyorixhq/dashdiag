//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestFirmwareCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewFirmwareCollector()
	if c.Name() != "Firmware" {
		t.Errorf("Name() = %q, want Firmware", c.Name())
	}
	if c.Timeout() != 30*time.Second {
		t.Errorf("Timeout() = %v, want 30s", c.Timeout())
	}
}

// TestFirmwareCollect_FwupdmgrNotInstalled guards the simplest gate: fwupdmgr
// absent from PATH must yield an explicit unavailable status, not an error.
func TestFirmwareCollect_FwupdmgrNotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("fwupdmgr", []string{"--version"})
	})
	c := NewFirmwareCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info, ok := res.(*models.FirmwareInfo)
	if !ok {
		t.Fatalf("expected *models.FirmwareInfo, got %T", res)
	}
	if info.Available {
		t.Error("Available must be false when fwupdmgr is not installed")
	}
	if info.Status != "unavailable" || info.StatusReason != "fwupd not installed" {
		t.Errorf("Status/StatusReason = %q/%q, want unavailable/fwupd not installed", info.Status, info.StatusReason)
	}
}

// TestFirmwareCollect_NoUpgradesAvailable guards the exit-code-based "clean"
// branch: fwupdmgr get-upgrades exits non-zero with no upgrades pending, and
// the collector must still resolve to Status=OK, not surface an error.
//
// NOTE (potential production bug, not fixed here): runCmd (collector.go)
// discards stdout when the command exits non-zero — it returns "" on any
// non-zero exit (see runCmd's `if res.ExitCode != 0 { return "", &cmdError{} }`).
// firmware.go's Collect (line ~36-44) calls `out, err := runCmd(ctx, "fwupdmgr",
// "get-upgrades", "--json")` and then, in the err != nil branch, checks
// `strings.Contains(out, "Nothing to do")` etc. Since runCmd always returns ""
// for out whenever err != nil, that substring check can NEVER match — the
// "Nothing to do" / "no upgrades" / "No upgrades" branch is dead code, and
// every non-zero-exit invocation instead falls through to the generic
// "fwupdmgr get-upgrades failed" StatusReason. This test pins the OBSERVED
// (buggy) behavior — reaching the generic failure reason instead of Status=OK
// — as a regression net around the current runtime behavior; it is not
// asserting this is correct. Likely fix: firmware.go should use runCmdOutput
// instead of runCmd so stdout survives a non-zero exit.
func TestFirmwareCollect_NoUpgradesAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("fwupdmgr", []string{"--version"}, "fwupdmgr version 1.9.10\n", 0)
		b.PutCmd("fwupdmgr", []string{"get-upgrades", "--json"}, "Nothing to do.\n", 2)
	})
	c := NewFirmwareCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.FirmwareInfo) //nolint:errcheck // asserted by identity test
	if !info.Available {
		t.Error("Available must be true once fwupdmgr --version succeeds")
	}
	// Documents the current (buggy) behavior: runCmd drops stdout on non-zero
	// exit, so the "Nothing to do" substring check never sees it and Status
	// never reaches "OK" via that branch.
	if info.Status == "OK" {
		t.Error("BUG-CONFIRMATION-INVERTED: if this now reports OK, the runCmd->runCmdOutput " +
			"fix landed — update this test to assert the corrected Status=OK behavior " +
			"and drop this comment")
	}
	if info.StatusReason != "fwupdmgr get-upgrades failed" {
		t.Errorf("StatusReason = %q, want the generic failure reason (see bug note above)", info.StatusReason)
	}
}

// TestFirmwareCollect_UpgradesJSONParseError guards the malformed-output path:
// a 0-exit get-upgrades call with unparsable JSON must set StatusReason
// without erroring the collector.
func TestFirmwareCollect_UpgradesJSONParseError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("fwupdmgr", []string{"--version"}, "fwupdmgr version 1.9.10\n", 0)
		b.PutCmd("fwupdmgr", []string{"get-upgrades", "--json"}, "not valid json", 0)
	})
	c := NewFirmwareCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.FirmwareInfo) //nolint:errcheck // asserted by identity test
	if info.StatusReason != "failed to parse fwupdmgr output" {
		t.Errorf("StatusReason = %q, want failed to parse fwupdmgr output", info.StatusReason)
	}
}

// TestFirmwareCollect_UpgradesFound guards the happy path: parses devices,
// classifies security-relevant releases (urgency, security category, and the
// dbx/secure-boot name/summary heuristics), and tallies counts.
func TestFirmwareCollect_UpgradesFound(t *testing.T) {
	upgradesJSON := `{
		"Devices": [
			{
				"Name": "UEFI dbx",
				"Summary": "UEFI Secure Boot revocation list",
				"Version": "1",
				"Flags": ["needs-reboot"],
				"Releases": [{"Version": "2", "Summary": "dbx update", "Urgency": "low", "Categories": []}]
			},
			{
				"Name": "System Firmware",
				"Summary": "BIOS update",
				"Version": "1.2.0",
				"Flags": [],
				"Releases": [{"Version": "1.3.0", "Summary": "bugfix", "Urgency": "critical", "Categories": ["X-Device"]}]
			},
			{
				"Name": "Touchpad Firmware",
				"Summary": "minor fix",
				"Version": "5",
				"Flags": [],
				"Releases": [{"Version": "6", "Summary": "minor fix", "Urgency": "low", "Categories": ["X-Security"]}]
			},
			{
				"Name": "Benign Device",
				"Summary": "cosmetic",
				"Version": "1",
				"Flags": [],
				"Releases": [{"Version": "2", "Summary": "cosmetic", "Urgency": "low", "Categories": []}]
			}
		]
	}`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("fwupdmgr", []string{"--version"}, "fwupdmgr version 1.9.10\n", 0)
		b.PutCmd("fwupdmgr", []string{"get-upgrades", "--json"}, upgradesJSON, 0)
	})
	c := NewFirmwareCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.FirmwareInfo) //nolint:errcheck // asserted by identity test
	if info.UpgradeCount != 4 {
		t.Fatalf("UpgradeCount = %d, want 4", info.UpgradeCount)
	}
	// dbx-by-name, critical-urgency, and X-Security category are each security-relevant;
	// the cosmetic device is not.
	if info.SecurityCount != 3 {
		t.Errorf("SecurityCount = %d, want 3, got upgrades %+v", info.SecurityCount, info.Upgrades)
	}
	if len(info.Upgrades) != 4 {
		t.Fatalf("len(Upgrades) = %d, want 4", len(info.Upgrades))
	}
	dbx := info.Upgrades[0]
	if !dbx.NeedsReboot || !dbx.SecurityFix || dbx.NewVer != "2" || dbx.CurrentVer != "1" {
		t.Errorf("dbx upgrade = %+v, want NeedsReboot/SecurityFix true, NewVer=2 CurrentVer=1", dbx)
	}
	bios := info.Upgrades[1]
	if !bios.SecurityFix {
		t.Errorf("BIOS upgrade with critical urgency must be flagged SecurityFix, got %+v", bios)
	}
	touchpad := info.Upgrades[2]
	if !touchpad.SecurityFix {
		t.Errorf("touchpad upgrade with X-Security category must be flagged SecurityFix, got %+v", touchpad)
	}
	benign := info.Upgrades[3]
	if benign.SecurityFix {
		t.Errorf("cosmetic upgrade must NOT be flagged SecurityFix, got %+v", benign)
	}
}
