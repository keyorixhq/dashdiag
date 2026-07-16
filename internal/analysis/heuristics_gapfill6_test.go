package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckPostBoot_UnknownStateReturnsNil covers the final `return nil` in
// checkPostBoot (heuristics_postboot.go:29) — reached when Available=true but
// State is not "unmeasurable", "absent", or "found".
func TestCheckPostBoot_UnknownStateReturnsNil(t *testing.T) {
	t.Parallel()
	if got := checkPostBoot(models.PostBootInfo{Available: true, State: "unknown"}); len(got) != 0 {
		t.Errorf("unrecognised state should yield nil, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_ReadonlyDisabled covers checkSteamOSUpdate's
// ReadonlyKnown && !ReadonlyEnabled → CRIT branch.
func TestCheckSteamOSUpdate_ReadonlyDisabled(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: false})
	if !hasInsightMsg(got, "CRIT", "rootfs is writable") {
		t.Errorf("disabled readonly must be CRIT, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_ChannelConfigMissing covers the ChannelConfigMissing → WARN branch.
func TestCheckSteamOSUpdate_ChannelConfigMissing(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{ChannelConfigMissing: true})
	if !hasInsightMsg(got, "WARN", "client.conf is missing") {
		t.Errorf("missing channel config must be WARN, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_NonStableChannel covers the Channel != "stable" → INFO branch.
func TestCheckSteamOSUpdate_NonStableChannel(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{Channel: "main"})
	if !hasInsightMsg(got, "INFO", "not stable") {
		t.Errorf("non-stable channel must be INFO, got %+v", got)
	}
}

// TestCheckSteamOSDeep_FlatpakAboveThreshold covers the FlatpakDataGB > 20 → WARN branch.
func TestCheckSteamOSDeep_FlatpakAboveThreshold(t *testing.T) {
	t.Parallel()
	got := checkSteamOSDeep(models.SteamOSInfo{FlatpakDataGB: 25})
	if !hasInsightMsg(got, "WARN", "flatpak data is") {
		t.Errorf("flatpak > 20 GB must be WARN, got %+v", got)
	}
}

// TestCheckAppArmorDenials_TruncatesAt5 covers the `i >= 5` truncation branch
// inside checkAppArmorDenials (heuristics_security.go:568-570). Passing 6 groups
// means the loop reaches i=5 and emits the "... and N more" hint before breaking.
func TestCheckAppArmorDenials_TruncatesAt5(t *testing.T) {
	t.Parallel()
	groups := make([]models.AppArmorDenial, 6)
	for i := range groups {
		groups[i] = models.AppArmorDenial{Profile: "/usr/sbin/nginx", Operation: "open", Path: "/etc/shadow", Count: i + 1}
	}
	got := checkAppArmorDenials(models.SecurityInfo{AppArmorGroups: groups})
	if len(got) == 0 {
		t.Fatal("expected a WARN insight, got none")
	}
	found := false
	for _, h := range got[0].Hints {
		if strings.Contains(h, "more group(s)") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("6 groups must produce a '... and N more group(s)' hint, got hints %v", got[0].Hints)
	}
}

// TestSecurityUpdateInsight_DefaultBranch covers the default case in
// securityUpdateInsight (heuristics_packages.go:218-222): a manager that is not
// apt/tdnf/brew and has no CriticalUpdates or ImportantUpdates breakdown.
func TestSecurityUpdateInsight_DefaultBranch(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		PackageManager:   "zypper",
		SecurityUpdates:  3,
		CriticalUpdates:  0,
		ImportantUpdates: 0,
	}
	got := securityUpdateInsight(pkg)
	if len(got) == 0 {
		t.Fatal("expected a WARN insight, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("default branch must be WARN, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "security update(s)") {
		t.Errorf("message must mention security updates, got %q", got[0].Message)
	}
}

// TestDiskGrowthHints_DefaultFSType covers the default case in diskGrowthHints
// (heuristics_storage.go:1502-1503): a filesystem type that is not ext*, xfs, or btrfs.
func TestDiskGrowthHints_DefaultFSType(t *testing.T) {
	t.Parallel()
	fs := models.FilesystemInfo{FSType: "zfs", Device: "/dev/sda1", Mount: "/data"}
	hints := diskGrowthHints(fs)
	if len(hints) == 0 {
		t.Fatal("expected at least one hint, got none")
	}
	if !strings.Contains(hints[0], "zfs") {
		t.Errorf("default hint must mention the FSType, got %q", hints[0])
	}
}
