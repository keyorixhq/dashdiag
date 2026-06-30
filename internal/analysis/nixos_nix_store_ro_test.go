package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NixOS bind-mounts /nix/store read-only off the read-write root for immutability.
// dsd false-WARNed "mounted READ-ONLY — the kernel likely remounted it after an I/O
// error" on /nix/store (found live on NixOS 25.05, 2026-06-30). Because a kernel
// I/O-error remount flips the WHOLE block device to ro, a ro mount of a device that
// is ALSO mounted rw elsewhere can only be an intentional ro bind — not an error.
// Real bytes: both / and /nix/store sit on the same uuid device, / rw and store ro.
func TestCheckDiskNixStoreROBindSuppressed(t *testing.T) {
	const dev = "/dev/disk/by-uuid/407cadeb-12f9-40ff-a157-b5d94e7d8899"
	nixos := models.DiskInfo{
		ImmutableRootFS: false, // NixOS is NOT detected as an immutable-infra distro
		Filesystems: []models.FilesystemInfo{
			{Mount: "/", Device: dev, FSType: "ext4", ReadOnly: false, TotalGB: 16, UsedGB: 2, UsedPct: 17},
			{Mount: "/nix/store", Device: dev, FSType: "ext4", ReadOnly: true, TotalGB: 16, UsedGB: 2, UsedPct: 17},
		},
	}
	if hasInsightMsg(checkDisk(nixos, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("/nix/store ro bind off the rw root must NOT WARN — it is intentional, not an I/O-error remount")
	}

	// Regression guard: a ro mount whose device is NOT mounted rw anywhere is a
	// genuine error remount and must still WARN.
	errorRemount := models.DiskInfo{
		Filesystems: []models.FilesystemInfo{
			{Mount: "/", Device: "/dev/sda1", FSType: "ext4", ReadOnly: false, TotalGB: 16, UsedGB: 2, UsedPct: 17},
			{Mount: "/var", Device: "/dev/sdb1", FSType: "ext4", ReadOnly: true, TotalGB: 16, UsedGB: 2, UsedPct: 17},
		},
	}
	if !hasInsightMsg(checkDisk(errorRemount, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("a ro /var on its own device (no rw mount of it) is an error remount and must WARN")
	}
}
