package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// On an ostree host (Fedora CoreOS/Silverblue) `/` stays writable but the
// physical root `/sysroot`, `/boot`, and the `/usr` bind are mounted read-only
// BY DESIGN. The old suppression only covered `/`, so those false-WARNed on
// Fedora CoreOS (2026-06-29). They must NOT WARN on an immutable host — but a
// genuine read-only remount of a DATA mount (/var, /home) still must.
func TestCheckDiskOstreeInfraMountsSuppressed(t *testing.T) {
	roInfra := func(mount, dev, fstype string) models.FilesystemInfo {
		return models.FilesystemInfo{
			Mount: mount, Device: dev, FSType: fstype, ReadOnly: true,
			TotalGB: 10, UsedGB: 5, UsedPct: 50,
		}
	}

	immutable := models.DiskInfo{
		ImmutableRootFS: true,
		Filesystems: []models.FilesystemInfo{
			roInfra("/sysroot", "/dev/sda4", "xfs"),
			roInfra("/boot", "/dev/sda3", "ext4"),
			roInfra("/usr", "/dev/sda4", "xfs"),
		},
	}
	if hasInsightMsg(checkDisk(immutable, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("ostree /sysroot,/boot,/usr are ro by design — must NOT WARN")
	}

	// A writable data mount going ro IS an error remount, even on an immutable host.
	dataRO := models.DiskInfo{
		ImmutableRootFS: true,
		Filesystems:     []models.FilesystemInfo{roInfra("/var", "/dev/sda5", "xfs")},
	}
	if !hasInsightMsg(checkDisk(dataRO, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("a read-only /var data mount must WARN even on an immutable host")
	}

	// Regression guard: on a NON-immutable host, /boot ro is still a real error.
	normalBoot := models.DiskInfo{
		ImmutableRootFS: false,
		Filesystems:     []models.FilesystemInfo{roInfra("/boot", "/dev/sda3", "ext4")},
	}
	if !hasInsightMsg(checkDisk(normalBoot, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("read-only /boot on a normal (non-immutable) host must WARN")
	}
}
