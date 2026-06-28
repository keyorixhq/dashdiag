package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkRootFS turns an unexpected read-only root into a CRIT. The collector only
// emits RootFSInfo on the fault (ro on a writable fs, fstab intends rw, no immutable
// mechanism), so this is unambiguous: an errors=remount-ro trip or failed fsck has
// forced the root read-only — the host can't write to disk and is degraded.
func checkRootFS(info models.RootFSInfo) []models.Insight {
	if !info.UnexpectedReadOnly {
		return nil
	}
	return []models.Insight{insight("CRIT", "Root FS",
		fmt.Sprintf("root filesystem (%s) is mounted READ-ONLY but fstab intends read-write — an errors=remount-ro trip or failed fsck has forced it ro; the host cannot write to disk", info.RootFstype),
		[]string{
			"to find the cause: journalctl -b -p err ; dmesg | grep -iE 'I/O error|ext4|xfs|btrfs|remount'",
			"to confirm: mount | grep ' / '",
			"common cause: a disk/filesystem error tripped errors=remount-ro, or a boot-time fsck failed",
			"after fixing the cause, remount rw: mount -o remount,rw /   (or fsck the root device from rescue)",
		},
	)}
}
