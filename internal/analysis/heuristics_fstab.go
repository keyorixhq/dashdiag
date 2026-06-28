package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkFstab flags /etc/fstab entries whose UUID=/PARTUUID= reference matches no
// present device — a mount that will fail at boot. A drift on a boot-critical mount
// (/ or /boot*) drops the host to an emergency shell → CRIT; any other drift → WARN
// (the mount silently fails). The classic cause is a cloned VM or replaced disk
// changing the filesystem id while fstab still names the old one.
func checkFstab(info models.FstabInfo) []models.Insight {
	if !info.Checked || len(info.Drifts) == 0 {
		return nil
	}
	out := make([]models.Insight, 0, len(info.Drifts))
	for _, d := range info.Drifts {
		level, effect := "WARN", "the device is absent, so this mount will fail at boot"
		if d.BootMount {
			level = "CRIT"
			effect = "this is a boot-critical mount — the host will fail to boot and drop to an emergency shell"
		}
		out = append(out, insight(level, "Fstab",
			fmt.Sprintf("/etc/fstab references %s for %s but no present device has that id — %s", d.Spec, d.MountPoint, effect),
			[]string{
				"common cause: the VM was cloned or the disk was replaced/moved, changing the filesystem UUID",
				"to find the current id: lsblk -o NAME,UUID,PARTUUID,MOUNTPOINT ; blkid",
				fmt.Sprintf("to fix: update the %s entry in /etc/fstab to the current id (or add 'nofail' if the mount is optional)", d.MountPoint),
			},
		))
	}
	return out
}
