//go:build linux

package collectors

import (
	"testing"
)

// Verbatim /etc/fstab from the pve01 host (Debian 13 + PVE): LVM device paths
// (/dev/pve/root, /dev/pve/swap), a real UUID= for /boot/efi (vfat, UPPERCASE id),
// a raw /dev/sdb2 device path, and the proc pseudo-fs. Only the UUID= line is a
// verifiable id reference; everything else must be skipped.
const fstabPVEHost = `# <file system> <mount point> <type> <options> <dump> <pass>
/dev/pve/root / ext4 errors=remount-ro 0 1
UUID=F130-EB02 /boot/efi vfat defaults 0 1
/dev/pve/swap none swap sw 0 0
proc /proc proc defaults 0 0
/dev/sdb2 /mnt/data ext4 defaults 0 2`

func TestParseFstabDrifts_RealHostClean(t *testing.T) {
	// The vfat id is uppercase in fstab but lowercased in the by-uuid set — the
	// match must be case-insensitive (else a false drift on /boot/efi).
	byUUID := map[string]bool{"f130-eb02": true, "fe2bdd06-80bf-4514-8168-f14c209bc708": true}
	byPart := map[string]bool{}
	if d := parseFstabDrifts(fstabPVEHost, byUUID, byPart); len(d) != 0 {
		t.Fatalf("clean host fstab must report no drift, got %+v", d)
	}
}

// Cloned-VM / replaced-disk: fstab still names the OLD filesystem id for / → the
// device is absent → CRIT (boot-blocking). Mirrors guest-101's PARTUUID= cloud-image
// layout (PARTUUID for / and /boot/efi).
func TestParseFstabDrifts_RootDriftIsBootMount(t *testing.T) {
	const fstab = `PARTUUID=old-root-id / ext4 defaults 0 1
PARTUUID=present-efi /boot/efi vfat defaults 0 2`
	byPart := map[string]bool{"present-efi": true} // old-root-id is gone (disk re-imaged)
	got := parseFstabDrifts(fstab, nil, byPart)
	if len(got) != 1 {
		t.Fatalf("want 1 drift, got %+v", got)
	}
	if got[0].MountPoint != "/" || !got[0].BootMount {
		t.Errorf("root drift must be flagged as a boot mount: %+v", got[0])
	}
}

// openSUSE-style btrfs: many entries share ONE UUID (subvolumes). When that UUID is
// present, none drift; the same-UUID repetition must not confuse the check.
func TestParseFstabDrifts_BtrfsSubvolsSameUUID(t *testing.T) {
	const fstab = `UUID=aa-bb / btrfs subvol=/@/.snapshots,defaults 0 0
UUID=aa-bb /home btrfs subvol=/@/home,defaults 0 0
UUID=aa-bb /var btrfs subvol=/@/var,defaults 0 0`
	if d := parseFstabDrifts(fstab, map[string]bool{"aa-bb": true}, nil); len(d) != 0 {
		t.Fatalf("present btrfs UUID across subvols must not drift, got %+v", d)
	}
}

// Conservative skips: device paths, LABEL=, pseudo/network filesystems, and noauto
// entries are never flagged; a tag class with no present-device set is not judged.
func TestParseFstabDrifts_ConservativeSkips(t *testing.T) {
	const fstab = `LABEL=mydata /data ext4 defaults 0 2
tmpfs /tmp tmpfs defaults 0 0
server:/export /mnt/nfs nfs defaults 0 0
//host/share /mnt/cifs cifs defaults 0 0
UUID=detached /backup ext4 noauto 0 0
UUID=unknowable /x ext4 defaults 0 2`
	// byUUID empty → the UUID= classes can't be verified → no flags at all.
	if d := parseFstabDrifts(fstab, nil, nil); len(d) != 0 {
		t.Fatalf("nothing verifiable / all skipped — want 0 drifts, got %+v", d)
	}
	// With a populated set, the noauto entry is still skipped; only the genuinely
	// absent auto entry drifts.
	got := parseFstabDrifts(fstab, map[string]bool{"something-else": true}, nil)
	if len(got) != 1 || got[0].MountPoint != "/x" {
		t.Fatalf("only the non-noauto absent UUID should drift, got %+v", got)
	}
}
