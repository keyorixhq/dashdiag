//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
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

// Conservative skips: device paths, LABEL=, pseudo/network filesystems, and
// noauto/nofail entries are never flagged; a tag class with no present-device set
// is not judged.
func TestParseFstabDrifts_ConservativeSkips(t *testing.T) {
	const fstab = `LABEL=mydata /data ext4 defaults 0 2
tmpfs /tmp tmpfs defaults 0 0
server:/export /mnt/nfs nfs defaults 0 0
//host/share /mnt/cifs cifs defaults 0 0
UUID=detached /backup ext4 noauto 0 0
UUID=optional /usb ext4 nofail 0 0
UUID=combo /opt ext4 defaults,nofail,x-systemd.device-timeout=5 0 2
UUID=unknowable /x ext4 defaults 0 2`
	// byUUID empty → the UUID= classes can't be verified → no flags at all.
	if d := parseFstabDrifts(fstab, nil, nil); len(d) != 0 {
		t.Fatalf("nothing verifiable / all skipped — want 0 drifts, got %+v", d)
	}
	// With a populated set, the noauto and nofail entries are still skipped (a nofail
	// device that's absent does not fail boot); only the genuinely absent auto entry
	// drifts.
	got := parseFstabDrifts(fstab, map[string]bool{"something-else": true}, nil)
	if len(got) != 1 || got[0].MountPoint != "/x" {
		t.Fatalf("only the non-noauto/non-nofail absent UUID should drift, got %+v", got)
	}
}

// TestParseFstabDrifts_MalformedAndQuoted guards short/blank lines being
// skipped and a quoted UUID= value being unquoted before matching.
func TestParseFstabDrifts_MalformedAndQuoted(t *testing.T) {
	const fstab = `
# comment
onlyonefield
UUID="quoted-id" /q ext4 defaults 0 2`
	got := parseFstabDrifts(fstab, map[string]bool{"quoted-id": true}, nil)
	if len(got) != 0 {
		t.Fatalf("quoted UUID matching the present set must not drift, got %+v", got)
	}
}

// TestUnquote guards the quote-stripping helper directly.
func TestUnquote(t *testing.T) {
	t.Parallel()
	if got := unquote(`"abc-123"`); got != "abc-123" {
		t.Errorf("unquote(quoted) = %q, want abc-123", got)
	}
	if got := unquote("abc-123"); got != "abc-123" {
		t.Errorf("unquote(bare) = %q, want abc-123", got)
	}
}

// TestHasMountOpt guards the comma-split option match.
func TestHasMountOpt(t *testing.T) {
	t.Parallel()
	if !hasMountOpt("rw,noauto,x-foo", "noauto") {
		t.Error("expected noauto to be found")
	}
	if hasMountOpt("rw,nofail", "noauto") {
		t.Error("did not expect noauto to be found in rw,nofail")
	}
	if hasMountOpt("", "noauto") {
		t.Error("empty opts must not match anything")
	}
}

// ── Collect() / identity / gate tests ────────────────────────────────────────

func TestFstabDriftCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewFstabDriftCollector()
	if c.Name() != "Fstab" {
		t.Errorf("Name() = %q, want Fstab", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

func TestFstabAvailable(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/etc/fstab", source.FileMeta{})
		})
		if !FstabAvailable() {
			t.Error("expected true when /etc/fstab exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if FstabAvailable() {
			t.Error("expected false when /etc/fstab does not exist")
		}
	})
}

func TestLowerDirNameSet(t *testing.T) {
	t.Run("lowercases entries", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/dev/disk/by-uuid", []string{"ABCD-1234", "ef56-7890"})
		})
		got := lowerDirNameSet("/dev/disk/by-uuid")
		if !got["abcd-1234"] || !got["ef56-7890"] {
			t.Errorf("expected lowercased entries in set, got %v", got)
		}
	})

	t.Run("unreadable dir returns nil", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if got := lowerDirNameSet("/dev/disk/by-uuid"); got != nil {
			t.Errorf("expected nil for unreadable dir, got %v", got)
		}
	})

	t.Run("empty dir returns nil", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/dev/disk/by-uuid", []string{})
		})
		if got := lowerDirNameSet("/dev/disk/by-uuid"); got != nil {
			t.Errorf("expected nil for empty dir (not distinguishable from absent by design), got %v", got)
		}
	})
}

// TestFstabDriftCollector_Collect_FstabUnreadable guards the Checked=false
// degrade path when /etc/fstab itself can't be read.
func TestFstabDriftCollector_Collect_FstabUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewFstabDriftCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FstabInfo)
	if info.Checked {
		t.Errorf("expected Checked=false when /etc/fstab is unreadable, got %+v", info)
	}
}

// TestFstabDriftCollector_Collect_NoUdevTagDirs guards the "can't verify"
// degrade path: fstab readable, but neither udev tag dir has any entries — the
// collector must not false-flag every UUID=/PARTUUID= entry.
func TestFstabDriftCollector_Collect_NoUdevTagDirs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/fstab", []byte("UUID=abc-123 / ext4 defaults 0 1\n"))
	})
	c := NewFstabDriftCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FstabInfo)
	if info.Checked {
		t.Errorf("expected Checked=false when neither udev tag dir is populated, got %+v", info)
	}
	if len(info.Drifts) != 0 {
		t.Errorf("expected no drifts reported when unverifiable, got %+v", info.Drifts)
	}
}

// TestFstabDriftCollector_Collect_HappyPathClean guards the fully-verified,
// no-drift case: fstab entry's UUID is present in /dev/disk/by-uuid.
func TestFstabDriftCollector_Collect_HappyPathClean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/fstab", []byte("UUID=abc-123 / ext4 defaults 0 1\n"))
		b.PutDir("/dev/disk/by-uuid", []string{"abc-123"})
	})
	c := NewFstabDriftCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FstabInfo)
	if !info.Checked {
		t.Error("expected Checked=true")
	}
	if len(info.Drifts) != 0 {
		t.Errorf("expected no drifts for a present UUID, got %+v", info.Drifts)
	}
}

// TestFstabDriftCollector_Collect_HappyPathDrift guards the drift-detected
// case end to end through Collect, not just parseFstabDrifts directly.
func TestFstabDriftCollector_Collect_HappyPathDrift(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/fstab", []byte("UUID=missing-id /data ext4 defaults 0 2\n"))
		b.PutDir("/dev/disk/by-uuid", []string{"other-id"})
	})
	c := NewFstabDriftCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FstabInfo)
	if !info.Checked {
		t.Error("expected Checked=true")
	}
	if len(info.Drifts) != 1 || info.Drifts[0].MountPoint != "/data" {
		t.Fatalf("expected 1 drift on /data, got %+v", info.Drifts)
	}
	if info.Drifts[0].BootMount {
		t.Errorf("/data is not a boot mount, BootMount should be false, got %+v", info.Drifts[0])
	}
}

// TestFstabDriftCollector_Collect_PARTUUIDOnly guards that byPart alone (no
// by-uuid entries) still verifies PARTUUID= specs through Collect.
func TestFstabDriftCollector_Collect_PARTUUIDOnly(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/fstab", []byte("PARTUUID=deadbeef /boot/efi vfat defaults 0 1\n"))
		b.PutDir("/dev/disk/by-partuuid", []string{"deadbeef"})
	})
	c := NewFstabDriftCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FstabInfo)
	if !info.Checked || len(info.Drifts) != 0 {
		t.Errorf("expected Checked=true, no drifts, got %+v", info)
	}
}
