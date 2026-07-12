//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// realBtrfsDevStats is the exact output of `btrfs device stats /mnt` on a
// two-device filesystem (btrfs-progs v6.x). Every device reports all five
// counters, in this fixed order, fully-qualified as `[<path>].<counter>`.
const realBtrfsDevStats = `[/dev/sdb].write_io_errs    0
[/dev/sdb].read_io_errs     0
[/dev/sdb].flush_io_errs    0
[/dev/sdb].corruption_errs  0
[/dev/sdb].generation_errs  0
[/dev/sdc].write_io_errs    3
[/dev/sdc].read_io_errs     7
[/dev/sdc].flush_io_errs    2
[/dev/sdc].corruption_errs  1
[/dev/sdc].generation_errs  5
`

func TestApplyBtrfsDevStats(t *testing.T) {
	vol := &models.BtrfsVolume{
		Status: "healthy",
		Devices: []models.BtrfsDev{
			{DevID: 1, Path: "/dev/sdb"},
			{DevID: 2, Path: "/dev/sdc"},
		},
	}

	applyBtrfsDevStats(realBtrfsDevStats, vol)

	// Clean device: every counter stays zero.
	sdb := vol.Devices[0]
	if sdb.ReadErrs|sdb.WriteErrs|sdb.CorruptErrs|sdb.GenErrs|sdb.FlushErrs != 0 {
		t.Errorf("sdb expected all-zero counters, got %+v", sdb)
	}

	// Faulty device: all five counters parsed, including the two that were
	// previously dropped (generation_errs, flush_io_errs).
	sdc := vol.Devices[1]
	if sdc.WriteErrs != 3 {
		t.Errorf("sdc write_io_errs: want 3, got %d", sdc.WriteErrs)
	}
	if sdc.ReadErrs != 7 {
		t.Errorf("sdc read_io_errs: want 7, got %d", sdc.ReadErrs)
	}
	if sdc.FlushErrs != 2 {
		t.Errorf("sdc flush_io_errs: want 2, got %d", sdc.FlushErrs)
	}
	if sdc.CorruptErrs != 1 {
		t.Errorf("sdc corruption_errs: want 1, got %d", sdc.CorruptErrs)
	}
	if sdc.GenErrs != 5 {
		t.Errorf("sdc generation_errs: want 5, got %d", sdc.GenErrs)
	}

	// Any non-zero counter upgrades volume status so the heuristic WARN fires.
	if vol.Status != "errors" {
		t.Errorf("status: want errors, got %q", vol.Status)
	}
}

// TestApplyBtrfsDevStatsGenFlushOnly proves a device with ONLY generation/flush
// errors (zero read/write/corruption) is no longer silently healthy — this is
// the exact gap the fix closes.
func TestApplyBtrfsDevStatsGenFlushOnly(t *testing.T) {
	vol := &models.BtrfsVolume{
		Status:  "healthy",
		Devices: []models.BtrfsDev{{DevID: 1, Path: "/dev/sdb"}},
	}

	out := `[/dev/sdb].write_io_errs    0
[/dev/sdb].read_io_errs     0
[/dev/sdb].flush_io_errs    4
[/dev/sdb].corruption_errs  0
[/dev/sdb].generation_errs  9
`
	applyBtrfsDevStats(out, vol)

	if vol.Devices[0].FlushErrs != 4 || vol.Devices[0].GenErrs != 9 {
		t.Errorf("gen/flush not captured: %+v", vol.Devices[0])
	}
	if vol.Status != "errors" {
		t.Errorf("gen/flush-only errors must upgrade status, got %q", vol.Status)
	}
}

// realNonRootBtrfsShow is the EXACT output of `btrfs filesystem show /` run as a
// non-root user on a healthy single-device Fedora 43 cloud box (arm64 EC2). btrfs
// cannot open the block device without privilege, so it prints the present device
// as `size 0 ... MISSING` with its real path — NOT an actual missing device.
const realNonRootBtrfsShow = `Label: 'fedora'  uuid: 509da459-91c3-45b9-9a77-dfeeb214752c
	Total devices 1 FS bytes used 744.21MiB
	devid    1 size 0 used 0 path /dev/nvme0n1p3 MISSING
`

// realGenuineMissingBtrfsShow is a two-device filesystem with devid 2 genuinely
// absent — btrfs uses the `<missing disk>` placeholder path. This IS a real fault.
const realGenuineMissingBtrfsShow = `Label: none  uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
	Total devices 2 FS bytes used 1.00GiB
	devid    1 size 2.00GiB used 1.00GiB path /dev/sdb
	devid    2 size 0 used 0 path <missing disk> MISSING
`

// A real device flagged MISSING under a NON-ROOT run must NOT count as a missing
// device (it's the unprivileged "can't open device" artifact) — the false-CRIT
// found on the Fedora EC2 box. The volume is "unverified", missing count zero.
func TestApplyBtrfsShow_NonRootUnreadableIsNotMissing(t *testing.T) {
	vol := applyBtrfsShow(realNonRootBtrfsShow, "/", true /*nonRoot*/)
	if vol == nil {
		t.Fatal("expected a volume, got nil")
	}
	if vol.MissingDevs != 0 {
		t.Errorf("non-root unreadable device must NOT count as missing, got MissingDevs=%d", vol.MissingDevs)
	}
	if !vol.DevReadUnverified {
		t.Error("non-root real-path MISSING must set DevReadUnverified")
	}
	if vol.Status == "degraded" {
		t.Errorf("status must not be degraded for the non-root artifact, got %q", vol.Status)
	}
}

// The SAME output seen as ROOT would be anomalous (root can open present devices),
// so a real-path MISSING is not suppressed — we don't hide a potential real fault.
func TestApplyBtrfsShow_RootRealPathMissingStillCounts(t *testing.T) {
	vol := applyBtrfsShow(realNonRootBtrfsShow, "/", false /*root*/)
	if vol.MissingDevs != 1 {
		t.Errorf("as root, a real-path MISSING is not the privilege artifact — want MissingDevs=1, got %d", vol.MissingDevs)
	}
	if vol.DevReadUnverified {
		t.Error("root run must not set DevReadUnverified")
	}
}

// A genuinely-absent device (`<missing disk>` placeholder) is a real DEGRADED fault
// regardless of privilege — must still be counted even on a non-root run.
func TestApplyBtrfsShow_GenuineMissingCountsEvenNonRoot(t *testing.T) {
	vol := applyBtrfsShow(realGenuineMissingBtrfsShow, "/mnt", true /*nonRoot*/)
	if vol.MissingDevs != 1 {
		t.Errorf("genuine `<missing disk>` must count as missing even non-root, got MissingDevs=%d", vol.MissingDevs)
	}
	if vol.Status != "degraded" {
		t.Errorf("genuine missing device must be degraded, got %q", vol.Status)
	}
}

// TestApplyBtrfsShow_NoUUIDReturnsNil guards the "couldn't parse a UUID at all"
// branch: malformed/empty `btrfs filesystem show` output must yield nil rather
// than a fabricated healthy volume with an empty UUID.
func TestApplyBtrfsShow_NoUUIDReturnsNil(t *testing.T) {
	vol := applyBtrfsShow("not real btrfs output\nno uuid line here\n", "/mnt", false)
	if vol != nil {
		t.Errorf("expected nil for output with no UUID line, got %+v", vol)
	}
}

// TestApplyBtrfsDevStatsUnmappedPath is the false-OK regression guard: a non-zero
// error counter whose device path does NOT match any device from `btrfs filesystem
// show` (multi-device path-format mismatch, /dev/mapper/LUKS names, or an empty
// vol.Devices from a show-parse miss) must still flag the volume. Previously the
// path-match failure dropped the error and the volume stayed "healthy".
func TestApplyBtrfsDevStatsUnmappedPath(t *testing.T) {
	// vol.Devices empty (e.g. parseBtrfsShow couldn't enumerate devices), yet device
	// stats reports real corruption.
	vol := &models.BtrfsVolume{Status: "healthy"}
	out := `[/dev/mapper/cryptroot].write_io_errs    0
[/dev/mapper/cryptroot].read_io_errs     0
[/dev/mapper/cryptroot].flush_io_errs    0
[/dev/mapper/cryptroot].corruption_errs  12
[/dev/mapper/cryptroot].generation_errs  0
`
	applyBtrfsDevStats(out, vol)

	if vol.Status != "errors" {
		t.Errorf("corruption on an unmappable device path must still flag the volume, got %q", vol.Status)
	}
	if vol.StatusReason == "" {
		t.Error("expected a StatusReason when errors are detected")
	}
}
