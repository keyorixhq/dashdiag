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
