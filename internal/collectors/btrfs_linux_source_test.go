//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestParseBtrfsShow exercises the runCmd wrapper (applyBtrfsShow, the actual
// parsing logic, already has direct coverage). Uses the genuinely-missing-
// device case (the literal "<missing disk>" placeholder), which behaves the
// same regardless of the test process's effective UID — the real-path
// unreadable-vs-missing distinction (root vs non-root) is exercised directly
// against applyBtrfsShow elsewhere, not through the live os.Geteuid() here.
func TestParseBtrfsShow(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("btrfs", []string{"filesystem", "show", "/mnt/data"},
			"Label: none  uuid: 1234-5678-abcd\n"+
				"\tTotal devices 2 FS bytes used 1.00GiB\n"+
				"\tdevid    1 size 10.00GiB used 1.00GiB path /dev/sda1\n"+
				"\tdevid    2 size 0.00B used 0.00B path <missing disk>\n", 0)
	})
	vol := parseBtrfsShow(context.Background(), "/mnt/data")
	if vol == nil {
		t.Fatal("a valid btrfs show output with a UUID should not return nil")
	}
	if vol.Status != "degraded" || vol.MissingDevs != 1 {
		t.Errorf("a genuinely missing device should degrade the volume, got %+v", vol)
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("btrfs", []string{"filesystem", "show", "/mnt/data"})
	})
	if got := parseBtrfsShow(context.Background(), "/mnt/data"); got != nil {
		t.Errorf("a missing btrfs binary should return nil, not a fabricated volume, got %+v", got)
	}
}

func TestParseBtrfsDevStats(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("btrfs", []string{"device", "stats", "/mnt/data"},
			"[/dev/sda1].write_io_errs    3\n[/dev/sda1].read_io_errs    0\n", 0)
	})
	vol := &models.BtrfsVolume{Devices: []models.BtrfsDev{{Path: "/dev/sda1"}}}
	parseBtrfsDevStats(context.Background(), "/mnt/data", vol)
	if !vol.StatsRead {
		t.Error("a successful device-stats run should mark counters as read")
	}
	if vol.Devices[0].WriteErrs != 3 {
		t.Errorf("the write error counter should be parsed, got %+v", vol.Devices[0])
	}
}

// TestParseBtrfsDevStats_CommandFailsLeavesStatsUnread guards the early-return
// branch: a failing (or empty-output) `btrfs device stats` run must leave
// StatsRead false rather than fabricating a zero-value reading — the analysis
// layer distinguishes "counters not read" from "counters read as zero".
func TestParseBtrfsDevStats_CommandFailsLeavesStatsUnread(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("btrfs", []string{"device", "stats", "/mnt/data"})
	})
	vol := &models.BtrfsVolume{Devices: []models.BtrfsDev{{Path: "/dev/sda1"}}}
	parseBtrfsDevStats(context.Background(), "/mnt/data", vol)
	if vol.StatsRead {
		t.Error("a failed device-stats command must not mark counters as read")
	}
}

// TestParseBtrfsDevStats_EmptyOutputLeavesStatsUnread covers the `out == ""`
// half of the early-return guard specifically (exit 0 with no output).
func TestParseBtrfsDevStats_EmptyOutputLeavesStatsUnread(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("btrfs", []string{"device", "stats", "/mnt/data"}, "", 0)
	})
	vol := &models.BtrfsVolume{Devices: []models.BtrfsDev{{Path: "/dev/sda1"}}}
	parseBtrfsDevStats(context.Background(), "/mnt/data", vol)
	if vol.StatsRead {
		t.Error("empty device-stats output must not mark counters as read")
	}
}

// ── collectBtrfsVolumes ──────────────────────────────────────────────────────

// TestCollectBtrfsVolumes_NoFilesystems guards the fast-path: no btrfs
// filesystems in the input list must short-circuit to nil without running any
// command.
func TestCollectBtrfsVolumes_NoFilesystems(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("btrfs", []string{"filesystem", "show", "/"},
			"should never be called", 0)
	})
	fss := []models.FilesystemInfo{{FSType: "ext4", Mount: "/"}}
	if got := collectBtrfsVolumes(fss); got != nil {
		t.Errorf("expected nil with no btrfs filesystems, got %+v", got)
	}
}

// TestCollectBtrfsVolumes_DedupesByMountAndUUID guards two dedup layers: (1) a
// mount listed twice (multiple subvolumes on the same mount) is only probed
// once, and (2) two DIFFERENT mounts that report the SAME UUID (subvolumes of
// one filesystem) collapse to a single result entry.
func TestCollectBtrfsVolumes_DedupesByMountAndUUID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("btrfs", []string{"filesystem", "show", "/"},
			"Label: none  uuid: 1234-5678-abcd\n"+
				"\tTotal devices 1 FS bytes used 1.00GiB\n"+
				"\tdevid    1 size 10.00GiB used 1.00GiB path /dev/sda1\n", 0)
		b.PutCmd("btrfs", []string{"filesystem", "show", "/home"},
			// Same UUID as "/" — a subvolume of the same filesystem.
			"Label: none  uuid: 1234-5678-abcd\n"+
				"\tTotal devices 1 FS bytes used 1.00GiB\n"+
				"\tdevid    1 size 10.00GiB used 1.00GiB path /dev/sda1\n", 0)
		b.PutCmd("btrfs", []string{"device", "stats", "/"},
			"[/dev/sda1].write_io_errs    0\n[/dev/sda1].read_io_errs    0\n", 0)
	})
	fss := []models.FilesystemInfo{
		{FSType: "btrfs", Mount: "/"},
		{FSType: "btrfs", Mount: "/"},     // duplicate mount — must be probed only once
		{FSType: "btrfs", Mount: "/home"}, // different mount, same UUID — collapses
		{FSType: "ext4", Mount: "/boot"},  // non-btrfs — ignored entirely
	}
	got := collectBtrfsVolumes(fss)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 deduped volume, got %d: %+v", len(got), got)
	}
	if got[0].UUID != "1234-5678-abcd" {
		t.Errorf("UUID = %q, want 1234-5678-abcd", got[0].UUID)
	}
}

// TestCollectBtrfsVolumes_ShowFailureSkipsMount guards that a mount whose
// `btrfs filesystem show` fails (binary missing, transient error) is skipped
// rather than producing a fabricated volume.
func TestCollectBtrfsVolumes_ShowFailureSkipsMount(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("btrfs", []string{"filesystem", "show", "/mnt/broken"})
	})
	fss := []models.FilesystemInfo{{FSType: "btrfs", Mount: "/mnt/broken"}}
	if got := collectBtrfsVolumes(fss); got != nil {
		t.Errorf("expected nil when btrfs filesystem show fails, got %+v", got)
	}
}
