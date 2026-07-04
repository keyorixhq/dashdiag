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
