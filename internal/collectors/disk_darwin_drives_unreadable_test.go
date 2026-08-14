//go:build darwin

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectDarwinDrives_ListFailure_SetsUnreadable is the regression test
// for the false-OK fix: a `diskutil list` failure must be distinguishable
// from a genuinely drive-free host (both previously returned an identical
// empty []models.PhysicalDrive) — see DiskInfo.DrivesListUnreadable.
func TestCollectDarwinDrives_ListFailure_SetsUnreadable(t *testing.T) {
	prev := SetSource(source.NewReplay(source.NewBundle())) // no PutCmd seeded → command errors as not-recorded
	t.Cleanup(func() { SetSource(prev) })

	drives, unreadable := collectDarwinDrives(context.Background())
	if !unreadable {
		t.Error("unreadable = false, want true when diskutil list fails")
	}
	if len(drives) != 0 {
		t.Errorf("drives = %+v, want empty on a list failure", drives)
	}
}

// TestCollectDarwinDrives_EmptyOutput_SetsUnreadable covers the sibling
// failure mode: diskutil exits 0 but produces no output (also treated as a
// failure — real diskutil output is never empty on success).
func TestCollectDarwinDrives_EmptyOutput_SetsUnreadable(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("diskutil", []string{"list"}, "", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	_, unreadable := collectDarwinDrives(context.Background())
	if !unreadable {
		t.Error("unreadable = false, want true on empty diskutil output")
	}
}

// TestCollectDarwinDrives_Success_NotUnreadable is the control: a successful
// diskutil list with no matching physical disks must NOT set unreadable —
// that's the genuine "nothing to report" case.
func TestCollectDarwinDrives_Success_NotUnreadable(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("diskutil", []string{"list"}, "/dev/disk0 (synthesized):\n", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	_, unreadable := collectDarwinDrives(context.Background())
	if unreadable {
		t.Error("unreadable = true, want false on a successful (if empty-of-matches) list")
	}
}
