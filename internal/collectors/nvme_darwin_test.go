//go:build darwin

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectDrivesDarwinText_ListFailure_SetsUnreadable is the regression
// test for the false-OK fix: a `diskutil list` failure must set
// DrivesListUnreadable, distinguishing it from a genuinely drive-free host
// (both previously returned an identical empty *models.NVMeInfo{}).
func TestCollectDrivesDarwinText_ListFailure_SetsUnreadable(t *testing.T) {
	prev := SetSource(source.NewReplay(source.NewBundle())) // no PutCmd seeded → command errors as not-recorded
	t.Cleanup(func() { SetSource(prev) })

	info, err := collectDrivesDarwinText(context.Background())
	if err != nil {
		t.Fatalf("collectDrivesDarwinText() error: %v", err)
	}
	if !info.DrivesListUnreadable {
		t.Error("DrivesListUnreadable = false, want true when diskutil list fails")
	}
	if len(info.SATADevices) != 0 {
		t.Errorf("SATADevices = %+v, want empty on a list failure", info.SATADevices)
	}
}

// TestCollectDrivesDarwinText_EmptyOutput_SetsUnreadable covers the sibling
// failure mode: diskutil exits 0 but produces no output (also treated as a
// failure — real diskutil output is never empty on success).
func TestCollectDrivesDarwinText_EmptyOutput_SetsUnreadable(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("diskutil", []string{"list"}, "", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	info, err := collectDrivesDarwinText(context.Background())
	if err != nil {
		t.Fatalf("collectDrivesDarwinText() error: %v", err)
	}
	if !info.DrivesListUnreadable {
		t.Error("DrivesListUnreadable = false, want true on empty diskutil output")
	}
}

// TestCollectDrivesDarwinText_Success_NotUnreadable is the control: a
// successful diskutil list with no physical disks found must NOT set
// DrivesListUnreadable — that's the genuine "nothing to report" case.
func TestCollectDrivesDarwinText_Success_NotUnreadable(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("diskutil", []string{"list"}, "/dev/disk0 (external, physical):\n", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	info, err := collectDrivesDarwinText(context.Background())
	if err != nil {
		t.Fatalf("collectDrivesDarwinText() error: %v", err)
	}
	if info.DrivesListUnreadable {
		t.Error("DrivesListUnreadable = true, want false on a successful (if empty-of-matches) list")
	}
}
