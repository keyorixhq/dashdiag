//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEDACCountsFrom(t *testing.T) {
	root := t.TempDir()
	mk := func(mc, ce, ue string) {
		dir := filepath.Join(root, mc)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ce_count"), []byte(ce), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ue_count"), []byte(ue), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("mc0", "5\n", "2\n")
	mk("mc1", "3", "0")
	if err := os.MkdirAll(filepath.Join(root, "max_location"), 0o755); err != nil { // non-mc entry, ignored
		t.Fatal(err)
	}

	avail, ce, ue := readEDACCountsFrom(root)
	if !avail {
		t.Error("EDAC should be available when the root exists")
	}
	if ce != 8 { // 5 + 3
		t.Errorf("corrected = %d, want 8", ce)
	}
	if ue != 2 { // 2 + 0
		t.Errorf("uncorrected = %d, want 2", ue)
	}
}

func TestReadEDACCountsFrom_Absent(t *testing.T) {
	avail, ce, ue := readEDACCountsFrom(filepath.Join(t.TempDir(), "no-edac"))
	if avail || ce != 0 || ue != 0 {
		t.Errorf("absent EDAC = (%v,%d,%d), want (false,0,0)", avail, ce, ue)
	}
}
