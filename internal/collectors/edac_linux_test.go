//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
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

	avail, ce, ue, unreadable := readEDACCountsFrom(root)
	if !avail {
		t.Error("EDAC should be available when the root exists")
	}
	if ce != 8 { // 5 + 3
		t.Errorf("corrected = %d, want 8", ce)
	}
	if ue != 2 { // 2 + 0
		t.Errorf("uncorrected = %d, want 2", ue)
	}
	if unreadable {
		t.Error("unreadable = true, want false — every controller's counters read cleanly")
	}
}

func TestReadEDACCountsFrom_Absent(t *testing.T) {
	avail, ce, ue, unreadable := readEDACCountsFrom(filepath.Join(t.TempDir(), "no-edac"))
	if avail || ce != 0 || ue != 0 || unreadable {
		t.Errorf("absent EDAC = (%v,%d,%d,%v), want (false,0,0,false)", avail, ce, ue, unreadable)
	}
}

// TestReadEDACCountsFrom_CounterReadFails is the regression guard for
// internal-collectors-11-03: a controller registered as available (ce_count
// exists at the existence check) whose counter can't actually be read/parsed
// — a TOCTOU race, EIO, or unexpected sysfs content — must set
// countersUnreadable, not silently fold the failed read's 0 into the sum as
// if it were a genuine zero-error reading.
func TestReadEDACCountsFrom_CounterReadFails(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "mc0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// ce_count exists (passes the existence check, so available=true) but its
	// contents are garbled — simulates a corrupted/racing sysfs read.
	if err := os.WriteFile(filepath.Join(dir, "ce_count"), []byte("garbled\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ue_count"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	avail, ce, ue, unreadable := readEDACCountsFrom(root)
	if !avail {
		t.Error("expected available=true — the controller was genuinely registered")
	}
	if !unreadable {
		t.Error("expected unreadable=true when ce_count fails to parse")
	}
	if ce != 0 || ue != 0 {
		t.Errorf("counts = (%d,%d), want (0,0) — a failed-read controller's counters must not contribute", ce, ue)
	}
}

// TestReadEDACCountsFrom_NoControllers covers the false-OK fix: the edac/mc class
// dir exists on non-ECC hardware (with only power/subsystem/uevent, no mc*), and dsd
// must NOT report ECC as "available" there — else it shows "ECC OK 0 errors" implying
// ECC protection that isn't present (found live on a bare-metal non-ECC i7-6700).
func TestReadEDACCountsFrom_NoControllers(t *testing.T) {
	root := t.TempDir()
	for _, e := range []string{"power", "subsystem", "uevent"} {
		if err := os.MkdirAll(filepath.Join(root, e), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	avail, ce, ue, unreadable := readEDACCountsFrom(root)
	if avail || ce != 0 || ue != 0 || unreadable {
		t.Errorf("non-ECC (no mc* controllers) = (%v,%d,%d,%v), want (false,0,0,false)", avail, ce, ue, unreadable)
	}
}

// TestReadEDACCountsFrom_StrayMCPrefixedEntrySkipped guards the "mc"-prefixed
// but missing ce_count skip: a stray directory that happens to start with
// "mc" (e.g. "mc-something-unrelated") but has no ce_count file must not be
// counted as a real controller, while a genuine mc* dir alongside it still is.
func TestReadEDACCountsFrom_StrayMCPrefixedEntrySkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "mc-unrelated"), 0o755); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(root, "mc0")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "ce_count"), []byte("4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "ue_count"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	avail, ce, ue, unreadable := readEDACCountsFrom(root)
	if !avail {
		t.Error("expected available=true from the one genuine mc0 controller")
	}
	if ce != 4 || ue != 1 {
		t.Errorf("counts = (%d,%d), want (4,1) — the stray mc-prefixed dir must not contribute", ce, ue)
	}
	if unreadable {
		t.Error("unreadable = true, want false — the one genuine controller read cleanly")
	}
}

// TestReadEDACCounter covers readEDACCounter directly (routed through the
// active source via readFile, unlike readEDACCountsFrom above which reads
// the real filesystem): a well-formed counter, a trailing-newline counter
// (the real /sys/.../ce_count shape), a garbled/non-numeric value, and a
// missing file. The last two must report ok=false so a caller can
// distinguish "couldn't measure" from a genuine zero count
// (internal-collectors-11-03) — readEDACCountsFrom above is what gates
// "available" and folds a failed read into countersUnreadable.
func TestReadEDACCounter(t *testing.T) {
	cases := []struct {
		name   string
		seed   func(b *source.Bundle)
		path   string
		want   int64
		wantOK bool
	}{
		{
			name:   "well-formed counter with trailing newline",
			seed:   func(b *source.Bundle) { b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("5\n")) },
			path:   "/sys/devices/system/edac/mc/mc0/ce_count",
			want:   5,
			wantOK: true,
		},
		{
			name:   "well-formed counter, no trailing newline",
			seed:   func(b *source.Bundle) { b.PutFile("/sys/devices/system/edac/mc/mc0/ue_count", []byte("0")) },
			path:   "/sys/devices/system/edac/mc/mc0/ue_count",
			want:   0,
			wantOK: true,
		},
		{
			name: "garbled non-numeric contents",
			seed: func(b *source.Bundle) {
				b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("not-a-number\n"))
			},
			path:   "/sys/devices/system/edac/mc/mc0/ce_count",
			want:   0,
			wantOK: false,
		},
		{
			name:   "missing file",
			seed:   func(b *source.Bundle) {},
			path:   "/sys/devices/system/edac/mc/mc0/ce_count",
			want:   0,
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFixtureSource(t, c.seed)
			got, ok := readEDACCounter(c.path)
			if got != c.want || ok != c.wantOK {
				t.Errorf("readEDACCounter(%q) = (%d,%v), want (%d,%v)", c.path, got, ok, c.want, c.wantOK)
			}
		})
	}
}
