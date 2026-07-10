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
	avail, ce, ue := readEDACCountsFrom(root)
	if avail || ce != 0 || ue != 0 {
		t.Errorf("non-ECC (no mc* controllers) = (%v,%d,%d), want (false,0,0)", avail, ce, ue)
	}
}

// TestReadEDACCounter covers readEDACCounter directly (routed through the
// active source via readFile, unlike readEDACCountsFrom above which reads
// the real filesystem): a well-formed counter, a trailing-newline counter
// (the real /sys/.../ce_count shape), a garbled/non-numeric value, and a
// missing file — none of the last two must ever be mistaken for a real
// zero count vs. "couldn't measure", which is why the function collapses
// both to 0 (readEDACCountsFrom above is what gates "available").
func TestReadEDACCounter(t *testing.T) {
	cases := []struct {
		name string
		seed func(b *source.Bundle)
		path string
		want int64
	}{
		{
			name: "well-formed counter with trailing newline",
			seed: func(b *source.Bundle) {
				b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("5\n"))
			},
			path: "/sys/devices/system/edac/mc/mc0/ce_count",
			want: 5,
		},
		{
			name: "well-formed counter, no trailing newline",
			seed: func(b *source.Bundle) {
				b.PutFile("/sys/devices/system/edac/mc/mc0/ue_count", []byte("0"))
			},
			path: "/sys/devices/system/edac/mc/mc0/ue_count",
			want: 0,
		},
		{
			name: "garbled non-numeric contents",
			seed: func(b *source.Bundle) {
				b.PutFile("/sys/devices/system/edac/mc/mc0/ce_count", []byte("not-a-number\n"))
			},
			path: "/sys/devices/system/edac/mc/mc0/ce_count",
			want: 0,
		},
		{
			name: "missing file",
			seed: func(b *source.Bundle) {},
			path: "/sys/devices/system/edac/mc/mc0/ce_count",
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFixtureSource(t, c.seed)
			if got := readEDACCounter(c.path); got != c.want {
				t.Errorf("readEDACCounter(%q) = %d, want %d", c.path, got, c.want)
			}
		})
	}
}
