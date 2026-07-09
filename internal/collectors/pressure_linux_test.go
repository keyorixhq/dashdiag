//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Captured from /proc/pressure/memory on a loaded system
const psiMemoryLoaded = `some avg10=5.21 avg60=3.14 avg300=1.02 total=12345678
full avg10=2.10 avg60=1.05 avg300=0.34 total=5678901
`

const psiMemoryCritical = `some avg10=45.00 avg60=32.00 avg300=15.00 total=99999999
full avg10=22.00 avg60=18.00 avg300=8.00 total=44444444
`

const psiMemoryIdle = `some avg10=0.00 avg60=0.00 avg300=0.00 total=0
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
`

func TestReadPSIFile(t *testing.T) {
	t.Run("loaded system parses correctly", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryLoaded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lines) != 2 {
			t.Fatalf("lines = %d, want 2", len(lines))
		}
		if lines[0].Avg10 != 5.21 {
			t.Errorf("some.avg10 = %f, want 5.21", lines[0].Avg10)
		}
		if lines[0].Avg60 != 3.14 {
			t.Errorf("some.avg60 = %f, want 3.14", lines[0].Avg60)
		}
		if lines[1].Avg10 != 2.10 {
			t.Errorf("full.avg10 = %f, want 2.10", lines[1].Avg10)
		}
	})

	t.Run("idle system returns zeros", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryIdle)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, l := range lines {
			if l.Avg10 != 0 || l.Avg60 != 0 || l.Avg300 != 0 {
				t.Errorf("expected all zeros, got %+v", l)
			}
		}
	})

	t.Run("critical memory pressure detected", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryCritical)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lines[1].Avg60 < 10 {
			t.Errorf("full.avg60 = %f, want >= 10 (critical threshold)", lines[1].Avg60)
		}
	})

	// Regression: a malformed/truncated pressure file (no line with >=4 fields)
	// must return an empty slice — never a non-nil err with a [0]-indexable slice.
	// Collect() relies on this to guard its m[0]/cpu[0]/io[0] indexing.
	t.Run("malformed content returns empty, no nil-err non-empty trap", func(t *testing.T) {
		for _, content := range []string{"", "   \n", "garbage", "some avg10=1.0"} {
			lines, err := readPSIString(content)
			if err != nil {
				t.Fatalf("readPSIString(%q) err = %v, want nil", content, err)
			}
			if len(lines) != 0 {
				t.Errorf("readPSIString(%q) = %d lines, want 0", content, len(lines))
			}
		}
	})
}

func TestPressureCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewPressureCollector()
	if c.Name() != "Pressure" {
		t.Errorf("Name() = %q, want Pressure", c.Name())
	}
	if c.Timeout() != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", c.Timeout())
	}
}

// TestPressureCollector_Collect_ProcPressure exercises the primary /proc/pressure
// path (no suffix) with full some/full lines for memory and io, and a some-only
// line for cpu.
func TestPressureCollector_Collect_ProcPressure(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/proc/pressure", source.FileMeta{})
		b.PutFile("/proc/pressure/memory", []byte(
			"some avg10=1.50 avg60=2.50 avg300=0.10 total=1234\n"+
				"full avg10=0.50 avg60=1.00 avg300=0.05 total=567\n"))
		b.PutFile("/proc/pressure/cpu", []byte(
			"some avg10=5.00 avg60=4.00 avg300=3.00 total=999\n"))
		b.PutFile("/proc/pressure/io", []byte(
			"some avg10=10.00 avg60=9.00 avg300=8.00 total=111\n"+
				"full avg10=6.00 avg60=5.00 avg300=4.00 total=222\n"))
	})

	c := NewPressureCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PressureInfo)
	if !info.Available {
		t.Fatal("expected Available=true when /proc/pressure exists")
	}
	if info.MemorySome.Avg10 != 1.5 || info.MemoryFull.Avg10 != 0.5 {
		t.Errorf("memory some/full = %+v/%+v, want avg10 1.5/0.5", info.MemorySome, info.MemoryFull)
	}
	if info.CPUSome.Avg10 != 5.0 {
		t.Errorf("CPUSome.Avg10 = %v, want 5.0", info.CPUSome.Avg10)
	}
	if info.IOSome.Avg10 != 10.0 || info.IOFull.Avg10 != 6.0 {
		t.Errorf("io some/full = %+v/%+v, want avg10 10.0/6.0", info.IOSome, info.IOFull)
	}
}

// TestPressureCollector_Collect_CgroupFallback guards the fallback to
// /sys/fs/cgroup/*.pressure when /proc/pressure is absent.
func TestPressureCollector_Collect_CgroupFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// /proc/pressure NOT seeded -> fileExists returns false -> falls back.
		b.PutStat("/sys/fs/cgroup/memory.pressure", source.FileMeta{})
		b.PutFile("/sys/fs/cgroup/memory.pressure", []byte(
			"some avg10=2.00 avg60=1.00 avg300=0.50 total=42\n"))
		b.PutFile("/sys/fs/cgroup/cpu.pressure", []byte(
			"some avg10=3.00 avg60=2.00 avg300=1.00 total=43\n"))
		b.PutFile("/sys/fs/cgroup/io.pressure", []byte(
			"some avg10=4.00 avg60=3.00 avg300=2.00 total=44\n"))
	})

	c := NewPressureCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PressureInfo)
	if !info.Available {
		t.Fatal("expected Available=true via the cgroup v2 fallback")
	}
	if info.MemorySome.Avg10 != 2.0 {
		t.Errorf("MemorySome.Avg10 = %v, want 2.0 (cgroup fallback)", info.MemorySome.Avg10)
	}
}

// TestPressureCollector_Collect_NotAvailable guards the "PSI unsupported"
// path: neither /proc/pressure nor the cgroup v2 PSI files exist.
func TestPressureCollector_Collect_NotAvailable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})

	c := NewPressureCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PressureInfo)
	if info.Available {
		t.Errorf("expected Available=false when no PSI source exists, got %+v", info)
	}
}

func TestIsPSIAvailable(t *testing.T) {
	t.Run("proc pressure", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/proc/pressure/memory", source.FileMeta{})
		})
		if !IsPSIAvailable() {
			t.Error("expected true when /proc/pressure/memory exists")
		}
	})

	t.Run("cgroup fallback", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/sys/fs/cgroup/memory.pressure", source.FileMeta{})
		})
		if !IsPSIAvailable() {
			t.Error("expected true when the cgroup v2 PSI file exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsPSIAvailable() {
			t.Error("expected false when neither PSI source exists")
		}
	})
}

// TestReadPSIFile_Missing guards the file-read error branch.
func TestReadPSIFile_Missing(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	_, err := readPSIFile("/proc/pressure/memory")
	if err == nil {
		t.Error("expected an error when the PSI file does not exist")
	}
}
