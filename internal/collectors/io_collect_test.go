//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewIOCollectorIdentity guards Name/Timeout wiring and the default
// diskstats path.
func TestNewIOCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewIOCollector()
	if c == nil {
		t.Fatal("NewIOCollector() returned nil")
	}
	if c.Name() != "IO" {
		t.Errorf("Name() = %q, want IO", c.Name())
	}
	if c.Timeout() != 4*time.Second {
		t.Errorf("Timeout() = %v, want 4s", c.Timeout())
	}
	if c.diskstatsPath != "/proc/diskstats" {
		t.Errorf("diskstatsPath = %q, want /proc/diskstats", c.diskstatsPath)
	}
}

// TestIOCollector_Collect_OpenError guards the first-open failure path: when
// /proc/diskstats can't be opened at all, Collect must return a wrapped error
// without attempting the 1s-gapped second read (so the test completes
// instantly, no real sleep).
func TestIOCollector_Collect_OpenError(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/diskstats never seeded

	c := NewIOCollector()
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error when /proc/diskstats can't be opened")
	}
}

// TestIOCollector_Collect_ContextCancelledDuringGap guards the ctx.Done()
// early-return inside the 1-second inter-sample gap: a context that's already
// cancelled before Collect reaches the gap must return ctx.Err() immediately,
// without actually waiting out the full second.
func TestIOCollector_Collect_ContextCancelledDuringGap(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/diskstats", []byte(
			"   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n",
		))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Collect ever runs

	c := NewIOCollector()
	start := time.Now()
	_, err := c.Collect(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected ctx.Err() when context is already cancelled")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Collect took %v with a pre-cancelled context, want near-instant (no 1s wait)", elapsed)
	}
}

// TestIOCollector_Collect_HappyPath exercises the full two-sample path with a
// REAL 1-second gap (the fixture source returns the same static content for
// both /proc/diskstats reads — there is no injectable-reader seam in
// IOCollector.Collect, unlike CPUCollector — so this is the only way to
// exercise the complete Collect() body end-to-end). Same before/after content
// means every delta is 0, but this still proves: both opens succeed, the
// parse succeeds twice, the "only in 2nd sample" skip is not hit, and the
// device survives into the sorted result with a valid drive type.
func TestIOCollector_Collect_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real 1s IO sampling gap in short mode")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/diskstats", []byte(
			"   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808\n"+
				"   259     0 nvme0n1 1000 200 50000 300 800 100 40000 200 0 500 700\n",
		))
		b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	})

	c := NewIOCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.IOInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if len(info.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d: %+v", len(info.Devices), info.Devices)
	}
	// Sorted by name: nvme0n1 before sda.
	if info.Devices[0].Name != "nvme0n1" || info.Devices[1].Name != "sda" {
		t.Errorf("expected sorted [nvme0n1, sda], got [%s, %s]", info.Devices[0].Name, info.Devices[1].Name)
	}
	if info.Devices[0].DriveType != "nvme" {
		t.Errorf("nvme0n1 DriveType = %q, want nvme", info.Devices[0].DriveType)
	}
	if info.Devices[1].DriveType != "ssd" {
		t.Errorf("sda DriveType = %q, want ssd (rotational=0)", info.Devices[1].DriveType)
	}
	// Same before/after content -> zero deltas throughout.
	for _, d := range info.Devices {
		if d.ReadMBps != 0 || d.WriteMBps != 0 || d.UtilPct != 0 {
			t.Errorf("device %s: expected all-zero deltas from identical samples, got %+v", d.Name, d)
		}
	}
}

// TestComputeDeltaZeroOps guards the AwaitMs boundary not covered by the
// existing computeDelta parser tests: with reads+writes unchanged between
// samples (zero ops in the window), AwaitMs must stay 0 rather than
// dividing by zero / producing NaN.
func TestComputeDeltaZeroOps(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
	})
	before := diskStatRaw{reads: 10, writes: 10}
	after := diskStatRaw{reads: 10, writes: 10} // no new ops
	d := computeDelta("sda", before, after)
	if d.AwaitMs != 0 {
		t.Errorf("AwaitMs = %v, want 0 with no ops", d.AwaitMs)
	}
}

// TestDriveType guards the nvme/hdd/ssd classification, including the sysfs
// rotational read and its error-defaults-to-SSD fallback.
func TestDriveType(t *testing.T) {
	t.Run("nvme by name prefix, no sysfs read needed", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if got := driveType("nvme0n1"); got != "nvme" {
			t.Errorf("driveType(nvme0n1) = %q, want nvme", got)
		}
	})

	t.Run("rotational=1 is hdd", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/block/sda/queue/rotational", []byte("1\n"))
		})
		if got := driveType("sda"); got != "hdd" {
			t.Errorf("driveType(sda) = %q, want hdd", got)
		}
	})

	t.Run("rotational=0 is ssd", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/block/sda/queue/rotational", []byte("0\n"))
		})
		if got := driveType("sda"); got != "ssd" {
			t.Errorf("driveType(sda) = %q, want ssd", got)
		}
	})

	t.Run("unreadable rotational file defaults to ssd", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {}) // not seeded -> read error
		if got := driveType("vda"); got != "ssd" {
			t.Errorf("driveType(vda) = %q, want ssd (error defaults to SSD)", got)
		}
	})
}

// TestReadRotational guards the rotational-flag reader directly.
func TestReadRotational(t *testing.T) {
	t.Run("rotational", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/block/sdb/queue/rotational", []byte("1\n"))
		})
		if !readRotational("sdb") {
			t.Error("expected true for rotational=1")
		}
	})

	t.Run("not rotational", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/block/sdb/queue/rotational", []byte("0\n"))
		})
		if readRotational("sdb") {
			t.Error("expected false for rotational=0")
		}
	})

	t.Run("read error defaults to false (assume SSD)", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if readRotational("sdc") {
			t.Error("expected false on read error")
		}
	})
}

// TestParseFiniteFloatIOBoundaries guards the finite-float guard shared with
// the darwin iostat parser: NaN/Inf/negative must all reject rather than
// silently becoming a verdict-corrupting sentinel.
func TestParseFiniteFloatIOBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		in     string
		wantOK bool
		want   float64
	}{
		{"valid positive", "12.5", true, 12.5},
		{"zero", "0", true, 0},
		{"NaN rejected", "NaN", false, 0},
		{"Inf rejected", "Inf", false, 0},
		{"negative rejected", "-1.5", false, 0},
		{"garbage rejected", "abc", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseFiniteFloat(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
