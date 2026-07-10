//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNewHugePagesCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewHugePagesCollector()
	if c.Name() != "HugePages" {
		t.Errorf("Name() = %q, want HugePages", c.Name())
	}
	if got := c.Timeout(); got != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", got)
	}
}

// TestHugePagesCollector_Collect_ConfiguredWithTHPAlways exercises the full
// happy path: meminfo huge-page fields parsed, THP sysfs read with the
// "always" mode active (bracketed value).
func TestHugePagesCollector_Collect_ConfiguredWithTHPAlways(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(meminfoWithHugePages))
		b.PutFile("/sys/kernel/mm/transparent_hugepage/enabled", []byte("[always] madvise never\n"))
	})
	c := NewHugePagesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info, ok := raw.(*models.HugePagesInfo)
	if !ok {
		t.Fatalf("unexpected type %T", raw)
	}
	if !info.Available {
		t.Error("Available should be true")
	}
	if info.Configured != 512 || info.Free != 400 || info.Used != 112 {
		t.Errorf("Configured/Free/Used = %d/%d/%d, want 512/400/112", info.Configured, info.Free, info.Used)
	}
	if info.PageSizeKB != 2048 {
		t.Errorf("PageSizeKB = %d, want 2048", info.PageSizeKB)
	}
	if info.ReservedGB < 0.9 || info.ReservedGB > 1.1 {
		t.Errorf("ReservedGB = %v, want ~1.0", info.ReservedGB)
	}
	if !info.THPEnabled || info.THPMode != "always" {
		t.Errorf("THPEnabled/THPMode = %v/%q, want true/always", info.THPEnabled, info.THPMode)
	}
}

// TestHugePagesCollector_Collect_THPMadvise guards the "madvise" bracketed
// branch, distinct from "always".
func TestHugePagesCollector_Collect_THPMadvise(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(meminfoNoHugePages))
		b.PutFile("/sys/kernel/mm/transparent_hugepage/enabled", []byte("always [madvise] never\n"))
	})
	c := NewHugePagesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.HugePagesInfo) //nolint:errcheck // type asserted in sibling test
	if !info.THPEnabled || info.THPMode != "madvise" {
		t.Errorf("THPEnabled/THPMode = %v/%q, want true/madvise", info.THPEnabled, info.THPMode)
	}
}

// TestHugePagesCollector_Collect_THPNever guards the "never" branch — THP
// present in sysfs but disabled — and that no static huge pages were
// configured leaves ReservedGB at zero.
func TestHugePagesCollector_Collect_THPNever(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(meminfoNoHugePages))
		b.PutFile("/sys/kernel/mm/transparent_hugepage/enabled", []byte("always madvise [never]\n"))
	})
	c := NewHugePagesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.HugePagesInfo) //nolint:errcheck // type asserted in sibling test
	if info.THPEnabled {
		t.Error("THPEnabled should be false for [never]")
	}
	if info.THPMode != "never" {
		t.Errorf("THPMode = %q, want never", info.THPMode)
	}
	if info.ReservedGB != 0 {
		t.Errorf("ReservedGB = %v, want 0 (no static huge pages configured)", info.ReservedGB)
	}
}

// TestHugePagesCollector_Collect_MeminfoUnreadable guards the graceful
// degrade: /proc/meminfo missing must still return a non-nil Available=true
// info (not an error), matching the "return info, nil" early-out in Collect.
func TestHugePagesCollector_Collect_MeminfoUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // nothing seeded
	c := NewHugePagesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.HugePagesInfo) //nolint:errcheck // type asserted in sibling test
	if !info.Available {
		t.Error("Available should stay true even when meminfo is unreadable")
	}
	if info.Configured != 0 || info.THPEnabled {
		t.Errorf("expected zero-value info, got %+v", info)
	}
}

// TestHugePagesCollector_Collect_THPAbsent guards the sysfs-missing branch:
// no transparent_hugepage sysfs file at all (e.g. THP compiled out) must
// leave THPEnabled/THPMode at their zero values, not "never".
func TestHugePagesCollector_Collect_THPAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte(meminfoWithHugePages))
		// transparent_hugepage/enabled intentionally not seeded.
	})
	c := NewHugePagesCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	info := raw.(*models.HugePagesInfo) //nolint:errcheck // type asserted in sibling test
	if info.THPEnabled {
		t.Error("THPEnabled should be false when the sysfs file is absent")
	}
	if info.THPMode != "" {
		t.Errorf("THPMode = %q, want empty when sysfs file absent", info.THPMode)
	}
}

// TestParseHugePagesMeminfo_SkipBranches covers the line-skip branches
// directly: a field with too few tokens must be ignored, and a non-numeric
// value must be skipped rather than propagating a parse error, while valid
// lines are still parsed correctly around them.
func TestParseHugePagesMeminfo_SkipBranches(t *testing.T) {
	t.Parallel()
	content := "HugePages_Total: 64\n" +
		"ShortLineNoValue\n" + // fewer than 2 fields — must be skipped
		"HugePages_Free: notanumber\n" + // non-numeric value — must be skipped
		"HugePages_Free: 10\n" +
		"Hugepagesize: 2048 kB\n"
	got := parseHugePagesMeminfo(content)
	if got.Configured != 64 {
		t.Errorf("Configured = %d, want 64", got.Configured)
	}
	if got.Free != 10 {
		t.Errorf("Free = %d, want 10 (garbled earlier value must be skipped, not fatal)", got.Free)
	}
	if got.PageSizeKB != 2048 {
		t.Errorf("PageSizeKB = %d, want 2048", got.PageSizeKB)
	}
	if got.Used != 54 {
		t.Errorf("Used = %d, want 54", got.Used)
	}
}

func TestIsHugePagesConfigured(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/meminfo", []byte(meminfoWithHugePages))
		})
		if !IsHugePagesConfigured() {
			t.Error("expected true when HugePages_Total > 0")
		}
	})
	t.Run("not configured", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/meminfo", []byte(meminfoNoHugePages))
		})
		if IsHugePagesConfigured() {
			t.Error("expected false when HugePages_Total = 0")
		}
	})
	t.Run("meminfo unreadable", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsHugePagesConfigured() {
			t.Error("expected false when meminfo is unreadable")
		}
	})
	t.Run("no HugePages_Total line", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/meminfo", []byte("MemTotal: 16384000 kB\n"))
		})
		if IsHugePagesConfigured() {
			t.Error("expected false when HugePages_Total line is missing")
		}
	})
}
