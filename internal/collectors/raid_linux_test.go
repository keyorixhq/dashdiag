//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// NOTE: withFixtureSource swaps a package-level global (activeSource) — these
// tests deliberately do NOT call t.Parallel(), matching the established
// convention in security_linux_source_test.go / nginx_linux_test.go.

func TestRAIDCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewRAIDCollector()
	if c.Name() != "RAID" {
		t.Errorf("Name() = %q, want RAID", c.Name())
	}
	if c.Timeout() != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", c.Timeout())
	}
}

func TestIsRAIDPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mdstat", []byte("Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n      976630464 blocks super 1.2 [2/2] [UU]\n\nunused devices: <none>\n"))
		})
		if !IsRAIDPresent() {
			t.Error("IsRAIDPresent() = false, want true")
		}
	})
	t.Run("absent - no array lines", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/mdstat", []byte("Personalities : \nunused devices: <none>\n"))
		})
		if IsRAIDPresent() {
			t.Error("IsRAIDPresent() = true, want false")
		}
	})
	t.Run("absent - file missing", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsRAIDPresent() {
			t.Error("IsRAIDPresent() = true, want false")
		}
	})
}

// TestRAIDCollector_Collect_NoMdstat guards the silent-OK gate: no
// /proc/mdstat (RAID subsystem unavailable) must return an empty RAIDInfo{},
// not an error.
func TestRAIDCollector_Collect_NoMdstat(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewRAIDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RAIDInfo)
	if len(info.Arrays) != 0 {
		t.Errorf("Arrays = %+v, want none", info.Arrays)
	}
}

// TestRAIDCollector_Collect_HealthyArray exercises the full read-through-
// openFile path with a real mdstat body.
func TestRAIDCollector_Collect_HealthyArray(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/mdstat", []byte(
			"Personalities : [raid1]\n"+
				"md0 : active raid1 sda1[0] sdb1[1]\n"+
				"      976630464 blocks super 1.2 [2/2] [UU]\n"+
				"\n"+
				"unused devices: <none>\n"))
	})
	c := NewRAIDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RAIDInfo)
	if len(info.Arrays) != 1 {
		t.Fatalf("Arrays = %+v, want 1", info.Arrays)
	}
	a := info.Arrays[0]
	if a.Name != "md0" || a.State != "active" || a.Active != 2 || a.Total != 2 {
		t.Errorf("Arrays[0] = %+v, want md0 active 2/2", a)
	}
}

// TestRAIDCollector_Collect_DegradedArray guards the degraded-state path end
// to end through Collect (not just the pure parser, already covered by
// TestParseMDStat_DegradedDroppedDisk).
func TestRAIDCollector_Collect_DegradedArray(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/mdstat", []byte(
			"Personalities : [raid1]\n"+
				"md0 : active raid1 sda1[0]\n"+
				"      976630464 blocks super 1.2 [2/1] [U_]\n"+
				"\n"+
				"unused devices: <none>\n"))
	})
	c := NewRAIDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RAIDInfo)
	if len(info.Arrays) != 1 || info.Arrays[0].State != "degraded" {
		t.Errorf("Arrays = %+v, want a single degraded array", info.Arrays)
	}
}

func TestParseMDStat_Healthy(t *testing.T) {
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976630464 blocks super 1.2 [2/2] [UU]

unused devices: <none>`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 1 {
		t.Fatalf("got %d arrays, want 1", len(info.Arrays))
	}
	a := info.Arrays[0]
	if a.State != "active" || a.Total != 2 || a.Active != 2 {
		t.Errorf("healthy array = %+v, want active 2/2", a)
	}
}

// The key regression: a degraded array whose failed disk fully DROPPED OUT —
// it isn't listed as "(F)" and active==total of the *listed* disks, so the old
// header-only logic read it as healthy. The [2/1] line is the authoritative
// signal.
func TestParseMDStat_DegradedDroppedDisk(t *testing.T) {
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0]
      976630464 blocks super 1.2 [2/1] [U_]

unused devices: <none>`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 1 {
		t.Fatalf("got %d arrays, want 1", len(info.Arrays))
	}
	a := info.Arrays[0]
	if a.State != "degraded" {
		t.Errorf("dropped-disk array State = %q, want degraded", a.State)
	}
	if a.Total != 2 || a.Active != 1 {
		t.Errorf("counts = %d/%d, want 1/2 (from [2/1])", a.Active, a.Total)
	}
}

func TestParseMDStat_Recovering(t *testing.T) {
	const mdstat = `Personalities : [raid1]
md1 : active raid1 sda2[2] sdb2[1]
      488254464 blocks super 1.2 [2/1] [U_]
      [===>.................]  recovery = 18.3% (89400448/488254464) finish=42.1min speed=100000K/sec

unused devices: <none>`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 1 {
		t.Fatalf("got %d arrays, want 1", len(info.Arrays))
	}
	a := info.Arrays[0]
	if a.State != "recovering" {
		t.Errorf("State = %q, want recovering (rebuild overrides degraded)", a.State)
	}
	if a.RebuildPct < 18.2 || a.RebuildPct > 18.4 {
		t.Errorf("RebuildPct = %.1f, want ~18.3", a.RebuildPct)
	}
}

func TestParseMDArrayCounts(t *testing.T) {
	cases := []struct {
		line          string
		total, active int
		ok            bool
	}{
		{"976630464 blocks super 1.2 [2/1] [U_]", 2, 1, true},
		{"976630464 blocks super 1.2 [2/2] [UU]", 2, 2, true},
		{"3906524672 blocks super 1.2 [4/3] [UUU_]", 4, 3, true},
		{"      [===>.................]  recovery = 18.3%", 0, 0, false}, // progress bar, no n/m
		{"md0 : active raid1 sda1[0] sdb1[1]", 0, 0, false},              // header, no [n/m]
		{"no brackets at all", 0, 0, false},
	}
	for _, c := range cases {
		total, active, ok := parseMDArrayCounts(c.line)
		if ok != c.ok || total != c.total || active != c.active {
			t.Errorf("parseMDArrayCounts(%q) = (%d,%d,%v), want (%d,%d,%v)",
				c.line, total, active, ok, c.total, c.active, c.ok)
		}
	}
}
