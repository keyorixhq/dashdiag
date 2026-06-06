//go:build linux

package collectors

import (
	"strings"
	"testing"
)

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
