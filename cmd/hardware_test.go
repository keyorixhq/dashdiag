package cmd

import "testing"

// Guards the per-core thermal grading in `dsd hardware`. The "warm at low load" rung
// must NOT fire on a normal idle CPU (50-70°C) — that was a false-WARN found live on
// a bare-metal i7-6700 idling at 61°C — but must still flag a genuinely hot idle core
// (cooling fault) and the hard elevated/throttling ceilings.
func TestCoreThermalLevel(t *testing.T) {
	cases := []struct {
		name  string
		temp  int
		load  float64
		level string
	}{
		{"normal idle 61C is OK (was the false WARN)", 61, 10, "ok"},
		{"cool 45C is OK", 45, 5, "ok"},
		{"warm idle 78C is WARN (cooling fault)", 78, 10, "warn"},
		{"warm but busy 78C is OK — load explains it", 78, 60, "ok"},
		{"elevated 86C WARN regardless of load", 86, 90, "warn"},
		{"throttling 96C is fail", 96, 5, "fail"},
	}
	for _, c := range cases {
		if lvl, _ := coreThermalLevel(c.temp, c.load); lvl != c.level {
			t.Errorf("%s: coreThermalLevel(%d,%g)=%q want %q", c.name, c.temp, c.load, lvl, c.level)
		}
	}
}

// Guards `dsd hardware`'s drive-temperature grading, including the implausible-
// SMART rejection. The 11759°C case is the real value a VMware virtual NVMe drive
// reported live — the standalone command used to grade it as a thermal CRIT while
// `dsd health` correctly rejected the same SMART (§L). plausible=false must drive
// the "rejected" render, never a CRIT.
func TestDriveThermalLevel(t *testing.T) {
	cases := []struct {
		name      string
		temp      int
		nvme      bool
		level     string
		plausible bool
	}{
		{"nvme normal 40C", 40, true, "ok", true},
		{"nvme warm 72C warns", 72, true, "warn", true},
		{"nvme hot 85C fails", 85, true, "fail", true},
		{"sata normal 52C ok (was a false WARN)", 52, false, "ok", true},
		{"sata warm 56C warns", 56, false, "warn", true},
		{"sata 61C fails", 61, false, "fail", true},
		// The live VMware vNVMe garbage — must be rejected, not graded CRIT.
		{"vmware vNVMe 11759C is implausible", 11759, true, "info", false},
		{"just over the 125C ceiling is implausible", 126, true, "info", false},
		{"125C ceiling is still plausible", 125, true, "fail", true},
	}
	for _, c := range cases {
		level, plausible := driveThermalLevel(c.temp, c.nvme)
		if plausible != c.plausible {
			t.Errorf("%s: driveThermalLevel(%d,%v) plausible=%v want %v", c.name, c.temp, c.nvme, plausible, c.plausible)
		}
		if level != c.level {
			t.Errorf("%s: driveThermalLevel(%d,%v) level=%q want %q", c.name, c.temp, c.nvme, level, c.level)
		}
	}
}
