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
