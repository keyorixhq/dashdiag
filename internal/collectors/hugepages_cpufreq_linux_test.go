//go:build linux

package collectors

import (
	"testing"
)

// ── HugePages tests ──────────────────────────────────────────────────────────

const meminfoWithHugePages = `MemTotal:       16384000 kB
MemFree:         8192000 kB
HugePages_Total:     512
HugePages_Free:      400
HugePages_Rsvd:        0
Hugepagesize:       2048 kB
AnonHugePages:    524288 kB
`

const meminfoNoHugePages = `MemTotal:       16384000 kB
MemFree:         8192000 kB
HugePages_Total:       0
HugePages_Free:        0
Hugepagesize:       2048 kB
`

func TestParseHugePagesMeminfo(t *testing.T) {
	t.Run("static huge pages configured", func(t *testing.T) {
		info := parseHugePagesMeminfo(meminfoWithHugePages)
		if info.Configured != 512 {
			t.Errorf("Configured = %d, want 512", info.Configured)
		}
		if info.Free != 400 {
			t.Errorf("Free = %d, want 400", info.Free)
		}
		if info.Used != 112 {
			t.Errorf("Used = %d, want 112 (512-400)", info.Used)
		}
		if info.PageSizeKB != 2048 {
			t.Errorf("PageSizeKB = %d, want 2048", info.PageSizeKB)
		}
		// 512 * 2048 kB / (1024*1024) = 1.0 GB
		if info.ReservedGB < 0.9 || info.ReservedGB > 1.1 {
			t.Errorf("ReservedGB = %f, want ~1.0", info.ReservedGB)
		}
	})

	t.Run("no huge pages configured", func(t *testing.T) {
		info := parseHugePagesMeminfo(meminfoNoHugePages)
		if info.Configured != 0 {
			t.Errorf("Configured = %d, want 0", info.Configured)
		}
		if info.ReservedGB != 0 {
			t.Errorf("ReservedGB = %f, want 0", info.ReservedGB)
		}
	})
}

// ── CPUFreq tests ────────────────────────────────────────────────────────────

func TestParseCPUFreqGovernor(t *testing.T) {
	cases := []struct{ in, want string }{
		{"performance\n", "performance"},
		{"powersave\n", "powersave"},
		{"schedutil\n", "schedutil"},
		{"ondemand\n", "ondemand"},
		{"  conservative  \n", "conservative"},
	}
	for _, c := range cases {
		got := parseCPUFreqGovernor(c.in)
		if got != c.want {
			t.Errorf("parseCPUFreqGovernor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseCPUFreqKHz(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"4465000\n", 4465000},
		{"2400000\n", 2400000},
		{"400000\n", 400000},
		{"0\n", 0},
	}
	for _, c := range cases {
		got := parseCPUFreqKHz(c.in)
		if got != c.want {
			t.Errorf("parseCPUFreqKHz(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
