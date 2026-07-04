//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestParseRedisInfo(t *testing.T) {
	out := "# Server\r\n" +
		"redis_version:7.2.4\r\n" +
		"\r\n" + // blank line, skipped
		"# Memory\r\n" +
		"used_memory:1048576\r\n" +
		"maxmemory:0\r\n"
	kv := parseRedisInfo(out)
	if kv["redis_version"] != "7.2.4" {
		t.Errorf("redis_version = %q, want 7.2.4", kv["redis_version"])
	}
	if kv["used_memory"] != "1048576" {
		t.Errorf("used_memory = %q, want 1048576", kv["used_memory"])
	}
	if _, ok := kv["# Server"]; ok {
		t.Error("section header lines (starting with #) must not be parsed as key/value")
	}
}

// TestParsePortNum guards the port-number extraction from an IB sysfs port
// directory's base name (e.g. ".../ports/1" -> "1"), which is always a bare
// digit in real sysfs output.
func TestParsePortNum(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"1", 1},
		{"2", 2},
		{"", 0},
	}
	for _, c := range cases {
		if got := parsePortNum(c.s); got != c.want {
			t.Errorf("parsePortNum(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestParseNUMANode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/devices/system/node/node0/meminfo", []byte(
			"Node 0 MemTotal:       16777216 kB\n"+
				"Node 0 MemFree:         4194304 kB\n",
		))
		b.PutFile("/sys/devices/system/node/node0/cpulist", []byte("0-3,8\n"))
	})
	node := parseNUMANode("/sys/devices/system/node/node0")
	if node.ID != 0 {
		t.Errorf("node ID should be parsed from the path, got %d", node.ID)
	}
	if node.MemGB != 16 {
		t.Errorf("MemGB should be 16777216kB/1024/1024 = 16, got %v", node.MemGB)
	}
	if node.MemFreeGB != 4 {
		t.Errorf("MemFreeGB should be 4, got %v", node.MemFreeGB)
	}
	if len(node.CPUs) != 5 || node.CPUs[4] != 8 {
		t.Errorf("CPU list should expand the range plus the singleton, got %v", node.CPUs)
	}
}
