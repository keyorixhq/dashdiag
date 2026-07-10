//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNUMAImbalanced_MemorylessNodeDoesNotDisableCheck is a regression guard:
// a single memoryless node (CPU-only NUMA domain, e.g. a CXL memory-expander
// topology) used to zero the tracked minimum, and the minMem>0 guard then
// disabled the WHOLE imbalance comparison — even when the other, real
// memory-bearing nodes were genuinely imbalanced.
func TestNUMAImbalanced_MemorylessNodeDoesNotDisableCheck(t *testing.T) {
	nodes := []models.NUMANode{
		{ID: 0, MemGB: 64},
		{ID: 1, MemGB: 16}, // 64/16 = 4.0 > 1.4 — genuinely imbalanced
		{ID: 2, MemGB: 0},  // memoryless CPU-only node
	}
	if !numaImbalanced(nodes) {
		t.Error("expected imbalanced=true — the memoryless node must not mask the real 64/16 imbalance")
	}
}

// TestNUMAImbalanced_Balanced confirms evenly-sized nodes stay clean, memoryless
// node included.
func TestNUMAImbalanced_Balanced(t *testing.T) {
	nodes := []models.NUMANode{
		{ID: 0, MemGB: 32},
		{ID: 1, MemGB: 30},
		{ID: 2, MemGB: 0}, // memoryless
	}
	if numaImbalanced(nodes) {
		t.Error("expected imbalanced=false —32 vs 30 is within the 1.4x threshold")
	}
}

// TestNUMAImbalanced_OnlyOneMemoryNode confirms a single memory-bearing node
// (all others memoryless) has nothing to compare against and stays clean.
func TestNUMAImbalanced_OnlyOneMemoryNode(t *testing.T) {
	nodes := []models.NUMANode{
		{ID: 0, MemGB: 64},
		{ID: 1, MemGB: 0},
		{ID: 2, MemGB: 0},
	}
	if numaImbalanced(nodes) {
		t.Error("expected imbalanced=false — only one memory-bearing node, nothing to compare")
	}
}

// TestNUMAImbalanced_AllMemoryless confirms no panic/false-positive when every
// node is memoryless (fully unreadable meminfo across the board).
func TestNUMAImbalanced_AllMemoryless(t *testing.T) {
	nodes := []models.NUMANode{{ID: 0, MemGB: 0}, {ID: 1, MemGB: 0}}
	if numaImbalanced(nodes) {
		t.Error("expected imbalanced=false — no memory-bearing nodes at all")
	}
}

// TestNUMACollectorIdentity guards Name/Timeout. Not parallel-safe by itself,
// but has no fixture dependency — parallel is fine here.
func TestNUMACollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNUMACollector()
	if c.Name() != "NUMA" {
		t.Errorf("Name() = %q, want NUMA", c.Name())
	}
	if c.Timeout() != 3e9 {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// TestParseCPUList_RangeAndSingleton guards the range+singleton parser used
// to expand "0-3,8-11" style cpulist sysfs content.
func TestParseCPUList_RangeAndSingleton(t *testing.T) {
	t.Parallel()
	got := parseCPUList("0-3,8-11")
	want := []int{0, 1, 2, 3, 8, 9, 10, 11}
	if len(got) != len(want) {
		t.Fatalf("parseCPUList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseCPUList[%d] = %d, want %d", i, got[i], want[i])
		}
	}

	if got := parseCPUList("5"); len(got) != 1 || got[0] != 5 {
		t.Errorf("parseCPUList(single) = %v, want [5]", got)
	}
}

// TestParseNUMANode_FromFixture guards the per-node meminfo+cpulist parse:
// MemTotal/MemFree in kB converted to GB, and cpulist expanded.
func TestParseNUMANode_FromFixture(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/devices/system/node/node0/meminfo", []byte(
			"Node 0 MemTotal:       33554432 kB\n"+
				"Node 0 MemFree:        16777216 kB\n"+
				"Node 0 MemUsed:        16777216 kB\n",
		))
		b.PutFile("/sys/devices/system/node/node0/cpulist", []byte("0-3\n"))
	})
	node := parseNUMANode("/sys/devices/system/node/node0")
	if node.ID != 0 {
		t.Errorf("ID = %d, want 0", node.ID)
	}
	if node.MemGB != 32 {
		t.Errorf("MemGB = %v, want 32", node.MemGB)
	}
	if node.MemFreeGB != 16 {
		t.Errorf("MemFreeGB = %v, want 16", node.MemFreeGB)
	}
	if len(node.CPUs) != 4 || node.CPUs[0] != 0 || node.CPUs[3] != 3 {
		t.Errorf("CPUs = %v, want [0 1 2 3]", node.CPUs)
	}
}

// TestParseNUMANode_UnreadableMeminfo guards the graceful-degrade path: a
// missing meminfo/cpulist must not panic and must leave the numeric fields
// at zero value (memoryless node representation).
func TestParseNUMANode_UnreadableMeminfo(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // nothing seeded for node1
	node := parseNUMANode("/sys/devices/system/node/node1")
	if node.ID != 1 {
		t.Errorf("ID = %d, want 1", node.ID)
	}
	if node.MemGB != 0 || node.MemFreeGB != 0 {
		t.Errorf("expected zero-value mem fields, got MemGB=%v MemFreeGB=%v", node.MemGB, node.MemFreeGB)
	}
	if node.CPUs != nil {
		t.Errorf("expected nil CPUs, got %v", node.CPUs)
	}
}

// TestIsNUMAPresent guards the multi-node gate: >1 node → true, <=1 → false.
func TestIsNUMAPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/node/node[0-9]*", []string{
			"/sys/devices/system/node/node0",
			"/sys/devices/system/node/node1",
		})
	})
	if !IsNUMAPresent() {
		t.Error("expected IsNUMAPresent=true with 2 nodes")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/node/node[0-9]*", []string{
			"/sys/devices/system/node/node0",
		})
	})
	if IsNUMAPresent() {
		t.Error("expected IsNUMAPresent=false with a single node")
	}
}

// TestNUMACollector_Collect_SingleNode guards the "not interesting" early
// return: a single (or zero) NUMA node must leave Available=false with no
// per-node data collected.
func TestNUMACollector_Collect_SingleNode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/node/node[0-9]*", []string{
			"/sys/devices/system/node/node0",
		})
	})
	c := NewNUMACollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.NUMAInfo)
	if info.Available {
		t.Error("expected Available=false for a single-node system")
	}
	if info.NodeCount != 0 {
		t.Errorf("NodeCount = %d, want 0 (unset on early return)", info.NodeCount)
	}
}

// TestNUMACollector_Collect_MultiNode guards the full multi-node path end to
// end: NodeCount/Nodes/Imbalanced all populated from real fixture data.
func TestNUMACollector_Collect_MultiNode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/devices/system/node/node[0-9]*", []string{
			"/sys/devices/system/node/node0",
			"/sys/devices/system/node/node1",
		})
		b.PutFile("/sys/devices/system/node/node0/meminfo", []byte("Node 0 MemTotal:       67108864 kB\nNode 0 MemFree:        4194304 kB\n"))
		b.PutFile("/sys/devices/system/node/node0/cpulist", []byte("0-1\n"))
		b.PutFile("/sys/devices/system/node/node1/meminfo", []byte("Node 1 MemTotal:       16777216 kB\nNode 1 MemFree:        4194304 kB\n"))
		b.PutFile("/sys/devices/system/node/node1/cpulist", []byte("2-3\n"))
	})
	c := NewNUMACollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.NUMAInfo)
	if !info.Available || info.NodeCount != 2 {
		t.Fatalf("Available=%v NodeCount=%d, want true/2", info.Available, info.NodeCount)
	}
	if len(info.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(info.Nodes))
	}
	if !info.Imbalanced {
		t.Error("64GB vs 16GB should be flagged imbalanced (4.0x > 1.4x)")
	}
}
