//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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
