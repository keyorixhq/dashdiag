package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// Characterization tests for the core memory / swap / PSI-pressure heuristics —
// high-frequency verdicts that run on every health check. Thresholds are driven
// off defaultThresh so the tests survive threshold-value changes and pin the
// *behavior* (warn vs crit boundary, container suppression, early returns).

// ── Memory ────────────────────────────────────────────────────────────────────

func TestCheckMemory(t *testing.T) {
	noCtr := platform.ContainerContext{}                  // not in a container
	inCtr := platform.ContainerContext{InContainer: true} // inside a container

	tests := []struct {
		name string
		mem  models.MemoryInfo
		ctr  platform.ContainerContext
		want string
	}{
		{"below warn is clean", models.MemoryInfo{UsedPct: 10, TotalGB: 16}, noCtr, ""},
		{"at warn threshold is WARN", models.MemoryInfo{UsedPct: defaultThresh.RAMWarnPct, TotalGB: 16, FreeGB: 3}, noCtr, "WARN"},
		{"at crit threshold is CRIT", models.MemoryInfo{UsedPct: defaultThresh.RAMCritPct, TotalGB: 16, FreeGB: 1}, noCtr, "CRIT"},
		{"overcommitted is CRIT only in strict mode (2)", models.MemoryInfo{UsedPct: 10, TotalGB: 16, OverCommitted: true, OvercommitMode: 2}, noCtr, "CRIT"},
		{"overcommitted in heuristic mode (0) is not flagged", models.MemoryInfo{UsedPct: 10, TotalGB: 16, OverCommitted: true, OvercommitMode: 0}, noCtr, ""},
		{"overcommitted in always-overcommit mode (1) is not flagged", models.MemoryInfo{UsedPct: 10, TotalGB: 16, OverCommitted: true, OvercommitMode: 1}, noCtr, ""},
		// SlabMB 4000 of 16 GB ≈ 24% > SlabWarnPct(20).
		{"high slab is WARN on host", models.MemoryInfo{UsedPct: 10, TotalGB: 16, SlabMB: 4000}, noCtr, "WARN"},
		{"high slab suppressed in container", models.MemoryInfo{UsedPct: 10, TotalGB: 16, SlabMB: 4000}, inCtr, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkMemory(tt.mem, defaultThresh, tt.ctr), tt.want)
		})
	}
}

// ── Swap ──────────────────────────────────────────────────────────────────────

func TestCheckSwap(t *testing.T) {
	tests := []struct {
		name string
		swap models.SwapInfo
		want string
	}{
		{"below warn is clean", models.SwapInfo{UsedPct: 10}, ""},
		{"usage at warn is WARN", models.SwapInfo{UsedPct: defaultThresh.SwapWarnPct, UsedGB: 2}, "WARN"},
		{"usage at crit is CRIT", models.SwapInfo{UsedPct: defaultThresh.SwapCritPct, UsedGB: 8}, "CRIT"},
		// SwapActivityWarn defaults to 0, so any paging is a WARN; >100 is CRIT.
		{"moderate paging is WARN", models.SwapInfo{UsedPct: 10, PagesInPerSec: 50}, "WARN"},
		{"heavy paging is CRIT", models.SwapInfo{UsedPct: 10, PagesInPerSec: 150}, "CRIT"},
		// macOS pressure path: MemPressureLevel>1 + high usage.
		{"darwin pressure level 2 high usage is WARN", models.SwapInfo{MemPressureLevel: 2, UsedPct: 80}, "WARN"},
		{"darwin pressure level 1 returns early clean", models.SwapInfo{MemPressureLevel: 1, UsedPct: 99}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSwap(tt.swap, defaultThresh), tt.want)
		})
	}
}

// ── PSI pressure ──────────────────────────────────────────────────────────────

func TestCheckPressure(t *testing.T) {
	tests := []struct {
		name string
		p    models.PressureInfo
		want string
	}{
		{"unavailable yields nothing", models.PressureInfo{Available: false, MemoryFull: models.PSILine{Avg60: 99}}, ""},
		{"available but quiet is clean", models.PressureInfo{Available: true}, ""},
		{"memory full stall is CRIT", models.PressureInfo{Available: true, MemoryFull: models.PSILine{Avg60: 15}}, "CRIT"},
		{"memory some stall is WARN", models.PressureInfo{Available: true, MemorySome: models.PSILine{Avg60: 25}}, "WARN"},
		{"io full stall is WARN", models.PressureInfo{Available: true, IOFull: models.PSILine{Avg60: 8}}, "WARN"},
		{"cpu some stall is WARN", models.PressureInfo{Available: true, CPUSome: models.PSILine{Avg60: 35}}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPressure(tt.p), tt.want)
		})
	}
}
