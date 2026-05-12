package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// helpers

func ins(level, check, msg string) models.Insight {
	return models.Insight{Level: level, Check: check, Message: msg}
}

// ── indexKeys ────────────────────────────────────────────────────────────────

func TestIndexKeysSimple(t *testing.T) {
	got := indexKeys("Memory")
	if len(got) != 1 || got[0] != "memory" {
		t.Errorf("indexKeys(Memory) = %v, want [memory]", got)
	}
}

func TestIndexKeysSlash(t *testing.T) {
	got := indexKeys("Memory/Slab")
	want := map[string]bool{"memory/slab": true, "memory": true}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected key %q in indexKeys(Memory/Slab)", k)
		}
	}
	if len(got) != 2 {
		t.Errorf("indexKeys(Memory/Slab) len = %d, want 2", len(got))
	}
}

// ── buildIndex ───────────────────────────────────────────────────────────────

func TestBuildIndexWorstWins(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "Memory", "warn first"),
		ins("CRIT", "Memory", "crit second"),
		ins("OK", "Memory", "ok third"),
	}
	idx := buildIndex(insights)
	if e := idx["memory"]; e.level != "CRIT" {
		t.Errorf("expected CRIT, got %q", e.level)
	}
}

func TestBuildIndexSlashRollsUp(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory/Slab", "slab full"),
	}
	idx := buildIndex(insights)
	if e := idx["memory"]; e.level != "CRIT" {
		t.Errorf("Memory/Slab CRIT should roll up to memory, got %q", e.level)
	}
	if e := idx["memory/slab"]; e.level != "CRIT" {
		t.Errorf("memory/slab should be indexed, got %q", e.level)
	}
}

// ── Correlate — no signals ───────────────────────────────────────────────────

func TestCorrelateEmpty(t *testing.T) {
	if got := Correlate(nil); got != nil {
		t.Errorf("Correlate(nil) = %v, want nil", got)
	}
}

func TestCorrelateAllOK(t *testing.T) {
	insights := []models.Insight{
		ins("OK", "Memory", "fine"),
		ins("OK", "Swap", "fine"),
		ins("OK", "CPU", "fine"),
	}
	if got := Correlate(insights); len(got) != 0 {
		t.Errorf("all-OK insights should produce no correlations, got %v", got)
	}
}

// ── ruleMemoryCascade ────────────────────────────────────────────────────────

func TestMemoryCascadeFiresWithHungProcesses(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
	}
	corrs := Correlate(insights)
	if len(corrs) == 0 {
		t.Fatal("expected Memory Pressure Cascade to fire")
	}
	if corrs[0].Name != "Memory Pressure Cascade" {
		t.Errorf("got name %q", corrs[0].Name)
	}
	if corrs[0].Level != "CRIT" {
		t.Errorf("got level %q, want CRIT", corrs[0].Level)
	}
}

func TestMemoryCascadeFiresWithOOMKills(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "Memory", "RAM at 85%"),
		ins("CRIT", "Swap", "heavy swap"),
		ins("CRIT", "Logs", "3 OOM kills"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			found = true
		}
	}
	if !found {
		t.Error("expected Memory Pressure Cascade with WARN Memory + CRIT Swap + CRIT Logs")
	}
}

func TestMemoryCascadeDoesNotFireWithoutSwapCrit(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("WARN", "Swap", "swap usage 60%"), // WARN, not CRIT
		ins("CRIT", "Processes", "5 hung"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			t.Error("cascade should not fire — swap is WARN not CRIT")
		}
	}
}

func TestMemoryCascadeDoesNotFireWithoutMemory(t *testing.T) {
	insights := []models.Insight{
		ins("OK", "Memory", "fine"),
		ins("CRIT", "Swap", "heavy swap"),
		ins("CRIT", "Processes", "5 hung"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			t.Error("cascade should not fire — memory is OK")
		}
	}
}

// ── ruleHardOOM ──────────────────────────────────────────────────────────────

func TestHardOOMFires(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 98%"),
		ins("CRIT", "Logs", "5 OOM kills"),
		ins("WARN", "Swap", "swap usage 40%"), // not CRIT
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Hard OOM Event" {
			found = true
		}
	}
	if !found {
		t.Error("expected Hard OOM Event to fire")
	}
}

func TestHardOOMDoesNotFireWhenSwapCrit(t *testing.T) {
	// When swap IS critical, MemoryCascade fires instead — not HardOOM
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 98%"),
		ins("CRIT", "Logs", "5 OOM kills"),
		ins("CRIT", "Swap", "heavy swap"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Hard OOM Event" {
			t.Error("Hard OOM should not fire when swap is also CRIT")
		}
	}
}

func TestHardOOMDoesNotFireWithoutMemoryCrit(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "Memory", "RAM at 75%"),
		ins("CRIT", "Logs", "1 OOM kill"),
		ins("OK", "Swap", "fine"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Hard OOM Event" {
			t.Error("Hard OOM should not fire — Memory is WARN not CRIT")
		}
	}
}

// ── ruleIOUnderMemoryPressure ────────────────────────────────────────────────

func TestIOUnderMemPressureFires(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "IO", "nvme await 18ms"),
		ins("WARN", "Memory", "RAM at 85%"),
		ins("CRIT", "Swap", "heavy swap"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "IO Stall Under Memory Pressure" {
			found = true
		}
	}
	if !found {
		t.Error("expected IO Stall Under Memory Pressure to fire")
	}
}

func TestIOUnderMemPressureDoesNotFireWithoutIOCrit(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "IO", "nvme await 6ms"), // WARN not CRIT
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("CRIT", "Swap", "heavy swap"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "IO Stall Under Memory Pressure" {
			t.Error("should not fire — IO is WARN not CRIT")
		}
	}
}

// ── multiple rules can fire simultaneously ───────────────────────────────────

func TestMultipleRulesFire(t *testing.T) {
	// The full stress-test cluster from 2026-05-11 overnight run on RHEL 10.1.
	// Memory Cascade + IO Under Memory Pressure should both fire.
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%, OOM kill risk"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
		ins("CRIT", "Logs", "5 OOM kills: traefik, coredns, stress"),
		ins("CRIT", "IO", "nvme1n1 await 18ms"),
		ins("CRIT", "CPU", "load at 266%"),
		ins("WARN", "Thermal", "CPU 92°C"),
	}
	corrs := Correlate(insights)
	names := make(map[string]bool)
	for _, c := range corrs {
		names[c.Name] = true
	}
	if !names["Memory Pressure Cascade"] {
		t.Error("expected Memory Pressure Cascade")
	}
	if !names["IO Stall Under Memory Pressure"] {
		t.Error("expected IO Stall Under Memory Pressure")
	}
	// Hard OOM should NOT fire when swap is also CRIT
	if names["Hard OOM Event"] {
		t.Error("Hard OOM should not fire when swap is CRIT (cascade takes precedence)")
	}
}
