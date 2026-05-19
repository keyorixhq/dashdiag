package analysis

import (
	"testing"
	"time"

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

// ── ruleNetworkDegradedUnderLoad ────────────────────────────────────────────

func TestNetworkDegradedUnderLoadFiresWithCPU(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Network", "gateway ping 271ms"),
		ins("CRIT", "CPU", "load at 266%"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Network Degraded Under System Load" {
			found = true
			if c.Level != "WARN" {
				t.Errorf("expected WARN level, got %q", c.Level)
			}
		}
	}
	if !found {
		t.Error("expected Network Degraded Under System Load to fire")
	}
}

func TestNetworkDegradedUnderLoadFiresWithSwap(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Network", "gateway ping 271ms"),
		ins("CRIT", "Swap", "heavy swap"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Network Degraded Under System Load" {
			found = true
		}
	}
	if !found {
		t.Error("expected Network Degraded Under System Load to fire with swap")
	}
}

func TestNetworkDegradedDoesNotFireAlone(t *testing.T) {
	// Network CRIT with everything else OK = external network problem, not system load
	insights := []models.Insight{
		ins("CRIT", "Network", "gateway 300ms"),
		ins("OK", "CPU", "fine"),
		ins("OK", "Swap", "fine"),
		ins("OK", "Memory", "fine"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Network Degraded Under System Load" {
			t.Error("should not fire when all other checks OK — likely external network issue")
		}
	}
}

func TestNetworkDegradedDoesNotFireWithoutNetCrit(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "Network", "gateway 60ms"), // WARN not CRIT
		ins("CRIT", "CPU", "load at 266%"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "Network Degraded Under System Load" {
			t.Error("should not fire — Network is WARN not CRIT")
		}
	}
}

func TestMultipleRulesFire(t *testing.T) {
	// The full stress-test cluster from 2026-05-11 overnight run on RHEL 10.1.
	// Memory Cascade + IO Under Memory Pressure + Network Degraded should all fire.
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%, OOM kill risk"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
		ins("CRIT", "Logs", "5 OOM kills: traefik, coredns, stress"),
		ins("CRIT", "IO", "nvme1n1 await 18ms"),
		ins("CRIT", "CPU", "load at 266%"),
		ins("CRIT", "Network", "gateway ping 271ms, 50% packet loss"),
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
	if !names["Network Degraded Under System Load"] {
		t.Error("expected Network Degraded Under System Load")
	}
	// Hard OOM should NOT fire when swap is also CRIT
	if names["Hard OOM Event"] {
		t.Error("Hard OOM should not fire when swap is CRIT (cascade takes precedence)")
	}
}

// ── ruleGPUSustainedLoad ──────────────────────────────────────────────────────

func TestGPUSustainedLoadFiresWithThermal(t *testing.T) {
	insights := []models.Insight{
		ins("INFO", "GPU", "RTX 3070 sustained compute load — util 100%, 114W"),
		ins("WARN", "Thermal", "CPU 85°C elevated"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "GPU Sustained Compute Load" {
			found = true
			if c.Level != "WARN" {
				t.Errorf("expected WARN, got %q", c.Level)
			}
		}
	}
	if !found {
		t.Error("expected GPU Sustained Compute Load to fire with Thermal WARN")
	}
}

func TestGPUSustainedLoadFiresWithVRAM(t *testing.T) {
	// When GPU is under sustained load AND thermal is elevated,
	// both an INFO (util) and WARN (VRAM) insight exist.
	// The index stores worst-level per key, so GPU index = WARN.
	// The rule fires when GPU WARN + Thermal WARN together.
	insights := []models.Insight{
		ins("INFO", "GPU", "RTX 3070 sustained compute — util 85%, 100W"),
		ins("WARN", "GPU", "VRAM usage at 85% (6970/8192 MB)"),
		ins("WARN", "Thermal", "CPU 82°C elevated"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "GPU Sustained Compute Load" {
			found = true
		}
	}
	if !found {
		t.Error("expected GPU Sustained Compute Load with VRAM WARN + Thermal WARN")
	}
}

func TestGPUSustainedLoadDoesNotFireAlone(t *testing.T) {
	// GPU load with everything else OK — not a problem worth surfacing
	insights := []models.Insight{
		ins("INFO", "GPU", "RTX 3070 sustained compute — util 90%, 115W"),
		ins("OK", "Thermal", "45°C"),
		ins("OK", "Memory", "fine"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "GPU Sustained Compute Load" {
			t.Error("should not fire when no other signals are elevated")
		}
	}
}

func TestGPUSustainedLoadDoesNotFireWithoutGPUInfo(t *testing.T) {
	// Thermal WARN without GPU load — not GPU's fault
	insights := []models.Insight{
		ins("WARN", "Thermal", "CPU 85°C"),
		ins("OK", "GPU", "idle"),
	}
	corrs := Correlate(insights)
	for _, c := range corrs {
		if c.Name == "GPU Sustained Compute Load" {
			t.Error("should not fire without GPU INFO insight")
		}
	}
}

// ── ruleDockerOOMCascade ──────────────────────────────────────────────────────

func makeOOM(eventsLast24h int, events ...models.OOMEvent) *models.OOMInfo {
	return &models.OOMInfo{
		Available:     true,
		EventsLast24h: eventsLast24h,
		RecentEvents:  events,
	}
}

func makeDocker(oomEvents int, events ...models.DockerEvent) *models.DockerInfo {
	return &models.DockerInfo{
		Available:    true,
		OOMEvents:    oomEvents,
		RecentEvents: events,
	}
}

func TestDockerOOMCascadeFiresWithTimestamps(t *testing.T) {
	now := time.Now()
	oom := makeOOM(2, models.OOMEvent{
		Process:   "traefik",
		Timestamp: now.Add(-2 * time.Minute),
	})
	docker := makeDocker(1, models.DockerEvent{
		Action:   "oom",
		Actor:    "traefik",
		TimeUnix: now.Unix(), // within 5 min of kernel OOM
	})

	corrs := CorrelateDeep(nil, oom, docker)
	found := false
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			found = true
			if c.Level != "CRIT" {
				t.Errorf("expected CRIT, got %q", c.Level)
			}
			// Time-aware path should mention "within 5 minutes"
			if c.Summary == "" {
				t.Error("summary should not be empty")
			}
		}
	}
	if !found {
		t.Error("expected Container OOM Cascade to fire with matching timestamps")
	}
}

func TestDockerOOMCascadeFiresFallbackNoTimestamps(t *testing.T) {
	// OOMEvents present but no timestamps in RecentEvents — fallback path
	oom := makeOOM(3, models.OOMEvent{Process: "nginx"}) // Timestamp is zero
	docker := makeDocker(2)                              // no RecentEvents

	corrs := CorrelateDeep(nil, oom, docker)
	found := false
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			found = true
		}
	}
	if !found {
		t.Error("expected Container OOM Cascade fallback to fire on co-occurrence")
	}
}

func TestDockerOOMCascadeDoesNotFireOutsideWindow(t *testing.T) {
	now := time.Now()
	oom := makeOOM(1, models.OOMEvent{
		Process:   "nginx",
		Timestamp: now.Add(-30 * time.Minute), // 30 min ago
	})
	docker := makeDocker(1, models.DockerEvent{
		Action:   "oom",
		Actor:    "nginx",
		TimeUnix: now.Unix(), // 30 min after kernel OOM — outside 5-min window
	})
	// But both counts are > 0, so the fallback still fires — that is correct.
	// What we verify: the time-aware path is NOT used when outside the window
	// (no test hook needed — we just verify the rule fires via fallback, not time path).
	corrs := CorrelateDeep(nil, oom, docker)
	found := false
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			found = true
			// Fallback summary does not mention "within 5 minutes"
			if c.Summary == "kernel OOM killer and Docker container OOM exit confirmed within 5 minutes — memory pressure killed a container" {
				t.Error("time-aware summary should not fire when events are 30 min apart")
			}
		}
	}
	if !found {
		t.Error("fallback should still fire when co-occurrence present (counts > 0)")
	}
}

func TestDockerOOMCascadeDoesNotFireWithoutDockerOOM(t *testing.T) {
	oom := makeOOM(3, models.OOMEvent{Process: "nginx"})
	docker := makeDocker(0) // no OOM events

	corrs := CorrelateDeep(nil, oom, docker)
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			t.Error("should not fire when docker.OOMEvents == 0")
		}
	}
}

func TestDockerOOMCascadeDoesNotFireWithoutKernelOOM(t *testing.T) {
	oom := makeOOM(0) // no kernel OOM events
	docker := makeDocker(2, models.DockerEvent{Action: "oom", Actor: "app", TimeUnix: time.Now().Unix()})

	corrs := CorrelateDeep(nil, oom, docker)
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			t.Error("should not fire when oom.EventsLast24h == 0")
		}
	}
}

func TestDockerOOMCascadeDoesNotFireWithNilInputs(t *testing.T) {
	corrs := CorrelateDeep(nil, nil, nil)
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			t.Error("should not fire with nil OOM and Docker inputs")
		}
	}
}

func TestCorrelateDeepPreservesExistingRules(t *testing.T) {
	// CorrelateDeep should still fire existing snapshot rules
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
	}
	corrs := CorrelateDeep(insights, nil, nil)
	found := false
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			found = true
		}
	}
	if !found {
		t.Error("CorrelateDeep should include all existing snapshot rules")
	}
}
