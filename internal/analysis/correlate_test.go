package analysis

import (
	"strings"
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
		// "CPU Load" is the real check name the CPU collector emits (not a bare
		// "CPU"). This is the regression test for the rule keying on the wrong
		// CPU index key — before the fix it indexed under "cpu" only, so a real
		// high CPU load never triggered this correlation.
		ins("CRIT", "CPU Load", "load at 266%"),
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
		ins("WARN", "CPU Thermal", "CPU 92°C"),
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
		ins("WARN", "CPU Thermal", "CPU 85°C elevated"),
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
		ins("WARN", "CPU Thermal", "CPU 82°C elevated"),
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
		ins("OK", "CPU Thermal", "45°C"),
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
		ins("WARN", "CPU Thermal", "CPU 85°C"),
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

	corrs := CorrelateDeep(nil, oom, docker, nil, nil)
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

	corrs := CorrelateDeep(nil, oom, docker, nil, nil)
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
	corrs := CorrelateDeep(nil, oom, docker, nil, nil)
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

	corrs := CorrelateDeep(nil, oom, docker, nil, nil)
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			t.Error("should not fire when docker.OOMEvents == 0")
		}
	}
}

func TestDockerOOMCascadeDoesNotFireWithoutKernelOOM(t *testing.T) {
	oom := makeOOM(0) // no kernel OOM events
	docker := makeDocker(2, models.DockerEvent{Action: "oom", Actor: "app", TimeUnix: time.Now().Unix()})

	corrs := CorrelateDeep(nil, oom, docker, nil, nil)
	for _, c := range corrs {
		if c.Name == "Container OOM Cascade" {
			t.Error("should not fire when oom.EventsLast24h == 0")
		}
	}
}

func TestDockerOOMCascadeDoesNotFireWithNilInputs(t *testing.T) {
	corrs := CorrelateDeep(nil, nil, nil, nil, nil)
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
	corrs := CorrelateDeep(insights, nil, nil, nil, nil)
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

func makeIO(devices ...models.IODeviceInfo) *models.IOInfo {
	return &models.IOInfo{Devices: devices}
}

func makeSysctl(uptimeSec int64, swappiness int) *models.SysctlInfo {
	return &models.SysctlInfo{
		Available:     true,
		UptimeSeconds: uptimeSec,
		VMSwappiness:  swappiness,
	}
}

// ── ruleEntropyTLSFailure ─────────────────────────────────────────────────

func TestEntropyTLSFailureFires(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Entropy", "entropy pool critically low (32 bits)"),
		ins("WARN", "TLS", "2 certificate(s) expiring within 30 days"),
	}
	corrs := Correlate(insights)
	found := false
	for _, c := range corrs {
		if c.Name == "Entropy Starvation with TLS Active" {
			found = true
			if c.Level != "CRIT" {
				t.Errorf("expected CRIT, got %q", c.Level)
			}
		}
	}
	if !found {
		t.Error("expected Entropy Starvation with TLS Active to fire")
	}
}

func TestEntropyTLSFailureDoesNotFireWithoutTLS(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Entropy", "entropy pool critically low"),
		// no TLS insight
	}
	for _, c := range Correlate(insights) {
		if c.Name == "Entropy Starvation with TLS Active" {
			t.Error("should not fire without TLS signal")
		}
	}
}

func TestEntropyTLSFailureDoesNotFireWithoutEntropy(t *testing.T) {
	insights := []models.Insight{
		ins("WARN", "TLS", "1 certificate expiring"),
		// no Entropy insight
	}
	for _, c := range Correlate(insights) {
		if c.Name == "Entropy Starvation with TLS Active" {
			t.Error("should not fire without Entropy signal")
		}
	}
}

// ── ruleIOSingleDeviceDegradation ────────────────────────────────────────

func TestIOSingleDeviceDegradationFires(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 45.0, UtilPct: 92.0}, // degraded
		models.IODeviceInfo{Name: "sdb", AwaitMs: 1.2, UtilPct: 15.0},  // healthy peer
	)
	c, ok := ruleIOSingleDeviceDegradation(io)
	if !ok {
		t.Fatal("expected rule to fire")
	}
	if c.Level != "CRIT" {
		t.Errorf("expected CRIT, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "sda") {
		t.Errorf("summary should name the degraded device, got: %q", c.Summary)
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWithOnlyOneDevice(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 50.0, UtilPct: 95.0},
	)
	if _, ok := ruleIOSingleDeviceDegradation(io); ok {
		t.Error("should not fire with only one device")
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWhenBothDegraded(t *testing.T) {
	io := makeIO(
		models.IODeviceInfo{Name: "sda", AwaitMs: 45.0, UtilPct: 92.0},
		models.IODeviceInfo{Name: "sdb", AwaitMs: 30.0, UtilPct: 88.0}, // both degraded
	)
	if _, ok := ruleIOSingleDeviceDegradation(io); ok {
		t.Error("should not fire when both devices are degraded (subsystem overload, not single drive)")
	}
}

func TestIOSingleDeviceDegradationDoesNotFireWithNilIO(t *testing.T) {
	if _, ok := ruleIOSingleDeviceDegradation(nil); ok {
		t.Error("should not fire with nil IOInfo")
	}
}

// ── ruleSysctlNotPersisted ────────────────────────────────────────────────

func TestSysctlNotPersistedFires(t *testing.T) {
	sysctl := makeSysctl(1800, 100) // 30 min uptime, swappiness=100 (bad)
	insights := []models.Insight{
		ins("WARN", "Sysctl", "vm.swappiness=100 is high for a server"),
	}
	idx := buildIndex(insights)
	c, ok := ruleSysctlNotPersisted(sysctl, idx)
	if !ok {
		t.Fatal("expected rule to fire")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "30 minute") {
		t.Errorf("summary should include uptime in minutes, got: %q", c.Summary)
	}
}

func TestSysctlNotPersistedDoesNotFireAfterOneHour(t *testing.T) {
	sysctl := makeSysctl(7200, 100) // 2 hours uptime
	insights := []models.Insight{
		ins("WARN", "Sysctl", "vm.swappiness=100 is high"),
	}
	idx := buildIndex(insights)
	if _, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		t.Error("should not fire when uptime >= 1 hour (not a recent reboot)")
	}
}

func TestSysctlNotPersistedDoesNotFireWhenSysctlOK(t *testing.T) {
	sysctl := makeSysctl(300, 10) // 5 min uptime, but sysctl is fine
	idx := buildIndex(nil)        // no sysctl insights
	if _, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		t.Error("should not fire when sysctl has no WARN/CRIT")
	}
}

func TestSysctlNotPersistedDoesNotFireWithNilSysctl(t *testing.T) {
	insights := []models.Insight{ins("WARN", "Sysctl", "bad param")}
	idx := buildIndex(insights)
	if _, ok := ruleSysctlNotPersisted(nil, idx); ok {
		t.Error("should not fire with nil SysctlInfo")
	}
}

// BUG-023 follow-up: a freshly booted box at the kernel stock default
// (swappiness=60) raises a workload Sysctl WARN, but that is the out-of-the-box
// value, not a sysctl -w that failed to persist. The correlation must not narrate
// a non-existent lost fix.
func TestSysctlNotPersistedDoesNotFireOnStockDefaults(t *testing.T) {
	sysctl := makeSysctl(180, 60) // 3 min uptime, swappiness=60 (stock default)
	insights := []models.Insight{
		ins("WARN", "Sysctl", "vm.swappiness=60 is high for k8s node (recommended: <= 10)"),
	}
	idx := buildIndex(insights)
	if _, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		t.Error("should not fire when flagged values are at kernel stock defaults (fresh boot, not a lost fix)")
	}
}

// ── CorrelateDeep nil-safety for new params ──────────────────────────────

func TestCorrelateDeepNewParamsNilSafe(t *testing.T) {
	// Must not panic with nil for the new parameters
	corrs := CorrelateDeep(nil, nil, nil, nil, nil)
	_ = corrs // any result is fine, just must not panic
}

func TestCorrelateDeepPreservesExistingRulesWithNewParams(t *testing.T) {
	insights := []models.Insight{
		ins("CRIT", "Memory", "RAM at 97%"),
		ins("CRIT", "Swap", "heavy swap activity: 29979 pages/s"),
		ins("CRIT", "Processes", "5 hung processes"),
	}
	corrs := CorrelateDeep(insights, nil, nil, nil, nil)
	found := false
	for _, c := range corrs {
		if c.Name == "Memory Pressure Cascade" {
			found = true
		}
	}
	if !found {
		t.Error("CorrelateDeep must still fire existing rules after signature change")
	}
}

// ── ruleServiceMemoryLeak ─────────────────────────────────────────────────

func TestServiceMemoryLeakFires(t *testing.T) {
	oom := makeOOM(3,
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "redis-server"},
	)
	// nginx killed twice — should fire
	c, ok := ruleServiceMemoryLeak(oom)
	if !ok {
		t.Fatal("expected rule to fire when same process killed 2+ times")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "nginx") {
		t.Errorf("summary should name the leaking process, got: %q", c.Summary)
	}
	if !strings.Contains(c.Summary, "2 times") {
		t.Errorf("summary should state kill count, got: %q", c.Summary)
	}
}

func TestServiceMemoryLeakDoesNotFireWhenAllDifferent(t *testing.T) {
	oom := makeOOM(3,
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "redis-server"},
		models.OOMEvent{Process: "postgres"},
	)
	// All different — general pressure, not a leak
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire when all OOM kills are different processes")
	}
}

func TestServiceMemoryLeakDoesNotFireWithOnlyOneEvent(t *testing.T) {
	oom := makeOOM(1, models.OOMEvent{Process: "nginx"})
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire with only one OOM event")
	}
}

func TestServiceMemoryLeakDoesNotFireWithNilOOM(t *testing.T) {
	if _, ok := ruleServiceMemoryLeak(nil); ok {
		t.Error("should not fire with nil OOMInfo")
	}
}

func TestServiceMemoryLeakDoesNotFireWithNoNamedProcesses(t *testing.T) {
	// Events with empty process names should be ignored
	oom := makeOOM(3,
		models.OOMEvent{Process: ""},
		models.OOMEvent{Process: ""},
		models.OOMEvent{Process: ""},
	)
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire when process names are all empty")
	}
}

// ── ruleRunQueueSaturation ────────────────────────────────────────────────

func TestRunQueueSaturationFires(t *testing.T) {
	// Run queue saturated, no iowait, no steal → genuinely CPU-bound.
	insights := []models.Insight{
		ins("WARN", "CPU/RunQueue", "16 runnable tasks on 4 CPUs"),
	}
	idx := buildIndex(insights)
	c, ok := ruleRunQueueSaturation(idx)
	if !ok {
		t.Fatal("expected rule to fire")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "CPU-bound") {
		t.Errorf("summary should call out CPU-bound, got: %q", c.Summary)
	}
}

func TestRunQueueSaturationSuppressedByIOWait(t *testing.T) {
	// Saturated run queue but high iowait — that's I/O-driven load, not CPU shortage.
	insights := []models.Insight{
		ins("WARN", "CPU/RunQueue", "saturated"),
		ins("WARN", "CPU/IOWait", "I/O wait at 30%"),
	}
	idx := buildIndex(insights)
	if _, ok := ruleRunQueueSaturation(idx); ok {
		t.Error("should not fire when iowait explains the load")
	}
}

func TestRunQueueSaturationSuppressedBySteal(t *testing.T) {
	// Saturated run queue but high steal — hypervisor theft, not local CPU shortage.
	insights := []models.Insight{
		ins("WARN", "CPU/RunQueue", "saturated"),
		ins("CRIT", "CPU/Steal", "steal at 25%"),
	}
	idx := buildIndex(insights)
	if _, ok := ruleRunQueueSaturation(idx); ok {
		t.Error("should not fire when steal explains the load")
	}
}

func TestRunQueueSaturationDoesNotFireWhenHealthy(t *testing.T) {
	idx := buildIndex([]models.Insight{ins("OK", "CPU Load", "fine")})
	if _, ok := ruleRunQueueSaturation(idx); ok {
		t.Error("should not fire without a CPU/RunQueue WARN/CRIT")
	}
}
