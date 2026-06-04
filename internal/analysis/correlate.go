package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Correlation is a diagnosed cause inferred from multiple simultaneous signals.
// v0: hardcoded ruleset. v1: history-aware pattern matching across snapshots.
type Correlation struct {
	Name    string   // short rule name, e.g. "Memory Pressure Cascade"
	Level   string   // CRIT or WARN — severity of the diagnosed pattern
	Summary string   // human-readable cause sentence shown in the summary block
	Action  string   // single most important next step
	Checks  []string // which Check names contributed to this diagnosis
}

// Correlate inspects a set of insights from a single snapshot and returns any
// diagnosed patterns. Returns nil when no rules fire (healthy or sparse signals).
func Correlate(insights []models.Insight) []Correlation {
	if len(insights) == 0 {
		return nil
	}

	idx := buildIndex(insights)
	var out []Correlation

	if c, ok := ruleMemoryCascade(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleHardOOM(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleIOUnderMemoryPressure(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleNetworkDegradedUnderLoad(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleGPUSustainedLoad(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleIODrivenLoad(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleCPUStealUnderLoad(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleDBusCascade(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleEntropyTLSFailure(idx); ok {
		out = append(out, c)
	}

	return out
}

// indexEntry holds the highest-severity insight for a given Check prefix.
type indexEntry struct {
	level   string // CRIT, WARN, INFO, OK
	message string
}

// buildIndex maps each Check name (lowercased, base prefix before "/") to its
// worst insight level. "Memory/Slab" is indexed under both "memory/slab" and "memory".
func buildIndex(insights []models.Insight) map[string]indexEntry {
	order := map[string]int{"CRIT": 3, "WARN": 2, "INFO": 1, "OK": 0}
	idx := make(map[string]indexEntry, len(insights))

	for _, ins := range insights {
		keys := indexKeys(ins.Check)
		for _, k := range keys {
			cur, exists := idx[k]
			if !exists || order[ins.Level] > order[cur.level] {
				idx[k] = indexEntry{level: ins.Level, message: ins.Message}
			}
		}
	}
	return idx
}

// indexKeys returns the lookup keys for a Check string.
// "Memory/Slab" → ["memory/slab", "memory"]
// "IO" → ["io"]
func indexKeys(check string) []string {
	lower := strings.ToLower(check)
	keys := []string{lower}
	if i := strings.Index(lower, "/"); i > 0 {
		keys = append(keys, lower[:i])
	}
	return keys
}

// atLeast returns true when the indexed entry for key is at or above minLevel.
func atLeast(idx map[string]indexEntry, key, minLevel string) bool {
	order := map[string]int{"CRIT": 3, "WARN": 2, "INFO": 1, "OK": 0}
	e, ok := idx[strings.ToLower(key)]
	if !ok {
		return false
	}
	return order[e.level] >= order[minLevel]
}

// exact returns true when the indexed entry for key is exactly level.
func exact(idx map[string]indexEntry, key, level string) bool {
	e, ok := idx[strings.ToLower(key)]
	return ok && e.level == level
}

// ── Rules ────────────────────────────────────────────────────────────────────
//
// Each rule is a pure function: (index) → (Correlation, fired bool).
// Add new rules here. Rule functions must not produce side effects.

// ruleMemoryCascade fires when RAM pressure, swap thrashing, and process
// stalls appear together — the canonical "memory pressure cascade" pattern
// first observed during the 2026-05-11 overnight stress test on RHEL 10.1.
//
// Required signals:
//   - Memory WARN or CRIT  (RAM exhaustion)
//   - Swap CRIT            (heavy swap activity — pages/s threshold crossed)
//   - Processes CRIT       (hung/uninterruptible — blocked on I/O during swap)
//     OR Logs CRIT         (OOM kills already happened)
func ruleMemoryCascade(idx map[string]indexEntry) (Correlation, bool) {
	memFired := atLeast(idx, "Memory", "WARN")
	swapCrit := exact(idx, "Swap", "CRIT")
	processesCrit := exact(idx, "Processes", "CRIT")
	logsCrit := exact(idx, "Logs", "CRIT")

	if !memFired || !swapCrit || (!processesCrit && !logsCrit) {
		return Correlation{}, false
	}

	checks := []string{"Memory", "Swap"}
	if processesCrit {
		checks = append(checks, "Processes")
	}
	if logsCrit {
		checks = append(checks, "Logs")
	}

	return Correlation{
		Name:    "Memory Pressure Cascade",
		Level:   "CRIT",
		Summary: "RAM exhaustion forced swap thrashing — processes stalled waiting for pages to free up",
		Action:  "find the memory hog: ps aux --sort=-%mem | head -10",
		Checks:  checks,
	}, true
}

// ruleHardOOM fires when OOM kills happened but swap was not a factor —
// the system hit a hard memory wall with no buffer.
//
// Required signals:
//   - Memory CRIT  (RAM at critical level)
//   - Logs CRIT    (OOM kills recorded)
//   - Swap NOT CRIT (swap wasn't the pressure valve — it wasn't being hit hard)
func ruleHardOOM(idx map[string]indexEntry) (Correlation, bool) {
	memCrit := exact(idx, "Memory", "CRIT")
	logsCrit := exact(idx, "Logs", "CRIT")
	swapNotCrit := !exact(idx, "Swap", "CRIT")

	if !memCrit || !logsCrit || !swapNotCrit {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Hard OOM Event",
		Level:   "CRIT",
		Summary: "Processes killed directly — memory hit a hard ceiling with no swap acting as a buffer",
		Action:  "check which processes were killed: dmesg | grep -i 'out of memory'",
		Checks:  []string{"Memory", "Logs"},
	}, true
}

// ruleIOUnderMemoryPressure fires when IO stalls are amplified by concurrent
// memory pressure — the kernel is both handling I/O and evicting pages,
// causing processes to wait in uninterruptible sleep (D state) longer than usual.
//
// Required signals:
//   - IO CRIT          (await latency past critical threshold)
//   - Memory WARN/CRIT (RAM pressure active)
//   - Swap CRIT        (kernel actively moving pages — competes with I/O scheduler)
func ruleIOUnderMemoryPressure(idx map[string]indexEntry) (Correlation, bool) {
	ioCrit := exact(idx, "IO", "CRIT")
	memFired := atLeast(idx, "Memory", "WARN")
	swapCrit := exact(idx, "Swap", "CRIT")

	if !ioCrit || !memFired || !swapCrit {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "IO Stall Under Memory Pressure",
		Level:   "CRIT",
		Summary: "Disk latency spiked while kernel is swapping — page eviction and I/O compete for the same storage bandwidth",
		Action:  "check what is swapping: vmstat 1 5 && iotop -ao",
		Checks:  []string{"IO", "Memory", "Swap"},
	}, true
}

// ruleNetworkDegradedUnderLoad fires when network latency is critically high
// and the system is simultaneously under CPU or memory pressure — suggesting
// the kernel scheduler is starved for cycles to service network interrupts,
// or network buffers are filling due to lack of processing headroom.
//
// Validated on RHEL 10.1 during overnight stress test (2026-05-11): gateway
// latency hit 271ms and packet loss 50% during CPU/swap stress windows.
// The tc netem delay (200ms injected) compound with kernel starvation.
//
// Required signals:
//   - Network CRIT (gateway latency or packet loss past critical threshold)
//   - CPU CRIT or WARN, OR Swap CRIT (system under load — not a pure network fault)
func ruleNetworkDegradedUnderLoad(idx map[string]indexEntry) (Correlation, bool) {
	netCrit := exact(idx, "Network", "CRIT")
	cpuLoaded := atLeast(idx, "CPU", "WARN")
	swapCrit := exact(idx, "Swap", "CRIT")
	memCrit := exact(idx, "Memory", "CRIT")

	if !netCrit {
		return Correlation{}, false
	}
	// Only diagnose if system load explains the network degradation.
	// If everything else is fine, the network issue is likely external.
	if !cpuLoaded && !swapCrit && !memCrit {
		return Correlation{}, false
	}

	summary := "Network latency spiked under system load — kernel may be starved for cycles to service interrupts"
	action := "check if load clears first: uptime && ping -c5 $(ip route | awk '/default/{print $3}')"

	checks := []string{"Network"}
	if cpuLoaded {
		checks = append(checks, "CPU")
	}
	if swapCrit {
		checks = append(checks, "Swap")
	}
	if memCrit {
		checks = append(checks, "Memory")
	}

	return Correlation{
		Name:    "Network Degraded Under System Load",
		Level:   "WARN",
		Summary: summary,
		Action:  action,
		Checks:  checks,
	}, true
}

// ruleGPUSustainedLoad fires when GPU is under heavy sustained compute load
// AND another system signal is degraded — providing context that the GPU
// workload may be contributing to thermal or memory pressure.
//
// This is an INFO-level correlation — GPU compute is not a fault.
// The value is explaining WHY thermal or memory is elevated.
//
// Validated on RHEL 10.1 overnight: gpu-burn at 100% util + 114.6W
// correlated with Thermal WARN at 61°C and VRAM at 83%.
//
// Required signals:
//   - GPU INFO (sustained compute: util ≥ 80%, power ≥ 80W)
//   - Thermal WARN/CRIT OR Memory WARN/CRIT OR VRAM WARN/CRIT
func ruleGPUSustainedLoad(idx map[string]indexEntry) (Correlation, bool) {
	// GPU active = INFO (sustained load insight) OR WARN (VRAM pressure).
	// When VRAM is WARN, the index key "gpu" holds WARN (worst wins),
	// so we check atLeast INFO to catch both cases.
	gpuActive := atLeast(idx, "GPU", "INFO")
	if !gpuActive {
		return Correlation{}, false
	}

	thermalElevated := atLeast(idx, "Thermal", "WARN")
	memoryElevated := atLeast(idx, "Memory", "WARN")
	vramElevated := atLeast(idx, "GPU", "WARN") // VRAM WARN fires at 85%

	if !thermalElevated && !memoryElevated && !vramElevated {
		return Correlation{}, false
	}

	checks := []string{"GPU"}
	summary := "GPU under sustained compute load"
	if thermalElevated {
		checks = append(checks, "Thermal")
		summary += " — thermal elevation likely GPU-driven"
	}
	if memoryElevated {
		checks = append(checks, "Memory")
		summary += " — check if GPU and system RAM are competing"
	}
	if vramElevated {
		summary += " — VRAM pressure: reduce batch size or restart workload"
	}

	return Correlation{
		Name:    "GPU Sustained Compute Load",
		Level:   "WARN",
		Summary: summary,
		Action:  "inspect: nvidia-smi dmon -s pucvmt -d 5",
		Checks:  checks,
	}, true
}

// ruleIODrivenLoad fires when load average is elevated but CPU user time is low
// while iowait is high — the classic "load is I/O driven, not CPU bound" pattern.
// Operators frequently escalate to CPU when disk is the actual bottleneck.
//
// Required signals:
//   - CPU Load WARN or CRIT (load_pct > warn threshold)
//   - CPU/IOWait WARN or CRIT (iowait_pct > 20%)
//   - CPU/Steal NOT firing (rules out hypervisor as the cause)
func ruleIODrivenLoad(idx map[string]indexEntry) (Correlation, bool) {
	cpuLoaded := atLeast(idx, "CPU Load", "WARN")
	iowaitElevated := atLeast(idx, "CPU/IOWait", "WARN")
	stealElevated := atLeast(idx, "CPU/Steal", "WARN")

	if !cpuLoaded || !iowaitElevated || stealElevated {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "IO-Driven Load Saturation",
		Level:   "WARN",
		Summary: "Load average is elevated but the CPU is mostly idle — tasks are stalled waiting for disk I/O, not running on CPU",
		Action:  "iostat -x 1 5 && iotop -ao",
		Checks:  []string{"CPU Load", "CPU/IOWait"},
	}, true
}

// ruleCPUStealUnderLoad fires when the VM is both under load AND losing CPU
// time to the hypervisor. The host is over-provisioned — application
// latency will be unpredictable and adding more vCPUs will not help.
//
// Required signals:
//   - CPU Load WARN or CRIT
//   - CPU/Steal WARN or CRIT (steal_pct > 10%)
func ruleCPUStealUnderLoad(idx map[string]indexEntry) (Correlation, bool) {
	cpuLoaded := atLeast(idx, "CPU Load", "WARN")
	stealElevated := atLeast(idx, "CPU/Steal", "WARN")

	if !cpuLoaded || !stealElevated {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "CPU Steal Under Load",
		Level:   "CRIT",
		Summary: "VM is under load AND losing CPU to the hypervisor — the host is over-provisioned, adding vCPUs will not help",
		Action:  "escalate to cloud provider or migrate VM to a less-loaded host",
		Checks:  []string{"CPU Load", "CPU/Steal"},
	}, true
}

// ruleDBusCascade fires when D-Bus has failed and other services have also
// failed — distinguishing a single root cause from unrelated failures.
// D-Bus failure is the canonical example of a Tier-0 dependency failure
// that cascades to NetworkManager, systemd-logind, and many other services.
//
// Required signals:
//   - DBus CRIT (dbus.service failed)
//   - Systemd CRIT (at least one other unit failed)
func ruleDBusCascade(idx map[string]indexEntry) (Correlation, bool) {
	dbusFailed := exact(idx, "DBus", "CRIT")
	systemdFailed := atLeast(idx, "Systemd", "CRIT")

	if !dbusFailed || !systemdFailed {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "D-Bus Cascade Failure",
		Level:   "CRIT",
		Summary: "D-Bus system message bus has failed — all other service failures are likely downstream effects of this single root cause",
		Action:  "systemctl status dbus.service && journalctl -u dbus.service -n 20",
		Checks:  []string{"DBus", "Systemd"},
	}, true
}

// ruleEntropyTLSFailure fires when the entropy pool is dangerously low while
// TLS certificates are active on the system. Low entropy causes SSL handshakes
// and key-generation operations to stall waiting for randomness — the symptom
// is connection timeouts, not certificate errors, making this hard to diagnose
// without the correlation.
//
// Required signals:
//   - Entropy WARN or CRIT  (pool below 256 bits)
//   - TLS    WARN or CRIT   (expired or expiring-soon certs present)
func ruleEntropyTLSFailure(idx map[string]indexEntry) (Correlation, bool) {
	entropyLow := atLeast(idx, "Entropy", "WARN")
	tlsFired := atLeast(idx, "TLS", "WARN")

	if !entropyLow || !tlsFired {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Entropy Starvation with TLS Active",
		Level:   "CRIT",
		Summary: "entropy pool is critically low while TLS certificates are in use — SSL handshakes and key operations will stall or time out waiting for randomness",
		Action:  "apt install haveged OR dnf install rng-tools && systemctl enable --now rngd",
		Checks:  []string{"Entropy", "TLS"},
	}, true
}

// ── Deep correlations (time-aware, require raw collector data) ────────────────

// CorrelateDeep extends Correlate with time-aware cross-signal rules that need
// access to raw collector output (OOM events, Docker events) rather than just the
// distilled insights slice.  Call this instead of Correlate when deep data is
// available (i.e. from dsd health --deep or dsd health deep).
func CorrelateDeep(insights []models.Insight, oom *models.OOMInfo, docker *models.DockerInfo, io *models.IOInfo, sysctl *models.SysctlInfo) []Correlation {
	out := Correlate(insights)
	if c, ok := ruleDockerOOMCascade(oom, docker); ok {
		out = append(out, c)
	}
	if c, ok := ruleIOSingleDeviceDegradation(io); ok {
		out = append(out, c)
	}
	if c, ok := ruleServiceMemoryLeak(oom); ok {
		out = append(out, c)
	}
	idx := buildIndex(insights)
	if c, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		out = append(out, c)
	}
	return out
}

// ruleIOSingleDeviceDegradation fires when one device has critically high
// latency while peer devices on the same system are healthy. This pattern
// points to a single failing or contended drive rather than a storage
// subsystem overload — the remediation differs (replace drive vs reduce load).
//
// Required signals (raw IOInfo, not insights):
//   - At least 2 devices in io.Devices
//   - Exactly 1 device with AwaitMs > 20.0 OR UtilPct > 85.0
//   - At least 1 peer device with AwaitMs < 5.0 AND UtilPct < 60.0
func ruleIOSingleDeviceDegradation(io *models.IOInfo) (Correlation, bool) {
	if io == nil || len(io.Devices) < 2 {
		return Correlation{}, false
	}

	var degraded []models.IODeviceInfo
	var healthy []models.IODeviceInfo
	for _, d := range io.Devices {
		if d.AwaitMs > 20.0 || d.UtilPct > 85.0 {
			degraded = append(degraded, d)
		} else if d.AwaitMs < 5.0 && d.UtilPct < 60.0 {
			healthy = append(healthy, d)
		}
	}

	if len(degraded) != 1 || len(healthy) == 0 {
		return Correlation{}, false
	}

	dev := degraded[0]
	return Correlation{
		Name:  "Single Device IO Degradation",
		Level: "CRIT",
		Summary: fmt.Sprintf("%s has critically high IO latency (%.0fms await, %.0f%% util) while %d peer device(s) are healthy — likely a failing or heavily contended drive",
			dev.Name, dev.AwaitMs, dev.UtilPct, len(healthy)),
		Action: fmt.Sprintf("smartctl -a /dev/%s && iostat -x 1 5", dev.Name),
		Checks: []string{"IO"},
	}, true
}

// ruleServiceMemoryLeak fires when the OOM killer repeatedly terminates the
// same process — a pattern that distinguishes a memory leak in one specific
// service from general system memory pressure. General pressure kills
// different processes; a leaking service is killed repeatedly as it grows.
//
// Required signals (raw OOMInfo):
//   - oom.EventsLast24h >= 2
//   - At least one process name appears in ≥ 2 OOMEvent entries
//   - The repeated kills must be of the same named process
func ruleServiceMemoryLeak(oom *models.OOMInfo) (Correlation, bool) {
	if oom == nil || oom.EventsLast24h < 2 || len(oom.RecentEvents) < 2 {
		return Correlation{}, false
	}

	// Count kills per process name
	counts := make(map[string]int)
	for _, e := range oom.RecentEvents {
		if e.Process != "" {
			counts[e.Process]++
		}
	}

	// Find the process killed most often (must be ≥ 2)
	var leaker string
	var maxCount int
	for proc, n := range counts {
		if n > maxCount {
			maxCount = n
			leaker = proc
		}
	}

	if maxCount < 2 || leaker == "" {
		return Correlation{}, false
	}

	return Correlation{
		Name:  "Repeated OOM Kill — Possible Memory Leak",
		Level: "WARN",
		Summary: fmt.Sprintf("%s was OOM-killed %d times in the last 24h — this pattern suggests a memory leak rather than general memory pressure",
			leaker, maxCount),
		Action: fmt.Sprintf("check %s memory growth: ps aux | grep %s && journalctl -u %s --since '24h ago' | grep -i 'memory\\|oom'",
			leaker, leaker, leaker),
		Checks: []string{"OOM"},
	}, true
}

// ruleSysctlNotPersisted fires when sysctl parameters are at non-recommended
// values AND the system rebooted recently (uptime < 1 hour). This combination
// indicates the operator applied a fix with `sysctl -w` but did not persist it
// to /etc/sysctl.d/ — the fix was lost on reboot.
//
// Required signals:
//   - Sysctl WARN or CRIT   (some parameter is misconfigured)
//   - sysctl.UptimeSeconds > 0 AND < 3600   (rebooted in the last hour)
func ruleSysctlNotPersisted(sysctl *models.SysctlInfo, idx map[string]indexEntry) (Correlation, bool) {
	if sysctl == nil || sysctl.UptimeSeconds <= 0 || sysctl.UptimeSeconds >= 3600 {
		return Correlation{}, false
	}
	if !atLeast(idx, "Sysctl", "WARN") {
		return Correlation{}, false
	}

	uptimeMin := sysctl.UptimeSeconds / 60
	return Correlation{
		Name:  "Sysctl Parameter Not Persisted",
		Level: "WARN",
		Summary: fmt.Sprintf("system rebooted %d minute(s) ago and sysctl parameters are still at non-recommended values — the previous fix was applied with sysctl -w but not written to /etc/sysctl.d/",
			uptimeMin),
		Action: "echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf && sysctl -p /etc/sysctl.d/99-dsd.conf",
		Checks: []string{"Sysctl"},
	}, true
}

// ruleDockerOOMCascade fires when the kernel OOM killer and a Docker/Podman
// container OOM exit co-occurred within a 5-minute window.  This is the
// "20:00 overnight cluster" canonical rule from the 2026-05-11 RHEL 10.1 stress
// run where traefik, coredns, and stress containers were OOM-killed while the
// kernel simultaneously recorded OOM kills.
//
// Time-aware path (preferred):
//   - OOMInfo.RecentEvents contains an event with a parsed Timestamp
//   - DockerInfo.RecentEvents contains an "oom" or "die" event within 5 min of it
//
// Fallback (co-occurrence without timestamps):
//   - OOMInfo.EventsLast24h > 0 AND DockerInfo.OOMEvents > 0
//   - Fires CRIT with a weaker summary — still actionable
func ruleDockerOOMCascade(oom *models.OOMInfo, docker *models.DockerInfo) (Correlation, bool) {
	if oom == nil || docker == nil {
		return Correlation{}, false
	}
	if !oom.Available || oom.EventsLast24h == 0 {
		return Correlation{}, false
	}
	if !docker.Available || docker.OOMEvents == 0 {
		return Correlation{}, false
	}

	// Time-aware: look for a docker "oom"/"die" event within 5 min of a kernel OOM kill.
	if actor, ok := findTimedDockerOOM(oom, docker); ok {
		action := "docker stats --no-stream"
		if actor != "" {
			action = "docker inspect " + actor + " && docker logs --tail=50 " + actor
		}
		return Correlation{
			Name:    "Container OOM Cascade",
			Level:   "CRIT",
			Summary: "kernel OOM killer and Docker container OOM exit confirmed within 5 minutes — memory pressure killed a container",
			Action:  action,
			Checks:  []string{"OOM", "Docker"},
		}, true
	}

	// Fallback: both signals present but no parseable timestamps.
	return Correlation{
		Name:    "Container OOM Cascade",
		Level:   "CRIT",
		Summary: "kernel OOM kills and Docker container OOM events co-occurred — containers are being killed by memory pressure",
		Action:  "docker stats --no-stream && docker events --filter type=container --filter event=oom",
		Checks:  []string{"OOM", "Docker"},
	}, true
}

// findTimedDockerOOM returns the Docker actor name (container ID/name) when a
// docker "oom" or "die" event occurred within 5 minutes of a kernel OOM kill.
func findTimedDockerOOM(oom *models.OOMInfo, docker *models.DockerInfo) (actor string, found bool) {
	const window = 5 * time.Minute
	for _, de := range docker.RecentEvents {
		if de.Action != "oom" && de.Action != "die" {
			continue
		}
		deTime := time.Unix(de.TimeUnix, 0)
		for _, ke := range oom.RecentEvents {
			if ke.Timestamp.IsZero() {
				continue
			}
			diff := deTime.Sub(ke.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff <= window {
				return de.Actor, true
			}
		}
	}
	return "", false
}
