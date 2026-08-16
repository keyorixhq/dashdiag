package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	corrCatMemory     = "Memory"
	corrCatCPULoad    = "CPU Load"
	corrCatSwap       = "Swap"
	corrCatLogs       = "Logs"
	corrCatIO         = "IO"
	corrCatCPUThermal = "CPU Thermal"
	corrCatCPUSteal   = "CPU Load/Steal"
	corrCatTLS        = "TLS"
	corrCatSystemd    = "Systemd"
	corrCatProcesses  = "Processes"
	corrCatOOM        = "oom"
	corrCatDocker     = "Docker"
	corrKwDie         = "die"
	corrCatCPUIOwait  = "CPU Load/IOWait"
	corrCatOOMUpper   = "OOM"
	corrCatNetwork    = "Network"
	corrCatGPU        = "GPU"
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
	if c, ok := ruleRunQueueSaturation(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleDBusCascade(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleEntropyTLSFailure(idx); ok {
		out = append(out, c)
	}
	// v2 rules — cross-collector causal chains (2026-06).
	if c, ok := ruleDiskFullServiceFailure(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleNFSStaleProcessHang(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleClockSkewTLSAuth(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleContainerCgroupOOM(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleThermalThrottleUnderLoad(idx); ok {
		out = append(out, c)
	}
	if c, ok := ruleDNSResolverNotConnectivity(idx); ok {
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
// corrCatIO → ["io"]
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

// confirmedNot returns true only when key was actually checked (present in
// idx) and its level differs from level. Unlike !exact(idx, key, level),
// this returns false — not true — when the check never ran at all: a check
// that produced no insight (silent-on-healthy) and a check that was never
// executed both leave key absent from idx, so "absent" must not be read as
// "confirmed healthy". internal-analysis-01-03: rules using !exact() as a
// "this signal is clear" qualifier were firing on unmeasured signals, not
// just confirmed-clear ones.
func confirmedNot(idx map[string]indexEntry, key, level string) bool {
	e, ok := idx[strings.ToLower(key)]
	return ok && e.level != level
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
	memFired := atLeast(idx, corrCatMemory, "WARN")
	swapCrit := exact(idx, corrCatSwap, "CRIT")
	processesCrit := exact(idx, corrCatProcesses, "CRIT")
	logsCrit := exact(idx, corrCatLogs, "CRIT")

	if !memFired || !swapCrit || (!processesCrit && !logsCrit) {
		return Correlation{}, false
	}

	checks := []string{corrCatMemory, corrCatSwap}
	if processesCrit {
		checks = append(checks, corrCatProcesses)
	}
	if logsCrit {
		checks = append(checks, corrCatLogs)
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
//   - Swap confirmed NOT CRIT (swap was measured and wasn't the pressure
//     valve — not merely unmeasured)
func ruleHardOOM(idx map[string]indexEntry) (Correlation, bool) {
	memCrit := exact(idx, corrCatMemory, "CRIT")
	logsCrit := exact(idx, corrCatLogs, "CRIT")
	swapNotCrit := confirmedNot(idx, corrCatSwap, "CRIT")

	if !memCrit || !logsCrit || !swapNotCrit {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Hard OOM Event",
		Level:   "CRIT",
		Summary: "Processes killed directly — memory hit a hard ceiling with no swap acting as a buffer",
		Action:  "check which processes were killed: dmesg | grep -i 'out of memory'",
		Checks:  []string{corrCatMemory, corrCatLogs},
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
	ioCrit := exact(idx, corrCatIO, "CRIT")
	memFired := atLeast(idx, corrCatMemory, "WARN")
	swapCrit := exact(idx, corrCatSwap, "CRIT")

	if !ioCrit || !memFired || !swapCrit {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "IO Stall Under Memory Pressure",
		Level:   "CRIT",
		Summary: "Disk latency spiked while kernel is swapping — page eviction and I/O compete for the same storage bandwidth",
		Action:  "check what is swapping: vmstat 1 5 && iotop -ao",
		Checks:  []string{corrCatIO, corrCatMemory, corrCatSwap},
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
	netCrit := exact(idx, corrCatNetwork, "CRIT")
	// corrCatCPULoad (key "cpu load") covers both the utilisation insight and the
	// sub-checks (corrCatCPUSteal etc.), which index under "cpu load" via the
	// namespace prefix — so any CPU-load signal qualifies as "system under load".
	cpuLoaded := atLeast(idx, corrCatCPULoad, "WARN")
	swapCrit := exact(idx, corrCatSwap, "CRIT")
	memCrit := exact(idx, corrCatMemory, "CRIT")

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

	checks := []string{corrCatNetwork}
	if cpuLoaded {
		checks = append(checks, "CPU")
	}
	if swapCrit {
		checks = append(checks, corrCatSwap)
	}
	if memCrit {
		checks = append(checks, corrCatMemory)
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
	gpuActive := atLeast(idx, corrCatGPU, "INFO")
	if !gpuActive {
		return Correlation{}, false
	}

	// The thermal collector emits its check as corrCatCPUThermal (index key
	// "cpu thermal") — there is no bare "Thermal" check, so this must match it
	// exactly or the thermal dimension of this correlation never fires.
	thermalElevated := atLeast(idx, corrCatCPUThermal, "WARN")
	memoryElevated := atLeast(idx, corrCatMemory, "WARN")
	vramElevated := atLeast(idx, corrCatGPU, "WARN") // VRAM WARN fires at 85%

	if !thermalElevated && !memoryElevated && !vramElevated {
		return Correlation{}, false
	}

	checks := []string{corrCatGPU}
	summary := "GPU under sustained compute load"
	if thermalElevated {
		checks = append(checks, "Thermal")
		summary += " — thermal elevation likely GPU-driven"
	}
	if memoryElevated {
		checks = append(checks, corrCatMemory)
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
	cpuLoaded := atLeast(idx, corrCatCPULoad, "WARN")
	iowaitElevated := atLeast(idx, corrCatCPUIOwait, "WARN")
	stealElevated := atLeast(idx, corrCatCPUSteal, "WARN")

	if !cpuLoaded || !iowaitElevated || stealElevated {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "IO-Driven Load Saturation",
		Level:   "WARN",
		Summary: "Load average is elevated but the CPU is mostly idle — tasks are stalled waiting for disk I/O, not running on CPU",
		Action:  "iostat -x 1 5 && iotop -ao",
		Checks:  []string{corrCatCPULoad, corrCatCPUIOwait},
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
	cpuLoaded := atLeast(idx, corrCatCPULoad, "WARN")
	stealElevated := atLeast(idx, corrCatCPUSteal, "WARN")

	if !cpuLoaded || !stealElevated {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "CPU Steal Under Load",
		Level:   "CRIT",
		Summary: "VM is under load AND losing CPU to the hypervisor — the host is over-provisioned, adding vCPUs will not help",
		Action:  "escalate to cloud provider or migrate VM to a less-loaded host",
		Checks:  []string{corrCatCPULoad, corrCatCPUSteal},
	}, true
}

// ruleRunQueueSaturation fires when the run queue is saturated (more runnable
// tasks than cores) while neither iowait nor steal explains it — the load is
// genuinely CPU-bound: too many threads competing for too few cores. This
// distinguishes a true CPU shortage from I/O-driven load (ruleIODrivenLoad) and
// hypervisor theft (ruleCPUStealUnderLoad); the remediation differs (add cores
// or reduce concurrency, vs fix disk, vs migrate VM).
//
// Required signals:
//   - CPU/RunQueue WARN or CRIT (runnable tasks ≥ 2× cores)
//   - CPU/IOWait confirmed NOT elevated (measured and below WARN — not
//     merely unmeasured; rules out I/O-driven load)
//   - CPU/Steal confirmed NOT elevated (measured and below WARN — not
//     merely unmeasured; rules out hypervisor steal)
func ruleRunQueueSaturation(idx map[string]indexEntry) (Correlation, bool) {
	rqSaturated := atLeast(idx, "CPU Load/RunQueue", "WARN")
	// internal-analysis-01-03: !atLeast(idx, key, "WARN") reads true both when
	// the signal was measured and confirmed low AND when it was never measured
	// at all (absent from idx) — that let this rule assert "genuinely
	// CPU-bound" on an unmeasured signal. confirmedNot requires presence, so
	// it must be checked against both non-OK tiers (WARN and CRIT) to rule out
	// "elevated" in either direction — confirmedNot(..., "WARN") alone would
	// still treat a CRIT reading as "not elevated".
	iowaitConfirmedLow := confirmedNot(idx, corrCatCPUIOwait, "WARN") && confirmedNot(idx, corrCatCPUIOwait, "CRIT")
	stealConfirmedLow := confirmedNot(idx, corrCatCPUSteal, "WARN") && confirmedNot(idx, corrCatCPUSteal, "CRIT")

	if !rqSaturated || !iowaitConfirmedLow || !stealConfirmedLow {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "CPU-Bound Run Queue Saturation",
		Level:   "WARN",
		Summary: "more tasks are runnable than the CPU can execute, and it is not I/O wait or hypervisor steal — the workload is genuinely CPU-bound",
		Action:  "find the busy threads: top -H -b -n1 | head -20 — then add cores or reduce concurrency",
		Checks:  []string{"CPU Load/RunQueue"},
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
	systemdFailed := atLeast(idx, corrCatSystemd, "CRIT")

	if !dbusFailed || !systemdFailed {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "D-Bus Cascade Failure",
		Level:   "CRIT",
		Summary: "D-Bus system message bus has failed — all other service failures are likely downstream effects of this single root cause",
		Action:  "systemctl status dbus.service && journalctl -u dbus.service -n 20",
		Checks:  []string{"DBus", corrCatSystemd},
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
	tlsFired := atLeast(idx, corrCatTLS, "WARN")

	if !entropyLow || !tlsFired {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Entropy Starvation with TLS Active",
		Level:   "CRIT",
		Summary: "entropy pool is critically low while TLS certificates are in use — SSL handshakes and key operations will stall or time out waiting for randomness",
		Action:  "apt install haveged OR dnf install rng-tools && " + PlatformServiceCmd("systemctl enable --now rngd"),
		Checks:  []string{"Entropy", corrCatTLS},
	}, true
}

// ── v2 rules ─────────────────────────────────────────────────────────────────

// ruleDiskFullServiceFailure fires when a filesystem is full and a service has
// failed or write errors are logged — the canonical "disk filled, things broke"
// incident, where the disk is the cause and the service failure is the symptom.
//
// Required signals:
//   - Disk CRIT                    (a filesystem at/over its capacity threshold)
//   - Systemd CRIT OR Logs CRIT    (a unit failed, or write/ENOSPC errors logged)
func ruleDiskFullServiceFailure(idx map[string]indexEntry) (Correlation, bool) {
	diskCrit := exact(idx, "Disk", "CRIT")
	systemdCrit := exact(idx, corrCatSystemd, "CRIT")
	logsCrit := exact(idx, corrCatLogs, "CRIT")

	if !diskCrit || (!systemdCrit && !logsCrit) {
		return Correlation{}, false
	}

	checks := []string{"Disk"}
	if systemdCrit {
		checks = append(checks, corrCatSystemd)
	}
	if logsCrit {
		checks = append(checks, corrCatLogs)
	}

	return Correlation{
		Name:    "Disk-Full Service Failure",
		Level:   "CRIT",
		Summary: "A full filesystem is the likely root cause — services can't write, so failures and errors are downstream symptoms, not the problem",
		Action:  "free space first: du -x -d1 / | sort -h | tail -10  (then restart the affected unit)",
		Checks:  checks,
	}, true
}

// ruleNFSStaleProcessHang fires when an NFS mount is stale/unresponsive and
// processes are stuck — the classic uninterruptible-sleep (D-state) hang where
// the storage, not the application, is at fault.
//
// Required signals:
//   - NFS CRIT        (a stale or unreachable mount)
//   - Processes CRIT  (uninterruptible-sleep / hung tasks)
func ruleNFSStaleProcessHang(idx map[string]indexEntry) (Correlation, bool) {
	if !exact(idx, "NFS", "CRIT") || !exact(idx, corrCatProcesses, "CRIT") {
		return Correlation{}, false
	}
	return Correlation{
		Name:    "NFS Stall Process Hang",
		Level:   "CRIT",
		Summary: "Processes are stuck in uninterruptible sleep on a stale NFS mount — they can't be killed until the mount responds or is force-unmounted",
		Action:  "find the bad mount: nfsstat -m; then: umount -f -l <mount>  (or restore the NFS server)",
		Checks:  []string{"NFS", corrCatProcesses},
	}, true
}

// ruleClockSkewTLSAuth fires when the clock is badly skewed and TLS or auth is
// failing — time drift makes valid certificates look not-yet-valid/expired and
// breaks Kerberos/2FA, so the fix is time sync, not the cert or credentials.
//
// Required signals:
//   - Clock CRIT                (NTP unsynced or large offset)
//   - TLS CRIT OR Auth WARN     (cert validation or authentication failing)
func ruleClockSkewTLSAuth(idx map[string]indexEntry) (Correlation, bool) {
	clockCrit := exact(idx, "Clock", "CRIT")
	tlsCrit := exact(idx, corrCatTLS, "CRIT")
	authFired := atLeast(idx, "Auth", "WARN")

	if !clockCrit || (!tlsCrit && !authFired) {
		return Correlation{}, false
	}

	checks := []string{"Clock"}
	if tlsCrit {
		checks = append(checks, corrCatTLS)
	}
	if authFired {
		checks = append(checks, "Auth")
	}

	return Correlation{
		Name:    "Clock Skew Breaking TLS/Auth",
		Level:   "CRIT",
		Summary: "The clock is badly skewed — valid certificates read as expired/not-yet-valid and Kerberos/2FA fail. Fix time first; the certs and credentials are probably fine",
		Action:  "sync time: timedatectl set-ntp true  (or chronyc makestep) — then re-test TLS/login",
		Checks:  checks,
	}, true
}

// ruleContainerCgroupOOM fires when a container was OOM-killed and a cgroup
// memory limit was hit while host RAM is NOT critical — the container's own
// limit is too low, so adding host RAM won't help.
//
// Required signals:
//   - Docker CRIT        (a container unhealthy / OOM-killed)
//   - Cgroup CRIT        (a cgroup at its memory limit)
//   - Memory confirmed NOT CRIT (the host was measured and has headroom —
//     not merely unmeasured)
func ruleContainerCgroupOOM(idx map[string]indexEntry) (Correlation, bool) {
	dockerCrit := exact(idx, corrCatDocker, "CRIT")
	cgroupCrit := exact(idx, "Cgroup", "CRIT")
	hostMemOK := confirmedNot(idx, corrCatMemory, "CRIT")

	if !dockerCrit || !cgroupCrit || !hostMemOK {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "Container Memory-Limit OOM",
		Level:   "CRIT",
		Summary: "A container hit its own cgroup memory limit while the host still has RAM — the container's limit is too low; adding host memory won't fix it",
		Action:  "raise the container's limit (docker update --memory / k8s resources.limits), or find its leak",
		Checks:  []string{corrCatDocker, "Cgroup"},
	}, true
}

// ruleThermalThrottleUnderLoad fires when the CPU is thermally throttling while
// under load — performance is capped by heat, not by a lack of CPU capacity, so
// the fix is cooling/airflow rather than more cores.
//
// Required signals:
//   - CPU Thermal WARN/CRIT  (throttling temperature reached)
//   - CPU Load WARN          (the box is actually busy — not idle-and-hot)
func ruleThermalThrottleUnderLoad(idx map[string]indexEntry) (Correlation, bool) {
	thermalFired := atLeast(idx, corrCatCPUThermal, "WARN")
	cpuLoaded := atLeast(idx, corrCatCPULoad, "WARN")

	if !thermalFired || !cpuLoaded {
		return Correlation{}, false
	}

	level := "WARN"
	if exact(idx, corrCatCPUThermal, "CRIT") {
		level = "CRIT"
	}

	return Correlation{
		Name:    "Thermal Throttling Under Load",
		Level:   level,
		Summary: "The CPU is throttling on temperature while busy — performance is capped by heat, not by core count; more vCPUs won't help",
		Action:  "check cooling/airflow: sensors; reduce sustained load or improve heat dissipation",
		Checks:  []string{corrCatCPUThermal, corrCatCPULoad},
	}, true
}

// ruleDNSResolverNotConnectivity fires when DNS resolution is failing but the
// network link itself is healthy — pointing the operator at the resolver/config
// rather than chasing a connectivity problem that isn't there.
//
// Required signals:
//   - DNS CRIT          (resolution failing)
//   - Network confirmed NOT CRIT (the link/gateway was measured and is up —
//     not merely unmeasured, so it's not connectivity)
func ruleDNSResolverNotConnectivity(idx map[string]indexEntry) (Correlation, bool) {
	dnsCrit := exact(idx, "DNS", "CRIT")
	networkOK := confirmedNot(idx, corrCatNetwork, "CRIT")

	if !dnsCrit || !networkOK {
		return Correlation{}, false
	}

	return Correlation{
		Name:    "DNS Resolver Failure (network is up)",
		Level:   "WARN",
		Summary: "DNS resolution is failing while the network link is healthy — this is a resolver/config problem, not connectivity. Don't chase the network",
		Action:  "check the resolver: resolvectl status; cat /etc/resolv.conf; dig @1.1.1.1 example.com vs dig example.com",
		Checks:  []string{"DNS"},
	}, true
}

// ── Deep correlations (time-aware, require raw collector data) ────────────────

// CorrelateDeep extends Correlate with time-aware cross-signal rules that need
// access to raw collector output (OOM events, Docker events) rather than just the
// distilled insights slice.  Call this instead of Correlate when deep data is
// available (i.e. from dsd health --deep or dsd health deep).
func CorrelateDeep(insights []models.Insight, oom *models.OOMInfo, docker *models.DockerInfo, io *models.IOInfo, sysctl *models.SysctlInfo, cpu *models.CPUInfo, deep *models.HealthDeepInfo) []Correlation {
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
	if c, ok := ruleIOWaitCulprit(cpu, io, deep); ok {
		out = append(out, c)
	}
	idx := buildIndex(insights)
	if c, ok := ruleSysctlNotPersisted(sysctl, idx); ok {
		out = append(out, c)
	}
	return out
}

// ioWaitCulpritGatePct is the iowait threshold (Spec 5.3) above which the
// deep collector's device+process data is worth attributing — well below
// checkCPU's own WARN floor (20%) because attribution is informational, not
// an alarm: naming the culprit early, before iowait becomes a full incident,
// is the point of the feature.
const ioWaitCulpritGatePct = 5.0

// ruleIOWaitCulprit pinpoints the device with the highest await time and the
// process most responsible for I/O, so an operator doesn't have to run
// iostat/iotop by hand to answer "iowait 12% ← what?". The device and the
// process are each independently the busiest by their own metric — not proven
// causally linked (Linux doesn't expose per-process, per-device attribution) —
// so this is the same best-effort correlation iotop itself offers, not a
// guarantee.
func ruleIOWaitCulprit(cpu *models.CPUInfo, io *models.IOInfo, deep *models.HealthDeepInfo) (Correlation, bool) {
	if cpu == nil || cpu.IOwaitPct < ioWaitCulpritGatePct {
		return Correlation{}, false
	}
	if io == nil || len(io.Devices) == 0 || deep == nil || len(deep.TopIOProcs) == 0 {
		return Correlation{}, false
	}

	dev := io.Devices[0]
	for _, d := range io.Devices[1:] {
		if d.AwaitMs > dev.AwaitMs {
			dev = d
		}
	}
	top := deep.TopIOProcs[0]

	level := "WARN"
	if cpu.IOwaitPct >= 40 {
		level = "CRIT"
	}
	summary := fmt.Sprintf("iowait %.0f%% ← %s (%.0fms await) ← %s (PID %d)",
		cpu.IOwaitPct, dev.Name, dev.AwaitMs, top.Name, top.PID)
	if deep.TopIOProcsNeedsRoot {
		summary += " — partial process visibility, run as root for full attribution"
	}

	return Correlation{
		Name:    "IO Wait Culprit",
		Level:   level,
		Summary: summary,
		Action:  fmt.Sprintf("iotop -ao -p %d && iostat -x 1 5 %s", top.PID, dev.Name),
		Checks:  []string{corrCatCPUIOwait, corrCatIO},
	}, true
}

// ioAwaitActiveUtilFloor is the minimum utilization at which a high await time is
// a meaningful signal. Await (average service time per I/O) is computed over the
// I/Os that occurred in the window; on a near-idle device a handful of slow I/Os
// produce a large await that says nothing about drive health. A genuinely failing
// or contended drive is, by definition, busy — its slow I/Os keep it occupied, so
// elevated await coincides with elevated util. Below this floor we treat high await
// as measurement noise rather than degradation (avoids a false "failing drive" CRIT
// on an essentially-idle disk — e.g. 24ms await at 4% util on a shared LXC host).
const ioAwaitActiveUtilFloor = 20.0

// ruleIOSingleDeviceDegradation fires when one device has critically high
// latency while peer devices on the same system are healthy. This pattern
// points to a single failing or contended drive rather than a storage
// subsystem overload — the remediation differs (replace drive vs reduce load).
//
// Required signals (raw IOInfo, not insights):
//   - At least 2 devices in io.Devices
//   - Exactly 1 device that is (await > 20ms AND util >= floor) OR util > 85%
//   - At least 1 peer device with AwaitMs < 5.0 AND UtilPct < 60.0
func ruleIOSingleDeviceDegradation(io *models.IOInfo) (Correlation, bool) {
	if io == nil || len(io.Devices) < 2 {
		return Correlation{}, false
	}

	var degraded []models.IODeviceInfo
	var healthy []models.IODeviceInfo
	for _, d := range io.Devices {
		highAwaitWhileActive := d.AwaitMs > 20.0 && d.UtilPct >= ioAwaitActiveUtilFloor
		if highAwaitWhileActive || d.UtilPct > 85.0 {
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
		Checks: []string{corrCatIO},
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
	// counts is a map; tie-break by process name so the reported leaker is stable
	// run-to-run when two processes were OOM-killed the same (max) number of times
	// (otherwise map iteration order picks the winner — TRIAGE §I).
	for proc, n := range counts {
		if n > maxCount || (n == maxCount && proc < leaker) {
			maxCount = n
			leaker = proc
		}
	}

	if maxCount < 2 || leaker == "" {
		return Correlation{}, false
	}

	// leaker is the OOM-killed process's kernel comm name, parsed verbatim from
	// dmesg by collectors/oom_linux.go. comm is attacker-settable via
	// prctl(PR_SET_NAME) and is NOT restricted to a safe charset (only length-
	// capped to 15 bytes) — shell metacharacters are legal. Action is printed
	// verbatim as a copy-pasteable "next step", so an unvalidated leaker here
	// is a local privesc if an operator pastes it into a root shell. Validate
	// before building the command; fall back to a generic, non-pasteable hint
	// otherwise (see looksLikeSafeToken).
	action := fmt.Sprintf("check %s memory growth: ps aux | grep %s && journalctl -u %s --since '24h ago' | grep -i 'memory\\|oom'",
		leaker, leaker, leaker)
	if !looksLikeSafeToken(leaker) {
		action = "check the repeatedly OOM-killed process manually (ps aux / journalctl) — its name contains unexpected characters and is withheld from this command suggestion"
	}

	return Correlation{
		Name:  "Repeated OOM Kill — Possible Memory Leak",
		Level: "WARN",
		Summary: fmt.Sprintf("%s was OOM-killed %d times in the last 24h — this pattern suggests a memory leak rather than general memory pressure",
			leaker, maxCount),
		Action: action,
		Checks: []string{corrCatOOMUpper},
	}, true
}

// ruleSysctlNotPersisted fires when sysctl parameters are at non-recommended
// values AND the system rebooted recently (uptime < 1 hour). The combination is
// *consistent with* an operator having applied a fix with `sysctl -w` that was
// never persisted to /etc/sysctl.d/ (so it was lost on reboot) — but current
// state alone cannot prove it: a lost `sysctl -w` reverts to the same stock
// default a never-touched box shows. So the summary is phrased conditionally
// rather than asserting a past action (BUG-023 follow-up), and the rule is
// suppressed when the flagged values are still at their kernel stock defaults —
// the strongest "nobody tuned this" signal available without history. A truly
// reliable verdict needs the history-aware v2 (compare against a prior snapshot
// that showed the recommended value).
//
// Required signals:
//   - Sysctl WARN or CRIT   (some parameter is misconfigured)
//   - sysctl.UptimeSeconds > 0 AND < 3600   (rebooted in the last hour)
//   - at least one flagged value is non-default (not a fresh-boot stock value)
func ruleSysctlNotPersisted(sysctl *models.SysctlInfo, idx map[string]indexEntry) (Correlation, bool) {
	if sysctl == nil || sysctl.UptimeSeconds <= 0 || sysctl.UptimeSeconds >= 3600 {
		return Correlation{}, false
	}
	if !atLeast(idx, "Sysctl", "WARN") {
		return Correlation{}, false
	}
	if sysctlAllAtStockDefaults(sysctl) {
		// Non-recommended-but-default values after a fresh boot are the stock
		// configuration, not a fix that failed to persist. Don't narrate a
		// non-existent lost fix (the underlying Sysctl WARN still stands on its
		// own — this only suppresses the misleading correlation).
		return Correlation{}, false
	}

	uptimeMin := sysctl.UptimeSeconds / 60
	return Correlation{
		Name:  "Sysctl Parameter Not Persisted",
		Level: "WARN",
		Summary: fmt.Sprintf("system rebooted %d minute(s) ago with sysctl parameters at non-recommended, non-default values — if a fix was applied last boot with `sysctl -w` it did not survive the reboot; persist tuning to /etc/sysctl.d/ so it reapplies at boot",
			uptimeMin),
		Action: "echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf && sysctl -p /etc/sysctl.d/99-dsd.conf",
		Checks: []string{"Sysctl"},
	}, true
}

// sysctlAllAtStockDefaults reports whether the "high value is bad" tunables that
// commonly drive a Sysctl WARN are still at their well-known, version-stable
// kernel defaults — i.e. nothing was tuned away from the out-of-the-box value.
// When true, the "fix applied but not persisted" narrative is almost certainly
// wrong (a fresh boot, not a lost sysctl -w), so the correlation is suppressed.
//
// Deliberately limited to swappiness and dirty_ratio: their defaults (60, 20)
// are stable across kernel versions AND exceed the WARN threshold, so a flagged
// value sitting exactly on the default is the unambiguous "untouched" signal.
// Parameters whose default is itself version-dependent or whose flagged value
// coincides with a historical default (net.core.somaxconn, tcp_tw_reuse) are
// excluded — there a "still at default" test would misfire. For those the
// conditional wording in the summary carries the caveat instead.
//
// A zero current value means "not collected" and is treated as default.
func sysctlAllAtStockDefaults(s *models.SysctlInfo) bool {
	type pair struct{ cur, def int }
	for _, p := range []pair{
		{s.VMSwappiness, 60}, // kernel default; WARN fires when > 10 for k8s/db
		{s.VMDirtyRatio, 20}, // kernel default; WARN fires when > 10 for db
	} {
		if p.cur != 0 && p.cur != p.def {
			return false // tuned away from default — let the correlation fire
		}
	}
	return true
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
		// actor is a Docker/Podman container name/ID read verbatim from
		// `docker events` Actor attributes (collectors/docker.go). Docker's own
		// API constrains names created normally, but this code doesn't itself
		// enforce that before splicing actor into a copy-pasteable Action
		// string — validate here too rather than rely on an external, unstated
		// assumption (see looksLikeSafeToken).
		if actor != "" && looksLikeSafeToken(actor) {
			action = "docker inspect " + actor + " && docker logs --tail=50 " + actor
		} else if actor != "" {
			action = "docker inspect <container> && docker logs --tail=50 <container> — actor name contains unexpected characters; run `docker ps -a` to find the container"
		}
		return Correlation{
			Name:    "Container OOM Cascade",
			Level:   "CRIT",
			Summary: "kernel OOM killer and Docker container OOM exit confirmed within 5 minutes — memory pressure killed a container",
			Action:  action,
			Checks:  []string{corrCatOOMUpper, corrCatDocker},
		}, true
	}

	// Fallback: both signals present but no parseable timestamps.
	return Correlation{
		Name:    "Container OOM Cascade",
		Level:   "CRIT",
		Summary: "kernel OOM kills and Docker container OOM events co-occurred — containers are being killed by memory pressure",
		Action:  "docker stats --no-stream && docker events --filter type=container --filter event=oom",
		Checks:  []string{corrCatOOMUpper, corrCatDocker},
	}, true
}

// findTimedDockerOOM returns the Docker actor name (container ID/name) when a
// docker "oom" or "die" event occurred within 5 minutes of a kernel OOM kill.
func findTimedDockerOOM(oom *models.OOMInfo, docker *models.DockerInfo) (actor string, found bool) {
	const window = 5 * time.Minute
	for _, de := range docker.RecentEvents {
		if de.Action != corrCatOOM && de.Action != corrKwDie {
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
