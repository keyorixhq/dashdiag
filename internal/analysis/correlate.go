package analysis

import (
	"strings"

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
