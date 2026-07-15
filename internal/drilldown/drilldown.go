package drilldown

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	drilldownTimeout = 5 * time.Second
	tableProcesses   = "process_table"
	tableKV          = "kv_table"
)

// PopulateAll runs drill-down for each WARN/CRIT insight in parallel.
// OK-level insights pass through unchanged. Results are written into
// the returned slice (same backing data as input).
func PopulateAll(ctx context.Context, insights []models.Insight, results []runner.Result) []models.Insight {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)

	for idx := range insights {
		if insights[idx].Level != "WARN" && insights[idx].Level != "CRIT" {
			continue
		}
		idx := idx
		g.Go(func() error {
			d := dispatch(gctx, insights[idx], results)
			if d != nil {
				insights[idx].Details = d
			}
			return nil
		})
	}
	_ = g.Wait()
	return insights
}

// errNoDetails is a sentinel so a nil drill-down result records as a recorded
// "no details" outcome (replayed verbatim) rather than a recording gap.
var errNoDetails = errors.New("drilldown: no details")

// dispatch routes an insight to its drill-down, with the DERIVED *Details routed
// through Source.Cached so it is hermetic under capture/replay. The drill-downs
// read live /proc (often with a two-sample timing delta, e.g. top-CPU%), which is
// neither routed through the source nor deterministic — under `dsd replay` they
// would read the REPLAYING machine's live processes, so two replays of one bundle
// disagreed (the top-process tables flickered). Caching the table at capture and
// replaying it verbatim fixes the whole drill-down class at one boundary; produce
// never runs on replay, so no live read happens. Keyed by Check+Message (stable
// across replays — insights derive from the recorded collector results).
func dispatch(ctx context.Context, ins models.Insight, results []runner.Result) *models.Details {
	key := "drilldown\x00" + ins.Check + "\x00" + ins.Message
	data, err := collectors.ActiveSource().Cached(key, func() ([]byte, error) {
		d := dispatchLive(ctx, ins, results)
		if d == nil {
			return nil, errNoDetails
		}
		return json.Marshal(d)
	})
	if err != nil {
		return nil // no details at capture, an older bundle without the key, or a gap
	}
	var out *models.Details
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

func dispatchLive(ctx context.Context, ins models.Insight, results []runner.Result) (d *models.Details) {
	dctx, cancel := context.WithTimeout(ctx, drilldownTimeout)
	defer cancel()

	defer func() {
		if recover() != nil {
			d = nil
		}
	}()

	var err error
	switch ins.Check {
	case "Memory", "Memory/Slab":
		d, err = TopProcessesByRSS(dctx, 10)
	case "CPU Load":
		// The CPU collector emits its load check as "CPU Load", not a bare "CPU";
		// this case must match it or the top-CPU-processes drilldown never runs.
		d, err = TopProcessesByCPU(dctx, 10)
	case "Swap":
		d, err = TopProcessesBySwap(dctx, 10)
	case "Disk":
		mount := parseMountFromMessage(ins.Message)
		d, err = LargestDirs(dctx, mount)
	case "IO":
		d, err = TopProcessesByIO(dctx, 5)
	case "Network":
		// TCP state summary is only useful for TCP-level problems.
		// Skip it for physical interface warnings (USB, WiFi, etc.)
		if !strings.Contains(ins.Message, "USB") &&
			!strings.Contains(ins.Message, "Wi-Fi") &&
			!strings.Contains(ins.Message, "wireless") &&
			!strings.Contains(ins.Message, "not responding") {
			d, err = TCPStateAttribution(dctx, results)
		}
	case "Processes":
		if strings.Contains(ins.Message, "hung") || strings.Contains(ins.Message, "uninterruptible") {
			d = hungProcessesFromResults(results)
			if d == nil {
				d, err = HungProcesses(dctx)
			}
		} else {
			d = zombiesFromResults(results)
			if d == nil {
				d, err = ZombiesWithParent(dctx)
			}
		}
	case "Systemd":
		unit := parseUnitFromMessage(ins.Message)
		d, err = FailedUnitLogs(dctx, unit, 20)
	case "FDLimits":
		d, err = TopProcessesByFDPercent(dctx, 10)
	case "Clock":
		d, err = ClockTracking(dctx)
	case "Sysctl":
		d, err = ActualVsRecommended(dctx, ins.Message)
	case "SELinux", "KernelSec":
		d, err = PoliciesNotEnforcing(dctx)
	case "Hardening":
		d = hardeningFromResults(results, ins.Message)
	}
	_ = err
	return d
}

// parseMountFromMessage extracts the mount path from a Disk insight message.
// Message format: "disk usage at 85% on /var (/dev/sda1)" → "/var"
func parseMountFromMessage(msg string) string {
	re := regexp.MustCompile(`\bon\s+(/\S*)`)
	if m := re.FindStringSubmatch(msg); len(m) > 1 {
		// strip trailing parenthesis that might be captured
		return strings.TrimRight(m[1], "(")
	}
	return "/"
}

// parseUnitFromMessage extracts the systemd unit name from a Systemd insight.
// Message format: "unit foo.service has failed" → "foo.service"
func parseUnitFromMessage(msg string) string {
	re := regexp.MustCompile(`unit\s+(\S+)\s+has`)
	if m := re.FindStringSubmatch(msg); len(m) > 1 {
		return m[1]
	}
	return ""
}

// walkProcs calls fn(pid) for every process under procRoot, using a worker
// pool. Permission errors are silently skipped. procRoot is normally "/proc";
// tests pass a testdata fixture directory instead.
func walkProcs(ctx context.Context, procRoot string, fn func(pid int) error) error {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return err
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 0 {
			continue
		}
		g.Go(func() error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			default:
			}
			if err := fn(pid); err != nil && !os.IsPermission(err) {
				return nil // skip non-permission errors too — /proc entries vanish
			}
			return nil
		})
	}
	return g.Wait()
}

// procComm reads procRoot/PID/comm for a process name.
func procComm(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, fmt.Sprintf("%d", pid), "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// runCmd runs a command with context and returns its combined stdout.
// LC_ALL=C and LANG=C are always set so numeric output uses dot as the
// decimal separator regardless of the user's locale.
//
// It is a package-level var, not a plain func, so tests can swap in a fake
// implementation for the tools they don't want to depend on being installed
// (getenforce, aa-status, chronyc, ...) — see swapRunCmd in drilldown_test.go.
// Tests that swap it must NOT call t.Parallel(): the swap is only race-free
// because Go's test runner finishes all serial tests before starting the
// parallel batch (same constraint as the t.Setenv("HOME") tests elsewhere in
// this codebase).
var runCmd = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

// lookPath is exec.LookPath as a package var for the same test-swap reason as
// runCmd above.
var lookPath = exec.LookPath

// zombiesFromResults builds a Details table from already-captured
// ZombieProcs in the Processes collector result.
func zombiesFromResults(results []runner.Result) *models.Details {
	for _, r := range results {
		if r.Name != "Processes" {
			continue
		}
		info, ok := r.Data.(*models.ProcessInfo)
		if !ok || len(info.ZombieProcs) == 0 {
			return nil
		}
		rows := make([][]string, 0, len(info.ZombieProcs))
		for _, p := range info.ZombieProcs {
			parentName := p.ParentName
			if parentName == "" {
				parentName = procComm("/proc", p.PPID) // Linux fallback via /proc
			}
			// Use only the base name — full paths break table formatting
			if idx := strings.LastIndexByte(parentName, '/'); idx >= 0 {
				parentName = parentName[idx+1:]
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", p.PID),
				fmt.Sprintf("%d", p.PPID),
				parentName,
			})
		}
		return &models.Details{
			Type:    tableProcesses,
			Title:   "Zombie processes (parent is the reaping offender)",
			Columns: []string{"ZOMBIE_PID", "PARENT_PID", "PARENT_NAME"},
			Rows:    rows,
		}
	}
	return nil
}

// hungProcessesFromResults builds a Details table from already-captured
// HungProcs in the Processes collector result, avoiding a late /proc re-scan
// that would miss transient D-state processes.
func hungProcessesFromResults(results []runner.Result) *models.Details {
	for _, r := range results {
		if r.Name != "Processes" {
			continue
		}
		info, ok := r.Data.(*models.ProcessInfo)
		if !ok || len(info.HungProcs) == 0 {
			return nil
		}
		rows := make([][]string, 0, len(info.HungProcs))
		for _, p := range info.HungProcs {
			rows = append(rows, []string{
				fmt.Sprintf("%d", p.PID),
				p.Name,
				fmt.Sprintf("%d", p.PPID),
				p.WChan,
			})
		}
		return &models.Details{
			Type:    tableProcesses,
			Title:   "Hung (uninterruptible) processes",
			Columns: []string{"PID", "NAME", "PPID", "WCHAN"},
			Rows:    rows,
		}
	}
	return nil
}

// hardeningFromResults builds a Details table from already-captured SecurityInfo.
// Different insight messages get different table views.
func hardeningFromResults(results []runner.Result, msg string) *models.Details {
	for _, r := range results {
		if r.Name != "Hardening" {
			continue
		}
		info, ok := r.Data.(*models.SecurityInfo)
		if !ok || info == nil {
			return nil
		}

		// Unexpected ports table
		if strings.Contains(msg, "unexpected port") {
			var rows [][]string
			for _, p := range info.ListeningPorts {
				if !p.Expected {
					rows = append(rows, []string{
						fmt.Sprintf("%d", p.Port),
						p.Protocol,
						p.Process,
					})
				}
			}
			if len(rows) > 0 {
				note := ""
				if info.PortsNeedRoot {
					note = "process names require root — run: sudo dsd health"
				}
				return &models.Details{
					Type:    tableProcesses,
					Title:   "Unexpected ports listening on all interfaces",
					Columns: []string{"PORT", "PROTO", "PROCESS"},
					Rows:    rows,
					Note:    note,
				}
			}
		}

		// Failed logins table
		if strings.Contains(msg, "failed login") && len(info.FailedLoginIPs) > 0 {
			var rows [][]string
			for _, ip := range info.FailedLoginIPs {
				rows = append(rows, []string{ip})
			}
			return &models.Details{
				Type:    tableProcesses,
				Title:   "Top source IPs for failed logins",
				Columns: []string{"IP (attempts)"},
				Rows:    rows,
			}
		}
	}
	return nil
}

// formatBytes returns a human-readable string for a byte count.
func formatBytes(bytes int64) string {
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
