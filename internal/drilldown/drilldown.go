package drilldown

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const drilldownTimeout = 5 * time.Second

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

func dispatch(ctx context.Context, ins models.Insight, results []runner.Result) (d *models.Details) {
	dctx, cancel := context.WithTimeout(ctx, drilldownTimeout)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			d = nil
		}
	}()

	var err error
	switch ins.Check {
	case "Memory", "Memory/Slab":
		d, err = TopProcessesByRSS(dctx, 10)
	case "CPU":
		d, err = TopProcessesByCPU(dctx, 10)
	case "Swap":
		d, err = TopProcessesBySwap(dctx, 10)
	case "Disk":
		mount := parseMountFromMessage(ins.Message)
		d, err = LargestDirs(dctx, mount)
	case "IO":
		d, err = TopProcessesByIO(dctx, 5)
	case "Network":
		d, err = TCPStateAttribution(dctx, results)
	case "Processes":
		if strings.Contains(ins.Message, "hung") || strings.Contains(ins.Message, "uninterruptible") {
			d = hungProcessesFromResults(results)
			if d == nil {
				d, err = HungProcesses(dctx)
			}
		} else {
			d, err = ZombiesWithParent(dctx)
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
	case "SELinux":
		d, err = PoliciesNotEnforcing(dctx)
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

// walkProcs calls fn(pid) for every process in /proc, using a worker pool.
// Permission errors are silently skipped.
func walkProcs(ctx context.Context, fn func(pid int) error) error {
	entries, err := os.ReadDir("/proc")
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

// procComm reads /proc/PID/comm for a process name.
func procComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// runCmd runs a command with context and returns its combined stdout.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
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
			Type:    "process_table",
			Title:   "Hung (uninterruptible) processes",
			Columns: []string{"PID", "NAME", "PPID", "WCHAN"},
			Rows:    rows,
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
