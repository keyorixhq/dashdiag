package baseline

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/output"
)

func DetectLastDeployTime() (time.Time, string, error) {
	for _, svc := range []string{
		"nginx", "apache2", "caddy", "postgres", "mysqld",
		"redis", "redis-server", "docker", "containerd", "node", "gunicorn",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "systemctl", "show", svc, //nolint:gosec // G204: hardcoded binary // NOSONAR
			"--property=ActiveEnterTimestamp", "--value").Output()
		cancel()
		if err != nil || strings.TrimSpace(string(out)) == "" {
			continue
		}
		t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(string(out)))
		if err != nil {
			continue
		}
		return t, svc + ".service restarted", nil
	}

	if t, name, err := newestProcStart(2 * time.Hour); err == nil {
		return t, name + " process started", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	out, err := exec.CommandContext(ctx, "git", "log", "-1", "--format=%ct").Output() // NOSONAR — hardcoded binary
	cancel()
	if err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			return time.Unix(ts, 0), "git: last commit", nil
		}
	}

	return time.Time{}, "", fmt.Errorf("no deploy signal found")
}

func newestProcStart(maxAge time.Duration) (time.Time, string, error) {
	return newestProcStartFrom("/proc/[0-9]*/stat", getBootTime(), maxAge)
}

func newestProcStartFrom(glob string, boot time.Time, maxAge time.Duration) (time.Time, string, error) {
	entries, err := filepath.Glob(glob)
	if err != nil {
		return time.Time{}, "", err
	}
	var newest time.Time
	var newestName string
	for _, entry := range entries {
		f, err := os.Open(filepath.Clean(entry))
		if err != nil {
			continue
		}
		startTime, name, ok := parseProcStart(f, boot)
		_ = f.Close()
		if !ok {
			continue
		}
		age := time.Since(startTime)
		if age > maxAge || age < 0 {
			continue
		}
		if startTime.After(newest) {
			newest = startTime
			newestName = name
		}
	}
	if newest.IsZero() {
		return time.Time{}, "", fmt.Errorf("no recent process")
	}
	return newest, newestName, nil
}

// parseProcStart parses a single /proc/<pid>/stat record, returning the process
// name and its start time (field 22, in clock ticks, offset from boot). ok is
// false if the record is malformed.
func parseProcStart(r io.Reader, boot time.Time) (time.Time, string, bool) {
	data, err := io.ReadAll(r)
	if err != nil {
		return time.Time{}, "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return time.Time{}, "", false
	}
	name := strings.Trim(fields[1], "()")
	startTicks, err := strconv.ParseFloat(fields[21], 64)
	if err != nil {
		return time.Time{}, "", false
	}
	startTime := boot.Add(time.Duration(startTicks/100) * time.Second)
	return startTime, name, true
}

func getBootTime() time.Time {
	return getBootTimeFrom("/proc/stat")
}

func getBootTimeFrom(path string) time.Time {
	f, err := os.Open(path)
	if err != nil {
		return time.Now().Add(-24 * time.Hour)
	}
	defer func() { _ = f.Close() }()
	if bt, ok := parseBootTime(f); ok {
		return bt
	}
	return time.Now().Add(-24 * time.Hour)
}

// parseBootTime extracts the btime (boot epoch, seconds) line from /proc/stat.
// ok is false if no valid btime line is present.
func parseBootTime(r io.Reader) (time.Time, bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if after, ok := strings.CutPrefix(scanner.Text(), "btime "); ok {
			ts, err := strconv.ParseInt(strings.TrimSpace(after), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(ts, 0), true
		}
	}
	if err := scanner.Err(); err != nil {
		return time.Time{}, false
	}
	return time.Time{}, false
}

func FindBaselineBeforeTime(t time.Time, hostname string) (*Snapshot, error) {
	dir := baselineDir()
	entries, err := filepath.Glob(filepath.Join(dir, SafeHostname(hostname)+"-2*.json"))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("no baselines found for %s", hostname)
	}
	var best *Snapshot
	var bestTime time.Time
	for _, p := range entries {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.ModTime().Before(t) && info.ModTime().After(bestTime) {
			snap, err := LoadBaseline(p)
			if err != nil {
				continue
			}
			best = snap
			bestTime = info.ModTime()
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no baseline found before %s", t.Format(time.RFC3339))
	}
	return best, nil
}

func RunSinceDeployDiff(mode output.OutputMode) error {
	deployTime, signal, err := DetectLastDeployTime()
	if err != nil {
		fmt.Println("info:  No deploy signal detected.")
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		fmt.Println("       Or: dsd health --diff  to compare against your last run.")
		return nil
	}
	hostname, _ := os.Hostname()
	_, err = FindBaselineBeforeTime(deployTime, hostname)
	if err != nil {
		mins := int(time.Since(deployTime).Minutes())
		fmt.Printf("info:  No pre-deploy baseline found (%s, %d min ago).\n", signal, mins)
		fmt.Println("       Run dsd health before your next deploy to enable this check.")
		return nil
	}
	mins := int(time.Since(deployTime).Minutes())
	fmt.Printf("Changes since last deploy (%s, %d min ago)\n\n", signal, mins)
	return nil
}
