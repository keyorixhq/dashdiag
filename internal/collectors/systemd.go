package collectors

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type SystemdCollector struct{}

func NewSystemdCollector() *SystemdCollector { return &SystemdCollector{} }

func (c *SystemdCollector) Name() string           { return "Systemd" }
func (c *SystemdCollector) Timeout() time.Duration { return 3 * time.Second }

// parseUnitList parses `systemctl list-units --no-legend --no-pager --plain` output.
// Each line's first field that contains "." is the unit name.
func parseUnitList(r io.Reader) []string {
	var units []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		// Skip non-unit lines (header/summary) and bullet indicators
		if !strings.Contains(name, ".") {
			if len(fields) > 1 && strings.Contains(fields[1], ".") {
				name = fields[1]
			} else {
				continue
			}
		}
		units = append(units, name)
	}
	return units
}

var cloudInitUnits = map[string]bool{
	"cloud-final.service":      true,
	"cloud-config.service":     true,
	"cloud-init.service":       true,
	"cloud-init-local.service": true,
	// Live ISO artifacts — fail on installed systems, not a real error
	"casper-md5check.service": true,
	"casper.service":          true,
	// LXC container false positives — host kernel already owns these;
	// containers cannot set them up and systemd marks them failed.
	"dev-mqueue.mount":                         true,
	"dev-hugepages.mount":                      true,
	"sys-fs-fuse-connections.mount":            true,
	"sys-kernel-config.mount":                  true,
	"sys-kernel-debug.mount":                   true,
	"run-lock.mount":                           true,
	"tmp.mount":                                true,
	"systemd-firstboot.service":                true,
	"systemd-sysctl.service":                   true,
	"systemd-sysusers.service":                 true,
	"systemd-tmpfiles-setup-dev-early.service": true,
	"systemd-tmpfiles-setup-dev.service":       true,
	"systemd-tmpfiles-setup.service":           true,
	"systemd-udev-load-credentials.service":    true,
	"systemd-journald-dev-log.socket":          true,
	"systemd-journald.socket":                  true,
	"systemd-networkd.socket":                  true,
	// Proxmox-injected services in LXC templates
	"proxmox-regenerate-snakeoil.service": true,
	// Debian/Ubuntu LXC — journald, networkd, getty cannot run fully in containers
	"systemd-journald.service":          true,
	"systemd-networkd.service":          true,
	"systemd-journal-flush.service":     true,
	"systemd-network-generator.service": true,
	"console-getty.service":             true,
	"container-getty@.service":          true, // matches container-getty@1.service etc.
	// tmpfiles-clean fails in unprivileged LXC — no access to protected dirs
	"systemd-tmpfiles-clean.service": true,
	"systemd-tmpfiles-clean.timer":   true,
}

func filterUnits(units []string, ignore map[string]bool) []string {
	out := units[:0]
	for _, u := range units {
		if ignore[u] {
			continue
		}
		// Handle template instances: container-getty@1.service matches container-getty@.service
		if at := strings.Index(u, "@"); at >= 0 {
			if dot := strings.LastIndex(u, "."); dot > at {
				templateKey := u[:at+1] + u[dot:] // e.g. "container-getty@.service"
				if ignore[templateKey] {
					continue
				}
			}
		}
		out = append(out, u)
	}
	return out
}

func listUnits(ctx context.Context, state string) []string {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", // #nosec G204 -- command is hardcoded "systemctl"; state is from internal enum values, not user input
		"--state="+state, "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil
	}
	return parseUnitList(strings.NewReader(string(out)))
}

func (c *SystemdCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" || !platform.SystemdAvailable() {
		return &models.SystemdInfo{Available: false}, nil
	}

	failed := filterUnits(listUnits(ctx, "failed"), cloudInitUnits)
	slowUnits, totalBoot := collectBootTimes(ctx)

	return &models.SystemdInfo{
		Available:    true,
		FailedUnits:  failed,
		StuckUnits:   nil,
		SlowUnits:    slowUnits,
		TotalBootSec: totalBoot,
	}, nil
}

// collectBootTimes runs systemd-analyze blame and returns the top 3 slow units
// plus total boot time. Units over 10s are considered slow.
// Returns nil slice and 0 if systemd-analyze is unavailable or fails.
func collectBootTimes(ctx context.Context) ([]models.SlowUnit, float64) {
	// Get total boot time first
	timeOut, err := exec.CommandContext(ctx, "systemd-analyze", "time").Output() // #nosec G204
	if err != nil {
		return nil, 0
	}
	totalBoot := parseAnalyzeTime(string(timeOut))

	// Get per-unit breakdown
	blameOut, err := exec.CommandContext(ctx, "systemd-analyze", "blame", "--no-pager").Output() // #nosec G204
	if err != nil {
		return nil, totalBoot
	}

	return parseBlameSlowUnits(string(blameOut)), totalBoot
}

// parseBlameSlowUnits parses `systemd-analyze blame` output into the top 3 slow
// service units (≥5s), skipping cloud-init and other infrastructure noise.
func parseBlameSlowUnits(blameOut string) []models.SlowUnit {
	var slow []models.SlowUnit
	for _, line := range strings.Split(blameOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "  12.345s unit-name.service" or "1min 52.470s unit-name.service".
		// The duration may span multiple tokens (e.g. "1min 52.470s"); the unit
		// name is always the last field, so the duration is everything before it.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[len(fields)-1]
		dur := parseBlameTime(strings.Join(fields[:len(fields)-1], " "))
		if dur < 5.0 {
			break // blame output is sorted descending — stop early
		}
		// Skip non-service units and known infrastructure units
		if !strings.Contains(name, ".") || cloudInitUnits[name] {
			continue
		}
		slow = append(slow, models.SlowUnit{Name: name, Duration: dur})
		if len(slow) >= 3 {
			break
		}
	}
	return slow
}

// parseAnalyzeTime extracts total boot time in seconds from systemd-analyze time output.
// Format: "Startup finished in 1.234s (kernel) + 2.345s (initrd) + 3.456s (userspace) = 7.035s"
func parseAnalyzeTime(out string) float64 {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "=") {
			continue
		}
		eqIdx := strings.LastIndex(line, "= ")
		if eqIdx < 0 {
			continue
		}
		total := strings.TrimSpace(line[eqIdx+2:])
		return parseBlameTime(total)
	}
	return 0
}

// parseBlameTime parses a systemd time string like "12.345s", "1min 3.456s", "1h 2min 3s".
func parseBlameTime(s string) float64 {
	s = strings.TrimSpace(s)
	total := 0.0
	// Handle compound times: "1min 3.456s"
	parts := strings.Fields(s)
	for _, p := range parts {
		switch {
		case strings.HasSuffix(p, "ms"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(p, "ms"), 64)
			total += n / 1000
		case strings.HasSuffix(p, "s") && !strings.HasSuffix(p, "ms"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(p, "s"), 64)
			total += n
		case strings.HasSuffix(p, "min"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(p, "min"), 64)
			total += n * 60
		case strings.HasSuffix(p, "h"):
			n, _ := strconv.ParseFloat(strings.TrimSuffix(p, "h"), 64)
			total += n * 3600
		}
	}
	return total
}
