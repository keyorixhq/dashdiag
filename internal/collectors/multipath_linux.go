//go:build linux

package collectors

import (
	"bufio"
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MultipathCollector reads DM-MPIO multipath status via multipathd.
type MultipathCollector struct{}

func NewMultipathCollector() *MultipathCollector     { return &MultipathCollector{} }
func (c *MultipathCollector) Name() string           { return "Multipath" }
func (c *MultipathCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *MultipathCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.MultipathInfo{}

	// Detect multipath presence before running commands
	if !IsMultipathPresent() {
		return info, nil
	}

	info.Available = true

	// Try multipathd show paths (detailed, machine-readable)
	out, err := runCmd(ctx, "multipathd", "show", "paths", "format", "%d %t %s %m")
	if err != nil {
		// Fallback: multipath -l (human-readable but parseable)
		out, err = runCmd(ctx, "multipath", "-l")
		if err != nil {
			info.Status = "error"
			info.StatusReason = "multipathd running but paths unreadable"
			return info, nil // actionable error — keep the row
		}
		info.Devices = parseMultipathL(out)
	} else {
		info.Devices = parseMultipathShow(out)
	}

	if len(info.Devices) == 0 {
		// multipathd installed/running but no multipath maps configured — common
		// when multipath-tools is present without any SAN. Absent, gate off.
		return nil, nil
	}
	return info, nil
}

// IsMultipathPresent returns true when multipath is genuinely in use: the multipathd
// daemon is running, OR there are dm-multipath maps in sysfs. The binary being
// installed is NOT enough — multipath-tools is frequently pulled in as a dependency
// on hosts with no SAN, daemon never started, no maps. There a non-root probe
// (root-only socket / devmapper ioctl) can fail → a spurious "multipath path health
// could NOT be verified" WARN on a host with no multipath at all. Gating on
// daemon-running OR maps-present registers the collector only where multipath exists,
// while still covering a degraded host whose maps persist after multipathd stopped.
func IsMultipathPresent() bool {
	if _, err := lookPath("multipathd"); err != nil {
		return false
	}
	return multipathDaemonRunning() || multipathMapsPresent("/sys/block")
}

// multipathDaemonRunning reports whether the real multipathd daemon is
// actually running, via its control socket rather than /proc/<pid>/comm.
// /proc/<pid>/comm is self-reported and any unprivileged local process can
// set it to "multipathd" (prctl(PR_SET_NAME) or argv[0]) — that is not proof
// the daemon is running, and previously let a spoofed comm make
// IsMultipathPresent() report a running daemon when it wasn't, producing a
// misleading "multipathd running but paths unreadable" diagnosis instead of
// the accurate "installed, daemon not running" state (Finding:
// internal-collectors-21-08). multipathd's control socket lives under /run,
// which an unprivileged process cannot write to — only the real daemon
// (started as root) can create it.
func multipathDaemonRunning() bool {
	return fileExists("/run/multipathd.sock") || fileExists("/var/run/multipathd.sock")
}

// multipathMapsPresent reports whether any device-mapper device in sysBlockDir is a
// multipath map (its dm/uuid starts with "mpath-"). sysfs is world-readable, so this
// detects real multipath regardless of privilege or daemon state.
func multipathMapsPresent(sysBlockDir string) bool {
	entries, err := readDirEntries(sysBlockDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		uuid, err := readFile(filepath.Join(sysBlockDir, e.Name(), "dm", "uuid"))
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(uuid)), "mpath-") {
			return true
		}
	}
	return false
}

// parseMultipathShow parses "multipathd show paths format %d %t %s %m" output.
// Columns: device, state, serial, map (DM device)
func parseMultipathShow(out string) []models.MultipathDevice {
	deviceMap := make(map[string]*models.MultipathDevice)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "hcil") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		dev := fields[0]
		state := fields[1]
		// Skip the column-header row that `multipathd show paths format` prints —
		// "dev dm_st vend/prod/rev multipath". Parsed as a path it became a phantom
		// device "multipath" whose one path was in state "dm_st" (not active/ready →
		// counted as failed → a spurious "degraded" device → a false CRIT on every
		// real multipath host). Real %d/%t values are never literally "dev"/"dm_st".
		if dev == "dev" && state == "dm_st" {
			continue
		}
		// The map name (%m) is the LAST field, not fields[3]: the vend/prod/rev
		// field (%s) can contain spaces (e.g. real output "ATA,APPLE SSD SM128C"),
		// which shifts the positional columns and made fields[3] a product token.
		// Reading from the end is robust to spaces in %s.
		dm := fields[len(fields)-1]
		// An [orphan] path belongs to no multipath map — it's a plain disk, not a
		// multipath device. Skip it; otherwise a host with multipath-tools installed
		// but no SAN (any Ubuntu box that pulled it in as a dependency) reports a
		// phantom "all paths failed — device unavailable" CRIT on a healthy disk.
		if dm == "[orphan]" || dm == "" {
			continue
		}

		d, ok := deviceMap[dm]
		if !ok {
			d = &models.MultipathDevice{Name: dm, DM: dm}
			deviceMap[dm] = d
		}
		d.TotalPaths++
		path := models.MultipathPath{Device: dev, State: state, DM: dm}
		if state == "active" || state == "ready" {
			d.ActivePaths++
		} else {
			d.FailedPaths++
		}
		d.Paths = append(d.Paths, path)
	}

	devices := make([]models.MultipathDevice, 0, len(deviceMap))
	for _, d := range deviceMap {
		if d.FailedPaths > 0 {
			d.State = "degraded"
		} else {
			d.State = "active"
		}
		devices = append(devices, *d)
	}
	// deviceMap is a map, so sort for deterministic output (stable JSON across
	// runs/replays — TRIAGE Section I).
	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	return devices
}

// parseMultipathL parses "multipath -l" text output.
// Less reliable but widely available.
func parseMultipathL(out string) []models.MultipathDevice {
	var devices []models.MultipathDevice
	var current *models.MultipathDevice
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// Device header line starts without leading whitespace and contains "dm-"
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.Contains(line, "dm-") {
			if current != nil {
				devices = append(devices, *current)
			}
			// Extract DM device name
			fields := strings.Fields(line)
			dm := ""
			for _, f := range fields {
				if strings.HasPrefix(f, "dm-") {
					dm = f
					break
				}
			}
			current = &models.MultipathDevice{Name: fields[0], DM: dm}
			continue
		}
		if current == nil {
			continue
		}
		trimmed := strings.TrimSpace(line)
		// Path lines contain "_ sdX" or similar
		if strings.Contains(trimmed, " sd") || strings.Contains(trimmed, " nvme") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				state := "active"
				for _, f := range fields {
					if f == "failed" || f == "faulty" {
						state = "failed"
					}
				}
				dev := fields[len(fields)-1]
				current.Paths = append(current.Paths, models.MultipathPath{
					Device: dev, State: state, DM: current.DM,
				})
				current.TotalPaths++
				if state == "failed" {
					current.FailedPaths++
				} else {
					current.ActivePaths++
				}
			}
		}
	}
	if current != nil {
		devices = append(devices, *current)
	}
	for i := range devices {
		if devices[i].FailedPaths > 0 {
			devices[i].State = "degraded"
		} else {
			devices[i].State = "active"
		}
	}
	return devices
}
