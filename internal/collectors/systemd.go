package collectors

import (
	"bufio"
	"context"
	"io"
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
	// Per-connection socket-activated sshd instances (sshd@.service template,
	// the default on Photon/Fedora). A connection dropped before auth completes —
	// a port scan, a TCP/LB health probe, kex_exchange_identification — leaves the
	// transient unit "failed" (status 255) until it is garbage-collected. These
	// accumulate into a pile of false CRITs that have nothing to do with the SSH
	// daemon's health (sshd.service / ssh.service are checked separately and are
	// NOT filtered here). Matched via filterUnits' template-instance collapsing
	// (sshd@<addr:port-addr:port>.service → sshd@.service).
	"sshd@.service": true,
	"ssh@.service":  true,
}

// dropBenignSysupdate removes systemd-sysupdate.service from the failed-units
// list when no transfer definitions are configured on disk. systemd ships
// systemd-sysupdate.timer enabled, but with no *.transfer files in
// /etc/sysupdate.d or /usr/lib/sysupdate.d the service exits 1 ("No transfer
// definitions found") on every timer firing and sits permanently "failed" — a
// benign default state (verified on VMware Photon OS 5.0, which enables the timer
// but ships zero transfers, so dsd false-CRIT'd on every box). The suppression is
// reason-aware, NOT unconditional: when transfers ARE configured the service can
// fail for a real reason (a failed update), and that failure is kept.
func dropBenignSysupdate(failed []string) []string {
	return dropSysupdateIf(failed, sysupdateUnconfigured())
}

// dropSysupdateIf removes systemd-sysupdate.service from failed only when
// unconfigured is true. Split out (impure glob in dropBenignSysupdate, pure list
// logic here) so the suppression rule is unit-testable without touching the real
// filesystem.
func dropSysupdateIf(failed []string, unconfigured bool) []string {
	const unit = "systemd-sysupdate.service"
	if !unconfigured || !containsUnit(failed, unit) {
		return failed
	}
	out := failed[:0]
	for _, u := range failed {
		if u != unit {
			out = append(out, u)
		}
	}
	return out
}

// sysupdateUnconfigured reports whether systemd-sysupdate has no transfer
// definitions on disk — in which case its only possible outcome is the benign
// "No transfer definitions found" failure (there is no update for it to apply, so
// suppressing it cannot hide a real update failure).
func sysupdateUnconfigured() bool {
	for _, dir := range []string{"/etc/sysupdate.d", "/usr/lib/sysupdate.d"} {
		if matches, _ := glob(dir + "/*.transfer"); len(matches) > 0 {
			return false
		}
	}
	return true
}

func containsUnit(units []string, name string) bool {
	for _, u := range units {
		if u == name {
			return true
		}
	}
	return false
}

// unitIgnored reports whether a unit name is in the ignore set, matching both the
// literal name and its template form (container-getty@1.service →
// container-getty@.service; sshd@<conn>.service → sshd@.service).
func unitIgnored(u string, ignore map[string]bool) bool {
	if ignore[u] {
		return true
	}
	if at := strings.Index(u, "@"); at >= 0 {
		if dot := strings.LastIndex(u, "."); dot > at {
			if ignore[u[:at+1]+u[dot:]] { // e.g. "container-getty@.service"
				return true
			}
		}
	}
	return false
}

func filterUnits(units []string, ignore map[string]bool) []string {
	out := units[:0]
	for _, u := range units {
		if !unitIgnored(u, ignore) {
			out = append(out, u)
		}
	}
	return out
}

// filterBenignFailedUnits removes environmental-noise failed units — the SAME set
// the health SystemdCollector suppresses — from a `dsd services deep` failed-unit
// list. Without it the two verdicts diverge sharply: a long-lived / cloned VM
// accrues dozens of transient sshd@<conn> units, so `dsd services deep`
// false-CRIT'd "47 failed units" while `dsd health` correctly read Systemd OK
// (observed live on VMware Photon OS). Shares cloudInitUnits + the benign
// systemd-sysupdate rule so the paths cannot drift.
func filterBenignFailedUnits(units []models.SystemdUnit) []models.SystemdUnit {
	sysupdateBenign := sysupdateUnconfigured()
	out := units[:0]
	for _, u := range units {
		if unitIgnored(u.Name, cloudInitUnits) {
			continue
		}
		if sysupdateBenign && u.Name == "systemd-sysupdate.service" {
			continue
		}
		out = append(out, u)
	}
	return out
}

// listUnits returns the unit names in the given state. The error is propagated
// (not swallowed) so the caller can tell "the query failed" apart from "zero
// units in this state" — collapsing the two into an empty list reads a transient
// systemctl failure (e.g. the 3s Timeout tripping under load, exactly when units
// are likely failing) as a silent healthy verdict.
func listUnits(ctx context.Context, state string) ([]string, error) {
	out, err := runCmd(ctx, "systemctl", "list-units",
		"--state="+state, "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, err
	}
	return parseUnitList(strings.NewReader(out)), nil
}

func (c *SystemdCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" || !platform.SystemdAvailable() {
		return &models.SystemdInfo{Available: false}, nil
	}

	failedRaw, failedErr := listUnits(ctx, "failed")
	failed := filterUnits(failedRaw, cloudInitUnits)
	failed = dropBenignSysupdate(failed)
	slowUnits, totalBoot := collectBootTimes(ctx)

	return &models.SystemdInfo{
		Available:          true,
		FailedUnits:        failed,
		FailedUnitsUnknown: failedErr != nil,
		NeedsDaemonReload:  systemdNeedsReload(ctx),
		StuckUnits:         nil,
		SlowUnits:          slowUnits,
		TotalBootSec:       totalBoot,
	}, nil
}

// collectBootTimes runs systemd-analyze blame and returns the top 3 slow units
// plus total boot time. Units over 10s are considered slow.
// Returns nil slice and 0 if systemd-analyze is unavailable or fails.
func collectBootTimes(ctx context.Context) ([]models.SlowUnit, float64) {
	// Get total boot time first
	timeOut, err := runCmd(ctx, "systemd-analyze", "time")
	if err != nil {
		return nil, 0
	}
	totalBoot := parseAnalyzeTime(timeOut)

	// Get per-unit breakdown
	blameOut, err := runCmd(ctx, "systemd-analyze", "blame", "--no-pager")
	if err != nil {
		return nil, totalBoot
	}

	return parseBlameSlowUnits(string(blameOut), timerTriggeredExcluder(ctx)), totalBoot
}

// timerTriggeredExcluder returns a predicate that reports whether a unit is
// started by a .timer — i.e. a scheduled job, not part of the boot transaction.
// `systemd-analyze blame` lists such units by their activation duration even
// though they run on a schedule well after boot; apt-daily-upgrade.service
// routinely shows 20-30s in blame on Debian/Ubuntu while running post-boot via
// apt-daily-upgrade.timer. Without this they false-WARN as "slow boot unit" on
// essentially every Debian/Ubuntu host. Fails open (returns false → unit kept)
// when systemctl can't be queried, so we never hide a genuine boot offender.
func timerTriggeredExcluder(ctx context.Context) func(string) bool {
	return func(unit string) bool {
		out, err := runCmd(ctx, "systemctl", "show", "-p", "TriggeredBy", "--value", unit)
		if err != nil {
			return false
		}
		return strings.Contains(out, ".timer")
	}
}

// blameSkipSuffixes are systemd unit types that appear in `systemd-analyze
// blame` but are not actionable slow-boot offenders. .device/.mount/.socket/etc.
// usually reflect *waiting*, not a fixable slow service — notably, virtio/serial
// console .device units on a VM routinely sit at the ~24s device timeout, which
// would otherwise dominate the slow-boot WARN on every guest (and the pilot's
// fleet is all VMs). Shared by parseBlame and parseBlameSlowUnits so the two
// blame parsers cannot drift apart again.
var blameSkipSuffixes = []string{".device", ".socket", ".mount", ".target", ".path", ".swap", ".automount"}

func isNonServiceBlameUnit(name string) bool {
	for _, s := range blameSkipSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// parseBlameSlowUnits parses `systemd-analyze blame` output into the top 3 slow
// service units (≥5s), skipping cloud-init and other infrastructure noise.
// exclude (may be nil) drops units it returns true for — used to remove
// timer-triggered async jobs that blame lists but which never gated boot.
func parseBlameSlowUnits(blameOut string, exclude func(string) bool) []models.SlowUnit {
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
		// Skip non-service units (device/mount/socket/etc. — see blameSkipSuffixes;
		// these are waits, not fixable slow services, and .device units are VM
		// console noise) and known infrastructure (cloud-init) units.
		if !strings.Contains(name, ".") || isNonServiceBlameUnit(name) || cloudInitUnits[name] {
			continue
		}
		// Timer-triggered jobs (apt-daily*, fstrim, man-db, …) appear in blame with
		// large durations but run on a schedule, not during boot — not boot offenders.
		if exclude != nil && exclude(name) {
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
