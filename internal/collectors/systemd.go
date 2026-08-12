package collectors

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type SystemdCollector struct{}

func NewSystemdCollector() *SystemdCollector { return &SystemdCollector{} }

func (c *SystemdCollector) Name() string           { return "Systemd" }
func (c *SystemdCollector) Timeout() time.Duration { return 3 * time.Second }

// parseUnitList parses `systemctl list-units --no-legend --no-pager --plain` output.
// Each line's first field that contains "." is the unit name.
func parseUnitList(r io.Reader) ([]string, error) {
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
	if err := scanner.Err(); err != nil {
		return units, fmt.Errorf("scanning unit list: %w", err)
	}
	return units, nil
}

// cloudInitServiceUnits are the cloud-init provisioning services. They are split
// out of cloudInitUnits because their failure is benign ONLY inside a container
// (LXC/Docker), where cloud-init cannot run and systemd marks them failed. On a
// real VM or bare metal a failed cloud-config/cloud-final is a GENUINE
// provisioning error — swallowing it unconditionally read green on a host whose
// cloud-init had actually failed (false-OK found on a VMware Photon VM). The
// failed-unit verdict therefore suppresses these only when InContainer; the
// log-crash and boot-blame NOISE filters still suppress them unconditionally
// (they filter chatter, not health verdicts) via cloudInitOrNoiseUnit.
var cloudInitServiceUnits = map[string]bool{
	"cloud-final.service":      true,
	"cloud-config.service":     true,
	"cloud-init.service":       true,
	"cloud-init-local.service": true,
}

// cloudInitOrNoiseUnit reports whether a unit is environmental noise for the
// log-crash and boot-blame filters, which suppress cloud-init unconditionally
// (a slow or chatty cloud-init there is not a swallowed failure). Checks the
// general noise set and the cloud-init services split out of it, both with
// template-instance matching.
func cloudInitOrNoiseUnit(u string) bool {
	return unitIgnored(u, cloudInitUnits) || unitIgnored(u, cloudInitServiceUnits)
}

var cloudInitUnits = map[string]bool{
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

// benignSysupdateUnits are the systemd-sysupdate units that fail with "No transfer
// definitions found" (exit 1) and sit permanently "failed" when no *.transfer files
// are configured. systemd ships BOTH the apply timer (systemd-sysupdate.service)
// AND the reboot variant (systemd-sysupdate-reboot.service) enabled; on a default
// VMware Photon OS box, with zero transfers, EITHER can be the one in the failed
// list, so both must be covered (the -reboot sibling was missed initially and
// false-CRIT'd live).
var benignSysupdateUnits = map[string]bool{
	"systemd-sysupdate.service":        true,
	"systemd-sysupdate-reboot.service": true,
}

// dropBenignSysupdate removes the benign systemd-sysupdate units from the
// failed-units list when no transfer definitions are configured on disk. The
// suppression is reason-aware, NOT unconditional: when transfers ARE configured the
// service can fail for a real reason (a failed update), and that failure is kept.
func dropBenignSysupdate(failed []string) []string {
	return dropSysupdateIf(failed, sysupdateUnconfigured())
}

// dropSysupdateIf removes the benign systemd-sysupdate units from failed only when
// unconfigured is true. Split out (impure glob in dropBenignSysupdate, pure list
// logic here) so the suppression rule is unit-testable without touching the real
// filesystem.
func dropSysupdateIf(failed []string, unconfigured bool) []string {
	if !unconfigured {
		return failed
	}
	out := failed[:0]
	for _, u := range failed {
		if !benignSysupdateUnits[u] {
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
	return slices.Contains(units, name)
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

// suppressCloudInitNoise removes benign cloud-init / LXC noise from a failed-unit
// list. The general noise set is always removed; the cloud-init SERVICES are
// removed only inContainer — on a VM / bare metal their failure is a real
// provisioning error that must surface (the false-OK this fixes). Pure so the
// container/non-container behaviour is unit-tested without a real host.
func suppressCloudInitNoise(failedRaw []string, inContainer bool) []string {
	failed := filterUnits(failedRaw, cloudInitUnits)
	if inContainer {
		failed = filterUnits(failed, cloudInitServiceUnits)
	}
	return failed
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
func filterBenignFailedUnits(units []models.SystemdUnit, inContainer bool) []models.SystemdUnit {
	sysupdateBenign := sysupdateUnconfigured()
	out := units[:0]
	for _, u := range units {
		if unitIgnored(u.Name, cloudInitUnits) {
			continue
		}
		// Cloud-init service failure is benign only in a container (see
		// cloudInitServiceUnits) — on a real VM it must surface, matching the
		// health SystemdCollector path.
		if inContainer && unitIgnored(u.Name, cloudInitServiceUnits) {
			continue
		}
		if sysupdateBenign && benignSysupdateUnits[u.Name] {
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
// sshdConnInstancePrefixes are the socket-activated per-connection sshd templates
// whose instances are otherwise suppressed wholesale (cloudInitUnits["sshd@.service"]).
var sshdConnInstancePrefixes = []string{"sshd@", "ssh@"}

// isSSHDConnInstance reports whether u is a per-connection sshd template INSTANCE
// (sshd@<conn>.service) rather than the bare template or the main daemon unit.
func isSSHDConnInstance(u string) bool {
	for _, p := range sshdConnInstancePrefixes {
		if strings.HasPrefix(u, p) && len(u) > len(p) && u[len(p)] != '.' {
			return true
		}
	}
	return false
}

// sshdMaxInspect caps how many failed sshd@ instances we query for exit status, so a
// port-scanned host with a large benign pile doesn't trigger a systemctl-show storm.
const sshdMaxInspect = 20

// nonBenignSSHDInstances returns the per-connection sshd@ instances in units that
// failed for a REAL reason — an ExecMainStatus other than 255 (the dropped-before-auth
// signature of a scan / LB probe / kex abort) or 0. The blanket sshd@ suppression
// rightly hides that benign pile, but would also hide a genuine per-connection fault
// (e.g. an unreadable host key fails every connection with a different status). This
// adds those back. Additive and fail-safe: a status that can't be read is left
// suppressed (the prior behaviour), so it can only surface more, never re-flood.
func nonBenignSSHDInstances(ctx context.Context, units []string) []string {
	return filterNonBenignSSHD(units, func(u string) (string, bool) {
		s, err := runCmd(ctx, "systemctl", "show", u, "-p", "ExecMainStatus", "--value")
		return strings.TrimSpace(s), err == nil
	})
}

// filterNonBenignSSHD is the pure core of nonBenignSSHDInstances: given a status
// lookup (ExecMainStatus, ok), it returns the sshd@ instances that failed non-benign.
// statusOf returning ok=false (unreadable) leaves the instance suppressed (fail-safe).
func filterNonBenignSSHD(units []string, statusOf func(string) (status string, ok bool)) []string {
	var out []string
	inspected := 0
	for _, u := range units {
		if !isSSHDConnInstance(u) {
			continue
		}
		if inspected >= sshdMaxInspect {
			break
		}
		inspected++
		status, ok := statusOf(u)
		if !ok {
			continue // can't read → leave suppressed
		}
		switch status {
		case "", "0", "255": // success / dropped-before-auth → benign
		default:
			out = append(out, u)
		}
	}
	return out
}

func listUnits(ctx context.Context, state string) ([]string, error) {
	out, err := runCmd(ctx, "systemctl", "list-units",
		"--state="+state, "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return nil, err
	}
	return parseUnitList(strings.NewReader(out))
}

// systemdPresentViaSource reports whether systemd is the init system, routed through the
// active Source so the gate is RECORDED on capture and REPLAYED faithfully. A live
// platform.SystemdAvailable() probes the replaying host, so replaying a systemd guest's
// bundle on a non-systemd host (a slim container, macOS, Alpine) dropped the whole
// Systemd check — and with it any failed units — a false-OK in `dsd replay` / `dsd diff`
// / `dsd migrate certify`. Found by the migrate-certify live test (a failed unit on the
// destination went undetected when the bundle was replayed in a non-systemd container).
func systemdPresentViaSource() bool {
	return fileExists("/run/systemd/private") || fileExists("/run/systemd/system")
}

func (c *SystemdCollector) Collect(ctx context.Context) (any, error) {
	if runtime.GOOS == "darwin" || !systemdPresentViaSource() {
		return &models.SystemdInfo{Available: false}, nil
	}

	failedRaw, failedErr := listUnits(ctx, "failed")
	failed := suppressCloudInitNoise(failedRaw, ContainerContextViaSource().InContainer)
	failed = dropBenignSysupdate(failed)
	// The blanket sshd@ suppression hides the benign dropped-before-auth pile, but
	// would also hide a real per-connection sshd fault — add those (non-255) back.
	failed = append(failed, nonBenignSSHDInstances(ctx, failedRaw)...)
	slowUnits, totalBoot := collectBootTimes(ctx)

	return &models.SystemdInfo{
		Available:          true,
		FailedUnits:        failed,
		FailedUnitsUnknown: failedErr != nil,
		NeedsDaemonReload:  systemdNeedsReload(ctx),
		StuckUnits:         nil,
		SlowUnits:          slowUnits,
		TotalBootSec:       totalBoot,
		SystemState:        systemRunningState(ctx),
	}, nil
}

// systemRunningState returns the overall system state from
// `systemctl is-system-running` (running / degraded / maintenance / starting / …).
// The command exits non-zero for any non-"running" state but still prints the word
// to stdout, so runCmdOutput is used to keep that output regardless of exit. The
// key signal is "maintenance" — the system booted into rescue.target/emergency.target
// rather than its default target (a failed boot, e.g. an fsck failure dropping the
// host to an emergency shell).
func systemRunningState(ctx context.Context) string {
	out, _ := runCmdOutput(ctx, "systemctl", "is-system-running")
	return strings.TrimSpace(out)
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
//
// blame's stdout is untrusted external-tool output; it is documented as sorted
// descending by duration, but truncated/unsorted/adversarial output must not
// cause a later genuinely-slow unit to be silently dropped. Every line is
// scanned (no early break on the first sub-threshold line) and candidates are
// sorted by duration before capping at 3.
func parseBlameSlowUnits(blameOut string, exclude func(string) bool) []models.SlowUnit {
	var slow []models.SlowUnit
	for line := range strings.SplitSeq(blameOut, "\n") {
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
			continue
		}
		// Skip non-service units (device/mount/socket/etc. — see blameSkipSuffixes;
		// these are waits, not fixable slow services, and .device units are VM
		// console noise) and known infrastructure (cloud-init) units.
		if !strings.Contains(name, ".") || isNonServiceBlameUnit(name) || cloudInitOrNoiseUnit(name) {
			continue
		}
		// Timer-triggered jobs (apt-daily*, fstrim, man-db, …) appear in blame with
		// large durations but run on a schedule, not during boot — not boot offenders.
		if exclude != nil && exclude(name) {
			continue
		}
		slow = append(slow, models.SlowUnit{Name: name, Duration: dur})
	}
	slices.SortFunc(slow, func(a, b models.SlowUnit) int {
		return cmp.Compare(b.Duration, a.Duration)
	})
	if len(slow) > 3 {
		slow = slow[:3]
	}
	return slow
}

// parseAnalyzeTime extracts total boot time in seconds from systemd-analyze time output.
// Format: "Startup finished in 1.234s (kernel) + 2.345s (initrd) + 3.456s (userspace) = 7.035s"
func parseAnalyzeTime(out string) float64 {
	for line := range strings.SplitSeq(out, "\n") {
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
	parts := strings.FieldsSeq(s)
	for p := range parts {
		switch {
		case strings.HasSuffix(p, "ms"):
			n := parseFloat(strings.TrimSuffix(p, "ms"))
			total += n / 1000
		case strings.HasSuffix(p, "s") && !strings.HasSuffix(p, "ms"):
			n := parseFloat(strings.TrimSuffix(p, "s"))
			total += n
		case strings.HasSuffix(p, "min"):
			n := parseFloat(strings.TrimSuffix(p, "min"))
			total += n * 60
		case strings.HasSuffix(p, "h"):
			n := parseFloat(strings.TrimSuffix(p, "h"))
			total += n * 3600
		}
	}
	return total
}
