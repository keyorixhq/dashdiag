package analysis

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	catKernelSec          = "KernelSec"
	catSysctl             = "Sysctl"
	inspectW              = "to inspect: w"
	inspectFreeH          = "to inspect: free -h"
	inspectSysctlSwap     = "to inspect: sysctl vm.swappiness"
	inspectSysctlMaxMap   = "to inspect: sysctl vm.max_map_count"
	inspectJournalDiskUse = "to inspect: journalctl --disk-usage"
	fixSysctlMaxMapCount  = "to fix: sysctl -w vm.max_map_count=262144"
	persistMaxMapCount    = "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"
	fixSysctlSwappiness   = "to fix: sysctl -w vm.swappiness=10"
	persistSwappiness     = "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"
	fixSELinuxRelabel     = "to fix:     touch /.autorelabel && reboot"
)

func checkFD(fd models.FDInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if l := levelPct(fd.UsedPct, thresh.FDSystemWarnPct, thresh.FDSystemCritPct); l != "" {
		out = append(out, insight(l, "FDLimits",
			fmt.Sprintf("system FD usage at %.0f%% (%d / %d open)", fd.UsedPct, fd.OpenCount, fd.MaxCount),
			[]string{"to inspect: cat /proc/sys/fs/file-nr", "to inspect: lsof | wc -l"},
		))
	}
	for _, proc := range fd.HotProcesses {
		if proc.UsedPct >= thresh.FDProcWarnPct {
			out = append(out, insight("WARN", "FDLimits",
				fmt.Sprintf("process %s (PID %d) has %d/%d FDs open (%.0f%%)",
					proc.Name, proc.PID, proc.OpenFDs, proc.SoftLimit, proc.UsedPct),
				[]string{
					fmt.Sprintf("to inspect: ls /proc/%d/fd | wc -l", proc.PID),
					fmt.Sprintf("to inspect: lsof -p %d | tail -20", proc.PID),
				},
			))
		}
	}
	if fd.DeletedOpenSizeGB >= 1 {
		out = append(out, insight("WARN", "FDLimits",
			fmt.Sprintf("%.1f GB held by deleted-but-open files", fd.DeletedOpenSizeGB),
			[]string{"to inspect: lsof | grep deleted | head -20", "to inspect: lsof | grep deleted | awk '{sum+=$7} END{print sum/1024/1024/1024\" GB\"}'"},
		))
	}
	return out
}
func checkSystemd(sys models.SystemdInfo) []models.Insight {
	if !sys.Available {
		return nil // not present on this platform — hide the row entirely
	}
	out := make([]models.Insight, 0, len(sys.FailedUnits))

	// The failed-unit query did not run (systemctl list-units errored or hit the
	// 3s timeout — most likely under load, exactly when units are failing). Say
	// so instead of letting an empty list read as a silent healthy verdict.
	if sys.FailedUnitsUnknown {
		out = append(out, insight("INFO", "Systemd",
			"could not list failed units — systemctl list-units did not complete; failed-unit status is unverified",
			[]string{
				"to check manually: systemctl --failed",
				"note: the query may have timed out under load — re-run when the host is quieter",
			},
		))
	}

	// Booted into emergency/rescue mode — the system did not reach its default
	// target. `systemctl is-system-running` reports "maintenance" when
	// rescue.target/emergency.target is the active target (e.g. a root/fstab fsck
	// failure dropped the host to an emergency shell — the Dell VxRail /
	// cloned-appliance fingerprint). Only "maintenance" fires here; "degraded" (a
	// failed unit on an otherwise-normal boot) is already covered by the per-unit
	// CRITs below, so it must NOT double-fire.
	if sys.SystemState == "maintenance" {
		out = append(out, insight("CRIT", "Systemd",
			"system is in emergency/rescue mode — the boot did not complete (a maintenance shell is active, not the default target)",
			[]string{
				"to inspect: journalctl -b -p err --no-pager",
				"to inspect: systemctl --failed",
				"common cause: a root/fstab filesystem failed its boot-time fsck — check systemctl status systemd-fsck-root.service",
				"to resume normal boot once fixed: systemctl default   (or reboot)",
			},
		))
	}

	for _, unit := range sys.FailedUnits {
		out = append(out, failedUnitInsight(unit, sys.SELinuxEnforcing, sys.ZFSPoolsPresent))
	}

	// Modified unit files not yet reloaded — the running service is using stale
	// config (admin edited the unit and forgot `systemctl daemon-reload`). A
	// definitive systemd signal (NeedsDaemonReload=yes), not a heuristic.
	if n := len(sys.NeedsDaemonReload); n > 0 {
		out = append(out, insight("WARN", "Systemd",
			fmt.Sprintf("%d unit(s) have modified files pending reload — running stale config: %s",
				n, strings.Join(firstN(sys.NeedsDaemonReload, 5), ", ")),
			[]string{
				"to fix: systemctl daemon-reload",
				"note: the unit file on disk changed since systemd loaded it; restart the unit to apply",
			},
		))
	}

	// Boot slowness — surface top slow units from systemd-analyze blame.
	// Threshold: WARN if any unit > 10s, INFO if total boot > 30s.
	// Research: "systemd-analyze blame tells you which is slow — not why"
	// dsd surfaces the slow units with the next diagnostic step.
	for _, u := range sys.SlowUnits {
		if u.Duration >= 10 {
			hints := make([]string, 0, 6)
			hints = append(hints,
				fmt.Sprintf("to inspect: systemctl status %s", u.Name),
				fmt.Sprintf("to inspect: journalctl -u %s -b", u.Name),
				"to analyse:  systemd-analyze blame",
				"to plot:     systemd-analyze plot > boot.svg",
			)
			// Service-specific fix hints for known slow-boot offenders
			hints = append(hints, slowBootFix(u.Name)...)
			out = append(out, insight("WARN", "Systemd",
				fmt.Sprintf("slow boot unit: %s took %.1fs", u.Name, u.Duration),
				hints,
			))
		}
	}
	if sys.TotalBootSec > 30 && len(sys.SlowUnits) == 0 {
		out = append(out, insight("INFO", "Systemd",
			fmt.Sprintf("total boot time %.0fs — run systemd-analyze blame to find slow units", sys.TotalBootSec),
			[]string{
				"to analyse: systemd-analyze blame",
				"to plot:    systemd-analyze plot > boot.svg",
			},
		))
	}

	return out
}

func checkSysctl(sysctl models.SysctlInfo) []models.Insight { //nolint:cyclop,funlen // NOSONAR — workload-profile switch — each case is a distinct set of checks, splitting would harm readability
	var out []models.Insight

	// somaxconn — the listen() backlog: a TUNING parameter, not a fault. 128 is the
	// historical kernel default (<5.4; e.g. CentOS 7 / RHEL 7) and only matters for a
	// high-connection server under load, where it degrades (SYN-backlog drops) but
	// never fails the system. So WARN at most — never CRIT. The old hard CRIT (<512)
	// flipped every default CentOS 7 / RHEL 7 / older box to CRITICAL on an untouched
	// OS default (found live on CentOS 7; the codebase already treats 128 as a
	// historical default, see correlate.go sysctlAllAtStockDefaults).
	if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 1024 {
		out = append(out, insight("WARN", catSysctl,
			fmt.Sprintf("net.core.somaxconn=%d is low for a high-connection server — kernels <5.4 default to 128; raise to 4096 if this host serves many concurrent connections", sysctl.NetSomaxconn),
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096", "to persist: echo 'net.core.somaxconn=4096' >> /etc/sysctl.d/99-dsd.conf"},
		))
	}

	// PID/task table usage — always checked. PIDCount counts tasks (processes AND
	// threads), matching what kernel.pid_max actually governs.
	if sysctl.KernelPIDMax > 0 {
		pidPct := float64(sysctl.PIDCount) / float64(sysctl.KernelPIDMax) * 100
		if l := levelPct(pidPct, 80, 90); l != "" {
			out = append(out, insight(l, catSysctl,
				fmt.Sprintf("PID/task table at %.0f%% (%d / %d)", pidPct, sysctl.PIDCount, sysctl.KernelPIDMax),
				[]string{"to inspect: cat /proc/sys/kernel/pid_max", "to inspect: cat /proc/loadavg  (4th field: running/total tasks)", "to inspect: ps -eLf | wc -l  (includes threads, unlike ps aux)"},
			))
		}
	}

	// Workload-aware tuning recommendations.
	// Each case adds "to persist:" hints so engineers know the fix survives reboot.
	switch sysctl.Workload {
	case "k8s":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.max_map_count=%d is low for k8s/Elasticsearch (recommended: 262144)", sysctl.VMMaxMapCount),
				[]string{inspectSysctlMaxMap, fixSysctlMaxMapCount, persistMaxMapCount},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 524288 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for k8s (recommended: 524288)", sysctl.FSInotifyWatches),
				[]string{"to inspect: sysctl fs.inotify.max_user_watches", "to fix: sysctl -w fs.inotify.max_user_watches=524288", "to persist: echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.swappiness=%d is high for k8s node (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{inspectSysctlSwap, fixSysctlSwappiness, persistSwappiness},
			))
		}

	case "webserver":
		if sysctl.TCPTWReuse == 0 {
			out = append(out, insight("WARN", catSysctl,
				"net.ipv4.tcp_tw_reuse=0 \u2014 enabling helps high-traffic web servers reuse TIME_WAIT sockets",
				[]string{"to fix: sysctl -w net.ipv4.tcp_tw_reuse=1", "to persist: echo 'net.ipv4.tcp_tw_reuse=1' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.NetRmemMax > 0 && sysctl.NetRmemMax < 16777216 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("net.core.rmem_max=%d is low for high-throughput web server (recommended: 16MB)", sysctl.NetRmemMax),
				[]string{"to inspect: sysctl net.core.rmem_max", "to fix: sysctl -w net.core.rmem_max=16777216", "to persist: echo 'net.core.rmem_max=16777216' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "database":
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.swappiness=%d is high for database workload (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{inspectSysctlSwap, fixSysctlSwappiness, persistSwappiness},
			))
		}
		if sysctl.VMDirtyRatio > 10 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.dirty_ratio=%d is high for database (recommended: \u2264 10 to reduce write latency spikes)", sysctl.VMDirtyRatio),
				[]string{"to inspect: sysctl vm.dirty_ratio", "to fix: sysctl -w vm.dirty_ratio=10", "to fix: sysctl -w vm.dirty_background_ratio=3", "to persist: echo 'vm.dirty_ratio=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "elasticsearch":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("CRIT", catSysctl,
				fmt.Sprintf("vm.max_map_count=%d \u2014 Elasticsearch requires \u2265 262144 or it will refuse to start", sysctl.VMMaxMapCount),
				[]string{inspectSysctlMaxMap, fixSysctlMaxMapCount, persistMaxMapCount},
			))
		}
		if sysctl.VMSwappiness > 1 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.swappiness=%d \u2014 Elasticsearch recommends 1 to minimise GC pauses from swapping", sysctl.VMSwappiness),
				[]string{inspectSysctlSwap, "to fix: sysctl -w vm.swappiness=1", "to persist: echo 'vm.swappiness=1' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "container":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.max_map_count=%d is low for container host running JVM workloads (recommended: 262144)", sysctl.VMMaxMapCount),
				[]string{inspectSysctlMaxMap, fixSysctlMaxMapCount, persistMaxMapCount},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 131072 {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for container host (recommended: 131072+)", sysctl.FSInotifyWatches),
				[]string{"to inspect: sysctl fs.inotify.max_user_watches", "to fix: sysctl -w fs.inotify.max_user_watches=131072", "to persist: echo 'fs.inotify.max_user_watches=131072' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	default: // general production server \u2014 flag values clearly suboptimal for any server role
		// swappiness=60 is the universal kernel default and is harmless on a host
		// with RAM headroom (it never swaps). Only flag a high value when the host
		// is ACTUALLY swapping \u2014 the only time swappiness changes behaviour. Without
		// this gate every stock server WARNed on its default. (SwapActive is injected
		// by the analysis pre-scan from SwapInfo.)
		if sysctl.VMSwappiness > 30 && sysctl.SwapActive {
			out = append(out, insight("WARN", catSysctl,
				fmt.Sprintf("vm.swappiness=%d is high and the host is actively swapping (recommended: \u2264 30; production servers typically use 10)", sysctl.VMSwappiness),
				[]string{"to inspect: cat /proc/sys/vm/swappiness; vmstat 1 5", fixSysctlSwappiness, persistSwappiness},
			))
		}
		// NOTE: no general net.core.rmem_max check here. The kernel default
		// (212992 / ~208KB) is below any "modern throughput" target, so flagging
		// it WARNed on essentially every untuned host \u2014 noise that reads as "this
		// tool doesn't know what normal looks like". rmem_max tuning is workload-
		// specific and is handled in the "webserver" profile (16MB target); a
		// general server running the kernel default is fine.
	}

	return out
}

// slowBootFix returns service-specific fix hints for known slow-boot offenders.
// These are services that are commonly slow and have a well-understood cause + fix.
func slowBootFix(unit string) []string {
	switch unit {
	case "gpu-manager.service":
		// Ubuntu/Mint GPU switching service. Slow on hybrid GPU laptops (AMD+NVIDIA)
		// especially when the iGPU is disabled in BIOS (nothing to switch between).
		return []string{
			"note: gpu-manager detects GPUs for PRIME switching — slow on Optimus laptops",
			"to fix (if not using GPU switching): systemctl disable --now gpu-manager.service",
			"note: safe to disable if you use NVIDIA-only mode or have one GPU",
		}
	case "NetworkManager-wait-online.service":
		// Waits for a network connection before continuing boot.
		// Often blocks boot on servers where network comes up slowly.
		return []string{
			"note: waits for network before continuing boot — often unnecessary on servers",
			"to fix: systemctl disable NetworkManager-wait-online.service",
			"note: safe if nothing critical depends on network at boot time",
		}
	case "plymouth-quit-wait.service":
		// Plymouth boot splash screen — slow when display detection is delayed.
		return []string{
			"note: plymouth boot splash — can be slow on headless or hybrid GPU systems",
			"to fix (headless): systemctl disable plymouth-quit-wait.service",
		}
	case "fwupd-refresh.service":
		// Firmware update metadata refresh — hits the network on boot.
		return []string{
			"note: checks for firmware updates on boot — hits the network",
			"to fix: systemctl disable fwupd-refresh.service  (updates still work manually)",
			"to run manually: fwupdmgr refresh",
		}
	case "snapd.service", "snapd.seeded.service":
		// Snap daemon — slow initialisation especially on first boot or after updates.
		return []string{
			"note: snap daemon initialisation — slow on first boot or after updates",
			"to fix (if not using snaps): systemctl disable --now snapd.service snapd.socket",
			"note: only disable if you have no snap packages installed",
		}
	case "apt-daily.service", "apt-daily-upgrade.service":
		return []string{
			"note: apt background updates running at boot — competes with boot I/O",
			"to fix: systemctl disable apt-daily.service apt-daily-upgrade.service",
			"note: updates will still run from cron/timer — boot impact removed",
		}
	default:
		return nil
	}
}

// isZFSImportUnit reports whether a unit is one of the ZFS pool-import services
// (zfs-import-scan / zfs-import-cache, including the zfs-import@<pool> template
// instances). Their failure is benign on a host that imports no pools of its own.
func isZFSImportUnit(unit string) bool {
	base := unitBaseName(unit) // strips ".service" and any "@instance"
	return base == "zfs-import-scan" || base == "zfs-import-cache" || base == "zfs-import"
}

// failedUnitInsight classifies one failed systemd unit into a single insight:
// a targeted repair hint for boot-filesystem units (fsck/remount), a benign INFO
// for ZFS-import units on a host with no imported pools, or the generic
// "unit failed" CRIT (with an SELinux-AVC hint when SELinux is enforcing).
func failedUnitInsight(unit string, selinuxEnforcing, zfsPoolsPresent bool) models.Insight {
	// Boot-time filesystem units (root remount, fsck) get a targeted repair hint —
	// a failed fsck/remount is the classic cause of a host stuck in emergency mode.
	if isBootFilesystemUnit(unit) {
		return insight("CRIT", "Systemd",
			fmt.Sprintf("boot filesystem unit %s failed — a filesystem check/remount did not complete at boot (can drop the host into emergency mode)", unit),
			[]string{
				fmt.Sprintf("to inspect: systemctl status %s", unit),
				fmt.Sprintf("to inspect: journalctl -u %s -b --no-pager", unit),
				"to find the device: blkid ; cat /etc/fstab",
				"to repair (offline/unmounted): e2fsck -y <device>   (xfs_repair for XFS)",
			})
	}
	// zfs-import-{scan,cache}.service failing is expected/benign on a host that
	// imports no ZFS pools of its own (ZFS HBA passed through to a VM, or unused).
	if isZFSImportUnit(unit) && !zfsPoolsPresent {
		return insight("INFO", "Systemd",
			fmt.Sprintf("unit %s has failed, but no ZFS pools are imported on this host — expected when ZFS is passed through to a VM or unused", unit),
			[]string{
				fmt.Sprintf("to inspect: systemctl status %s", unit),
				"to verify:  zpool list  (empty = no host pools, so the import failure is benign)",
				fmt.Sprintf("to disable: systemctl disable %s  (if this host never imports pools)", unit),
			})
	}
	hints := []string{
		fmt.Sprintf("to inspect: systemctl status %s", unit),
		fmt.Sprintf("to inspect: journalctl -u %s -n 50", unit),
	}
	// SELinux double-layer hint — permission errors from SELinux produce no output
	// in journalctl -u, so admins check standard permissions and find nothing wrong.
	if selinuxEnforcing {
		hints = append(hints,
			"note: SELinux is enforcing — check AVC denials if permissions look correct",
			fmt.Sprintf("to check SELinux: ausearch -m avc -ts recent -c %s", unitBaseName(unit)),
		)
	}
	return insight("CRIT", "Systemd", fmt.Sprintf("unit %s has failed", unit), hints)
}

// isBootFilesystemUnit reports whether a unit is a boot-time filesystem check or
// root remount — systemd-remount-fs, systemd-fsck-root, or a systemd-fsck@<dev>
// instance. A failure here means a filesystem could not be checked/mounted at
// boot, the classic cause of a host stuck in emergency mode.
func isBootFilesystemUnit(unit string) bool {
	return unit == "systemd-remount-fs.service" ||
		unit == "systemd-fsck-root.service" ||
		strings.HasPrefix(unit, "systemd-fsck@")
}

// unitBaseName extracts the base name from a systemd unit for use in ausearch -c.
// e.g. "nginx.service" → "nginx", "my-app@1.service" → "my-app"
func unitBaseName(unit string) string {
	// Strip extension
	if dot := strings.LastIndex(unit, "."); dot > 0 {
		unit = unit[:dot]
	}
	// Strip instance from template units
	if at := strings.LastIndex(unit, "@"); at > 0 {
		unit = unit[:at]
	}
	return unit
}

// extractAVCProcessNames parses comm= fields from SELinux AVC log lines.
// Returns unique process names so we can suggest targeted boolean searches.
// Example: type=AVC ... comm="httpd" ... → ["httpd"]
func extractAVCProcessNames(samples []string) []string {
	seen := map[string]bool{}
	var procs []string
	for _, line := range samples {
		_, after, ok := strings.Cut(line, `comm="`)
		if !ok {
			continue
		}
		rest := after
		end := strings.IndexByte(rest, '"')
		if end <= 0 {
			continue
		}
		proc := rest[:end]
		if !seen[proc] {
			seen[proc] = true
			procs = append(procs, proc)
		}
	}
	return procs
}

//nolint:funlen // flat registry of independent SELinux/AppArmor checks — splitting would harm readability
func checkKernelSecurity(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	seActive := mac.SELinuxPresent && mac.SELinuxMode != "disabled" && mac.SELinuxMode != "unknown"
	seIndeterminate := mac.SELinuxPresent && mac.SELinuxMode == "unknown"
	aaActive := mac.AppArmorPresent && mac.AppArmorMode != "disabled" && mac.AppArmorMode != "unknown"
	aaIndeterminate := mac.AppArmorPresent && mac.AppArmorMode == "unknown"

	var out []models.Insight

	// SELinux policy type validation — surface BEFORE any denial checks.
	// A bad SELINUXTYPE= is the root cause of cascading service failures at boot.
	// This check fires even when SELinux mode is "permissive" because the policy
	// directory / package mismatch still prevents dbus from loading its context file.
	if mac.SELinuxPresent && mac.SELinuxType != "" {
		if !mac.SELinuxTypeValid {
			out = append(out, insight("CRIT", catKernelSec,
				fmt.Sprintf("SELinux SELINUXTYPE=%q is not a valid policy type (must be: targeted, minimum, mls)", mac.SELinuxType),
				[]string{
					"to inspect: cat /etc/selinux/config",
					"to fix:     set SELINUXTYPE=targeted in /etc/selinux/config",
					fixSELinuxRelabel,
					"note: invalid SELINUXTYPE causes dbus to fail, cascading to NetworkManager and systemd-logind",
				},
			))
		} else if !mac.SELinuxPolicyDirOK {
			out = append(out, insight("CRIT", catKernelSec,
				fmt.Sprintf("SELinux SELINUXTYPE=%q policy directory /etc/selinux/%s/ does not exist", mac.SELinuxType, mac.SELinuxType),
				[]string{
					fmt.Sprintf("to fix:     dnf install selinux-policy-%s", mac.SELinuxType),
					fixSELinuxRelabel,
					"note: missing policy directory causes dbus to fail at boot",
				},
			))
		} else if !mac.SELinuxPolicyPkgOK {
			out = append(out, insight("CRIT", catKernelSec,
				fmt.Sprintf("SELinux policy package selinux-policy-%s is not installed", mac.SELinuxType),
				[]string{
					fmt.Sprintf("to fix:     dnf install selinux-policy-%s", mac.SELinuxType),
					fixSELinuxRelabel,
				},
			))
		}
		if mac.SELinuxRelabelPending {
			out = append(out, insight("WARN", catKernelSec,
				"SELinux filesystem relabel is pending — reboot required to complete relabeling",
				[]string{
					"note: /.autorelabel exists — system will relabel on next boot",
					"to apply: reboot",
				},
			))
		}
	}

	// Permissive = policy loaded but enforcement OFF (denials logged, not blocked).
	// Gated on SELinuxPresent only (independent of SELINUXTYPE). Without this it
	// rendered a green "OK SELinux permissive" — a false sense of protection, and
	// inconsistent with AppArmor complain mode (the identical non-enforcing posture)
	// which is flagged below. INFO, not WARN: permissive is the Amazon Linux default,
	// so it shouldn't flip the health verdict on every AL2023 host — but it must not
	// read as OK either.
	if mac.SELinuxPresent && mac.SELinuxMode == "permissive" {
		out = append(out, insight("INFO", catKernelSec,
			"SELinux is permissive — policy is loaded but NOT enforcing (denials are logged, not blocked)",
			[]string{
				"note: permissive provides audit only, not protection (the Amazon Linux default)",
				"to enforce after reviewing audit.log for would-be denials: setenforce 1, then set SELINUX=enforcing in /etc/selinux/config",
			},
		))
	}

	if !seActive && !aaActive {
		if seIndeterminate {
			// selinuxfs is mounted but the *world-readable* enforce node yielded no
			// mode — an unusual/transient state (policy mid-load, odd container view),
			// NOT a privilege gap. Re-running as root would NOT help (non-root can
			// read the same node), so don't suggest it — point at the node instead.
			// (Contrast AppArmor below, whose mode lives in a root-only node.)
			return append(out, insight("INFO", catKernelSec,
				"SELinux is present but its enforce state could not be read — policy may be mid-load or in an unusual state",
				[]string{
					"to inspect: cat /sys/fs/selinux/enforce   (1=enforcing, 0=permissive)",
					"to inspect: getenforce  /  sestatus",
				},
			))
		}
		if aaIndeterminate {
			// AppArmor's mode lives in /sys/kernel/security/apparmor/profiles, which
			// is root-only — so here "unknown" genuinely IS a privilege gap and
			// re-running as root resolves it.
			return append(out, insight("INFO", catKernelSec,
				"AppArmor present but mode unreadable — re-run as root",
				nil,
			))
		}
		// On non-Linux platforms (macOS, etc.) neither SELinux nor AppArmor
		// is applicable — suppress the "not enforced" INFO row. But any
		// insights already in `out` (e.g. a CRIT for an invalid SELINUXTYPE=
		// found in the policy-type block above) must still be returned.
		if runtime.GOOS != "linux" {
			return out
		}
		if len(out) == 0 {
			return []models.Insight{insight("INFO", catKernelSec,
				"kernel security module not enforced",
				nil,
			)}
		}
		return out
	}

	// AppArmor-specific checks
	if aaActive {
		out = append(out, checkAppArmorActive(mac)...)
	}
	if !mac.SELinuxPresent {
		return out
	}
	out = append(out, checkSELinuxDenials(mac, thresh)...)
	return out
}

// checkSELinuxDenials handles SELinux AVC denial insights and dontaudit suppression warning.
// checkAppArmorActive handles the AppArmor complain-mode and denial checks.
// Extracted from checkKernelSecurity to keep function length within linter limits.
func checkAppArmorActive(mac models.KernelSecurityInfo) []models.Insight {
	var out []models.Insight
	// Profiles in complain mode mean enforcement is bypassed
	if mac.AppArmorComplain > 0 {
		out = append(out, insight("WARN", catKernelSec,
			fmt.Sprintf("%d AppArmor profile(s) in complain mode — not enforcing", mac.AppArmorComplain),
			[]string{
				"to inspect: aa-status --complaining",
				// Deliberately NOT 'aa-enforce /etc/apparmor.d/*' — some profiles
				// ship in complain mode by distro default; blanket-enforcing all of
				// them can break working apps. Enforce specific profiles after review.
				"to enforce a profile after review: aa-enforce /etc/apparmor.d/<profile>",
			},
		))
	}
	// Denials in last hour. -1 = the denial source was unreadable (non-root with
	// /var/log/audit unreadable AND dmesg restricted), so we can't claim "no
	// denials" — surface it as unverified rather than a silent OK.
	if mac.AppArmorDenials < 0 {
		out = append(out, insight("INFO", catKernelSec,
			"AppArmor enforcing but its denial log could NOT be read — denials are unverified",
			[]string{
				"to inspect: dmesg | grep -i apparmor   (run as root)",
				"note: kernel.dmesg_restrict=1 blocks non-root dmesg; the audit log is root-only",
			},
		))
	} else if mac.AppArmorDenials > 0 {
		out = append(out, insight("WARN", catKernelSec,
			fmt.Sprintf("%d AppArmor denial(s) in the last hour", mac.AppArmorDenials),
			[]string{
				"to inspect: dmesg | grep -i apparmor",
				"to inspect: journalctl -k | grep apparmor",
			},
		))
	}
	return out
}

// Extracted from checkKernelSecurity to keep function length within linter limits.
func checkSELinuxDenials(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if l := func() string {
		if mac.SELinuxDenials < 0 {
			return ""
		}
		if mac.SELinuxDenials >= thresh.SELinuxDenialsCritPerHr {
			return "CRIT"
		}
		if mac.SELinuxDenials >= thresh.SELinuxDenialsWarnPerHr {
			return "WARN"
		}
		return ""
	}(); l != "" {
		hints := []string{
			"to inspect: ausearch -m avc -ts recent",
			"to inspect: sealert -a /var/log/audit/audit.log",
		}
		if len(mac.SELinuxAVCSamples) > 0 {
			procs := extractAVCProcessNames(mac.SELinuxAVCSamples)
			for _, proc := range procs {
				hints = append(hints, fmt.Sprintf("to check booleans: getsebool -a | grep %s", proc))
			}
		} else {
			hints = append(hints, "to check booleans: getsebool -a | grep <process-name>")
		}
		hints = append(hints,
			"to generate fix: ausearch -m avc -ts recent | audit2allow -M mypolicy",
			"to apply fix:    semodule -i mypolicy.pp",
			"note: check booleans and file contexts BEFORE using audit2allow",
			"note: audit2allow may grant broader access than needed — review .te file first",
		)
		for _, avc := range mac.SELinuxAVCSamples {
			hints = append(hints, "sample AVC: "+avc)
		}
		out = append(out, insight(l, catKernelSec,
			fmt.Sprintf("%d SELinux denial(s) in the last hour (mode: %s)", mac.SELinuxDenials, mac.SELinuxMode),
			hints,
		))
	}
	// -1 = the AVC denial source was fully unreadable (non-root with audit log
	// unreadable, ausearch absent, journald also failed). Don't read that as "no
	// denials" — surface it as unverified.
	if mac.SELinuxMode == "enforcing" && mac.SELinuxDenials < 0 {
		out = append(out, insight("INFO", catKernelSec,
			"SELinux enforcing but AVC denials could NOT be verified — audit log unreadable / ausearch absent",
			[]string{
				"to inspect: ausearch -m avc -ts recent   (run as root)",
				"to inspect: journalctl --since '1 hour ago' | grep 'avc:  denied'",
			},
		))
	}
	// dontaudit suppression warning — zero denials does not mean clean.
	// dontaudit rules silently suppress certain denials — the "invisible SELinux" problem.
	if mac.SELinuxMode == "enforcing" && mac.SELinuxDenials == 0 {
		out = append(out, insight("INFO", catKernelSec,
			"SELinux enforcing — if services fail unexpectedly, dontaudit rules may suppress denials silently",
			[]string{
				"to expose hidden denials: semodule -DB  (disables dontaudit rules)",
				"to re-enable dontaudit:   semodule -B   (run after debugging)",
				"to check for suppressed:  ausearch -m avc -ts recent --raw | wc -l",
			},
		))
	}
	return out
}

// nvmeEventInsights turns kmsg NVMe timeout/reset counts into insights. On
// physical NVMe these are the leading cause of system freezes (timeout=WARN,
// reset=CRIT). But on a VM/cloud guest the NVMe device is virtual storage, so a
// timeout/reset is a hypervisor/cloud-storage event (EBS throttle, volume
// detach, live-migration stun), NOT a failing physical drive — and the
// physical-host remediation (smartctl, nvme_core power settings) doesn't apply.
// Downgrade severity + reword on a guest; keep the strong signal on bare metal.
func nvmeEventInsights(logs models.LogsInfo) []models.Insight {
	var out []models.Insight
	if logs.NVMeTimeouts > 0 {
		if logs.Virtualized {
			out = append(out, insight("INFO", "Logs",
				fmt.Sprintf("%d NVMe I/O timeout event(s) on virtualized storage — usually a transient hypervisor/cloud-storage event, not a failing drive", logs.NVMeTimeouts),
				[]string{
					"to inspect: dmesg | grep -i 'nvme.*timeout'",
					"note: on a VM/cloud guest the NVMe device is virtual — persistent timeouts may mean cloud-storage throttling or a degraded volume",
				},
			))
		} else {
			out = append(out, insight("WARN", "Logs",
				fmt.Sprintf("%d NVMe I/O timeout event(s) in the last hour — drive may be failing or entering bad power state", logs.NVMeTimeouts),
				[]string{
					"to inspect: dmesg | grep -i 'nvme.*timeout'",
					"to inspect: smartctl -a /dev/nvme0  (or nvme smart-log /dev/nvme0)",
					"to mitigate: echo 'options nvme_core default_ps_max_latency_us=0' >> /etc/modprobe.d/nvme.conf",
					"note: NVMe timeouts can freeze the entire I/O stack — monitor closely",
				},
			))
		}
	}
	if logs.NVMeResets > 0 {
		if logs.Virtualized {
			out = append(out, insight("WARN", "Logs",
				fmt.Sprintf("%d NVMe controller reset/down event(s) on virtualized storage — likely a cloud-storage/hypervisor event (volume detach, migration), not a failing drive", logs.NVMeResets),
				[]string{
					"to inspect: dmesg | grep -i 'nvme.*reset\\|controller is down\\|CSTS'",
					"note: on a VM/cloud guest repeated resets may indicate a degraded volume or a noisy hypervisor host — check the cloud console / hypervisor",
				},
			))
		} else {
			out = append(out, insight("CRIT", "Logs",
				fmt.Sprintf("%d NVMe controller reset/down event(s) — drive or PCIe link is unstable", logs.NVMeResets),
				[]string{
					"to inspect: dmesg | grep -i 'nvme.*reset\\|controller is down\\|CSTS'",
					"to inspect: nvme smart-log /dev/nvme0  (if nvme-cli installed)",
					"to mitigate: echo 'options nvme_core default_ps_max_latency_us=0' >> /etc/modprobe.d/nvme.conf",
					"to mitigate: add 'pcie_aspm=off' to kernel cmdline if power-state related",
					"note: controller resets can cause mdadm/BTRFS/ZFS to go read-only",
				},
			))
		}
	}
	return out
}

func checkLogs(logs models.LogsInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if logs.NeedsRoot {
		out = append(out, insight("INFO", "Logs",
			"some checks limited — run as root for OOM/segfault detection via /dev/kmsg and auth log analysis",
			nil,
		))
	}
	if l := levelPct(logs.JournalSizeGB, thresh.JournalSizeWarnGB, thresh.JournalSizeCritGB); l != "" {
		out = append(out, insight(l, "Logs",
			fmt.Sprintf("journal is %.1f GB", logs.JournalSizeGB),
			[]string{inspectJournalDiskUse, "to fix: journalctl --vacuum-size=1G", "to fix: journalctl --vacuum-time=7d"},
		))
	}
	if logs.OOMKills > 0 {
		procs := strings.Join(logs.OOMProcesses, ", ")
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d OOM kill(s) in the last hour — processes killed: %s", logs.OOMKills, procs),
			[]string{"to inspect: dmesg | grep -i 'out of memory'", inspectFreeH},
		))
	}
	if logs.Segfaults > 0 {
		procs := strings.Join(logs.SegfaultProcs, ", ")
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d segfault(s) in the last hour — processes: %s", logs.Segfaults, procs),
			[]string{"to inspect: dmesg | grep segfault", "to inspect: journalctl -p err -n 50"},
		))
	}
	for _, unit := range logs.CrashLoops {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("crash loop detected: %s", unit),
			[]string{fmt.Sprintf("to inspect: journalctl -u %s -n 50", strings.Fields(unit)[0])},
		))
	}

	// Kernel instability signals — always CRIT, any count is too many
	if logs.SoftLockups > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d soft lockup(s) detected — CPU stuck in kernel context", logs.SoftLockups),
			[]string{"to inspect: dmesg | grep -i 'soft lockup'", "to inspect: check for runaway kernel threads or NFS hangs"},
		))
	}
	if logs.HardLockups > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d hard lockup(s) detected — CPU unresponsive, NMI watchdog fired", logs.HardLockups),
			[]string{"to inspect: dmesg | grep -i 'hard lockup'", "to inspect: likely hardware issue — check memory and CPU"},
		))
	}
	if logs.KernelPanics > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d kernel panic record(s) found — system crashed previously", logs.KernelPanics),
			[]string{"to inspect: ls /sys/fs/pstore/", "to inspect: dmesg | grep -i panic", "to inspect: check /var/crash if kdump is enabled"},
		))
	}

	out = append(out, nvmeEventInsights(logs)...)

	// Journal health — silent log loss is worse than noisy logs
	out = append(out, checkJournalHealthInsights(logs)...)

	return out
}

func checkJournalHealthInsights(logs models.LogsInfo) []models.Insight {
	out := checkJournalConfig(logs)
	out = append(out, checkJournalActivity(logs)...)
	return out
}

// journalVolatileInsight describes a volatile journald (no /var/log/journal).
// "all logs lost on reboot" is only true when there's ALSO no text-log fallback:
// RHEL/CentOS 7 (and many distros) ship volatile journald BUT a running rsyslog
// that persists everything to /var/log/messages, so logs are NOT lost — only the
// journalctl boot history is. Claiming "all logs lost" there is a false WARN on
// every default install (found live on CentOS 7: rsyslog active, /var/log/messages
// 2569 lines). Gate severity on the fallback the collector already detects.
func journalVolatileInsight(logs models.LogsInfo) models.Insight {
	if logs.JournalNoTextFallback {
		return insight("WARN", "Logs",
			"journald is volatile AND no text-log fallback (rsyslog/syslog-ng) is running — logs are lost on reboot",
			[]string{
				"to fix:     mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal",
				"to persist: echo 'Storage=persistent' >> /etc/systemd/journald.conf && systemctl restart systemd-journald",
				"or install a syslog daemon: dnf/apt/zypper install rsyslog",
			},
		)
	}
	return insight("INFO", "Logs",
		"journald is volatile (no /var/log/journal) — the journalctl boot history is lost on reboot, but a syslog daemon persists text logs to /var/log, so logs survive",
		[]string{
			"note: text logs (e.g. /var/log/messages) survive reboots via rsyslog/syslog-ng",
			"to keep journalctl history too: echo 'Storage=persistent' >> /etc/systemd/journald.conf && systemctl restart systemd-journald",
		},
	)
}

func checkJournalConfig(logs models.LogsInfo) []models.Insight {
	var out []models.Insight
	if logs.JournalCorrupt {
		// The collector only verifies archived (*.journal~) segments — active
		// journals are skipped (they race with live writers, systemd#35916). So a
		// hit here is always a damaged *historical* archive, common after an unclean
		// shutdown; current logging is unaffected. WARN, not CRIT — a blanket
		// "logs may be missing" CRIT on a rotated archive is the trust-eroding
		// false-alarm Principle 4b warns against (§O.3).
		out = append(out, insight("WARN", "Logs",
			"an archived (rotated) journal segment failed verification — a historical log file has a damaged region; current logging is unaffected",
			[]string{
				"to inspect: journalctl --verify",
				"to clean:   rm /var/log/journal/*/*.journal~  (removes the damaged archived segments)",
				"note: only rotated *.journal~ archives are checked; active journals are not verified (they race with live writers)",
			},
		))
	}
	if logs.JournalVolatile {
		out = append(out, journalVolatileInsight(logs))
	}
	if logs.JournalRateLimited {
		out = append(out, insight("WARN", "Logs",
			"journald RateLimitBurst is very low — logs may be silently dropped under load",
			[]string{
				"to inspect: grep RateLimit /etc/systemd/journald.conf",
				"to fix:     echo 'RateLimitBurst=10000' >> /etc/systemd/journald.conf",
				"to fix:     systemctl restart systemd-journald",
			},
		))
	}
	if logs.JournalNoTextFallback && !logs.JournalVolatile {
		// Persistent journald but no text fallback — logs survive (in the journal)
		// yet need journalctl to read. When journald is ALSO volatile, the merged
		// WARN above already covers it, so don't double-message.
		out = append(out, insight("INFO", "Logs",
			"no text log fallback detected (rsyslog/syslog-ng not running) — logs require journalctl to read",
			[]string{
				"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
				"note:   without a text fallback, logs are unreadable if journald corrupts or system partially fails",
				"note:   standard Unix tools (grep, tail, less) cannot read binary journal files",
			},
		))
	}
	if logs.JournalUnbounded {
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("journald has no SystemMaxUse cap — journal is %.1f GB and growing unbounded", logs.JournalSizeGB),
			[]string{
				"to fix: echo 'SystemMaxUse=2G' >> /etc/systemd/journald.conf",
				"to fix: systemctl restart systemd-journald",
				"to fix: journalctl --vacuum-size=2G  (immediate cleanup)",
			},
		))
	}
	if logs.JournalSyncRisk {
		out = append(out, insight("INFO", "Logs",
			"journald SyncIntervalSec is high (default 5min) — final log lines from a crashing process may be lost",
			[]string{
				"to fix: echo 'SyncIntervalSec=30s' >> /etc/systemd/journald.conf",
				"to fix: systemctl restart systemd-journald",
				"note:   lower sync interval increases disk I/O but ensures crash logs are preserved",
			},
		))
	}
	if logs.LogDiskUsedPct >= 90 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("log volume %s is %.0f%% full — journald may stop writing logs",
				logs.LogDiskMount, logs.LogDiskUsedPct),
			[]string{
				"to inspect: df -h " + logs.LogDiskMount,
				inspectJournalDiskUse,
				"to fix:     journalctl --vacuum-size=500M",
				"to fix:     journalctl --vacuum-time=7d",
			},
		))
	} else if logs.LogDiskUsedPct >= 80 {
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("log volume %s is %.0f%% full — monitor to prevent log loss",
				logs.LogDiskMount, logs.LogDiskUsedPct),
			[]string{
				"to inspect: df -h " + logs.LogDiskMount,
				inspectJournalDiskUse,
				"to fix:     journalctl --vacuum-size=1G",
			},
		))
	}
	return out
}

func checkJournalActivity(logs models.LogsInfo) []models.Insight {
	var out []models.Insight
	if logs.CoreDumpCount > 0 {
		paths := make([]string, 0, len(logs.CrashFiles))
		for _, cf := range logs.CrashFiles {
			paths = append(paths, fmt.Sprintf("%s (%.1fMB, %dd ago)", cf.Path, cf.SizeMB, cf.AgeDays))
		}
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d crash dump(s)/panic record(s) found in the last 30 days", logs.CoreDumpCount),
			append([]string{
				"to inspect: ls -lh /var/crash/ /var/lib/systemd/coredump/ /sys/fs/pstore/",
				"to analyse: journalctl -k -b -1 | tail -50  (previous boot kernel log)",
			}, paths...),
		))
	}
	if logs.ErrorCount > 50 {
		hints := make([]string, 0, 1+len(logs.TopErrors))
		hints = append(hints, "to inspect: journalctl -p err --since '1 hour ago' --no-pager | tail -30")
		hints = append(hints, logs.TopErrors...)
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d error(s) logged in the last hour", logs.ErrorCount), hints))
	} else if logs.ErrorCount > 10 {
		out = append(out, insight("INFO", "Logs",
			fmt.Sprintf("%d error(s) logged in the last hour — check if expected", logs.ErrorCount),
			[]string{"to inspect: journalctl -p err --since '1 hour ago' --no-pager"},
		))
	} else if logs.ErrorCountUnverified {
		// The journal error scan failed and no /var/log fallback covered it, so the
		// 0-error count is not trustworthy — don't read it as a clean log.
		out = append(out, insight("INFO", "Logs",
			"could not read journal error counts — recent errors are unverified",
			[]string{
				"to inspect: journalctl -p err --since '1 hour ago' --no-pager  (run as root?)",
				"to inspect: systemctl status systemd-journald",
			},
		))
	}
	return out
}

func checkEntropy(e models.EntropyInfo) []models.Insight {
	// Deliberate, not a gap: Available=false only ever comes from the non-Linux
	// stub (entropy_notlinux.go) — genuinely not applicable off-Linux. A real
	// Linux read failure never reaches this function at all: EntropyCollector.
	// Collect() returns a Go error in that case, which the runner surfaces as
	// checks[].status=="ERROR" with the failure message, not as Available=false.
	// So this is not the same class of silent-skip PR #921 fixed elsewhere.
	if !e.Available {
		return nil // not applicable on this platform
	}
	if e.EntropyBits < 64 {
		return []models.Insight{insight("CRIT", "Entropy",
			fmt.Sprintf("entropy pool critically low (%d bits) — crypto operations may block or fail", e.EntropyBits),
			[]string{"to inspect: cat /proc/sys/kernel/random/entropy_avail", "to fix: install haveged or rng-tools"},
		)}
	}
	if e.EntropyBits < 256 {
		return []models.Insight{insight("WARN", "Entropy",
			fmt.Sprintf("entropy pool low (%d bits) — TLS and key generation may slow down", e.EntropyBits),
			[]string{"to inspect: cat /proc/sys/kernel/random/entropy_avail", "to fix: install haveged or rng-tools"},
		)}
	}
	return nil
}

func checkProcesses(proc models.ProcessInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	// Zombie CRIT stays at the fixed 10 (no policy knob); WARN is configurable
	// via zombie_warn_count (default 1 = warn on any zombie).
	if proc.ZombieCount >= 10 {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d zombie processes detected", proc.ZombieCount),
			[]string{"to inspect: ps aux | grep Z", "to inspect: cat /proc/*/status | grep -E '^Name|^State' | paste - -"},
		))
	} else if proc.ZombieCount > 0 && proc.ZombieCount >= thresh.ZombieWarnCount {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d zombie process(es) detected", proc.ZombieCount),
			[]string{"to inspect: ps aux | grep Z"},
		))
	}
	// Hung CRIT is configurable via hung_d_state_crit (default 5); any hung
	// process below that still WARNs.
	if proc.HungCount > 0 && proc.HungCount >= thresh.HungDStateCrit {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) processes", proc.HungCount),
			[]string{"to inspect: ps aux | grep ' D '", "to inspect: for pid in $(ps -eo pid,stat | awk '$2~/D/{print $1}'); do cat /proc/$pid/wchan 2>/dev/null; done"},
		))
	} else if proc.HungCount > 0 {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) process(es)", proc.HungCount),
			[]string{"to inspect: ps aux | grep ' D '"},
		))
	}
	return out
}

// checkServices surfaces per-configured-service reachability/status problems.
// Nothing configured (empty Results) is silent, not a false-OK: ApplyThresholds
// produces no insight either way, and `dsd services` renders its own "no
// services configured" guidance for that case.
func checkServices(s models.ServicesInfo) []models.Insight {
	var out []models.Insight
	for _, r := range s.Results {
		addr := fmt.Sprintf("%s:%d", r.Host, r.Port)
		switch {
		case r.Status == "CRIT":
			out = append(out, insight("CRIT", "Services",
				fmt.Sprintf("%s (%s) returned HTTP %d", r.Name, addr, r.StatusCode),
				[]string{fmt.Sprintf("to inspect: curl -v %s://%s", r.Protocol, addr)},
			))
		case !r.Reachable:
			msg := fmt.Sprintf("%s (%s) unreachable", r.Name, addr)
			if r.Error != "" {
				msg += ": " + r.Error
			}
			out = append(out, insight("WARN", "Services", msg,
				[]string{fmt.Sprintf("to inspect: nc -zv %s %d", r.Host, r.Port)},
			))
		}
	}
	return out
}

// checkDBus surfaces D-Bus health. D-Bus is treated as a Tier-0 dependency —
// its failure cascades to all services that communicate via IPC.
func checkDBus(d models.DBusInfo) []models.Insight {
	if d.Status == "n/a" || d.Active {
		return nil // healthy or not applicable (non-Linux)
	}
	// "unknown" means systemctl couldn't determine the bus state (timeout, unit
	// alias lookup miss) — NOT that the bus is down. A live system you're
	// actively running on almost always has a working bus; treating "couldn't
	// determine" as "failed" produced a false CRIT on VMware guests (TRIAGE §M).
	// Surface it as INFO so the unverified state is honest without a scary
	// top-line CRIT. Only an explicit failed/inactive is a real failure.
	if d.Status != "failed" && d.Status != "inactive" {
		return []models.Insight{insight("INFO", "DBus",
			fmt.Sprintf("D-Bus state could not be determined (status: %q) — health unverified, not assumed failed", d.Status),
			[]string{
				"to inspect: systemctl is-active dbus",
				"to inspect: systemctl status dbus --no-pager",
				"note: if `systemctl is-active dbus` reports active, the bus is fine and this is a query artifact",
			},
		)}
	}
	hints := []string{
		"to inspect: systemctl status dbus.service",
		"to inspect: journalctl -u dbus.service -n 20",
		"note: D-Bus failure cascades — NetworkManager, systemd-logind, and other services will also fail",
		"note: check SELinux policy type: cat /etc/selinux/config | grep SELINUXTYPE",
	}
	if d.LastError != "" {
		hints = append([]string{"last error: " + d.LastError}, hints...)
	}
	return []models.Insight{insight("CRIT", "DBus",
		"D-Bus system message bus has failed — all IPC-dependent services are affected",
		hints,
	)}
}

func checkOOM(oom models.OOMInfo) []models.Insight {
	// The kernel log was unreadable, so EventsLast24h==0 means "couldn't check",
	// not "no OOM kills" — surface it rather than passing as a silent clean.
	if oom.StatusReason != "" {
		return []models.Insight{insight("INFO", "OOM",
			"OOM check not verified — "+oom.StatusReason,
			[]string{
				"to inspect: journalctl -k | grep -i 'out of memory'   (run as root)",
				"note: kernel.dmesg_restrict=1 blocks non-root dmesg",
			},
		)}
	}
	if oom.EventsLast24h == 0 {
		return nil
	}
	var victims []string
	seen := map[string]bool{}
	for _, ev := range oom.RecentEvents {
		if !seen[ev.Process] {
			seen[ev.Process] = true
			victims = append(victims, ev.Process)
		}
	}
	msg := fmt.Sprintf("%d OOM kill event(s) in the last 24h", oom.EventsLast24h)
	if len(victims) > 0 {
		msg += fmt.Sprintf(" — killed: %s", strings.Join(victims, ", "))
	}
	// CRIT, not WARN: an OOM kill is a real failure (a process was killed). The
	// logs path already CRITs on OOM kills in the last hour; this 24h-window path
	// must agree, else a kill 60+ min ago would only WARN and exit 1 not 2.
	return []models.Insight{insight("CRIT", "OOM",
		msg,
		[]string{
			"to inspect: journalctl -k | grep -i 'oom\\|killed process'",
			"to inspect: dmesg | grep -i 'out of memory'",
			inspectFreeH,
			inspectPsMemHead,
			"note: OOM kills are silent — services may restart without apparent cause",
		},
	)}
}

func checkMTE(m models.MTEInfo) []models.Insight {
	if !m.Available {
		return nil
	}
	if m.StatusReason != "" {
		return []models.Insight{insight("INFO", "MTE",
			"MTE fault check not verified — "+m.StatusReason,
			[]string{
				"to inspect: journalctl -k | grep -i 'tag check fault'   (run as root)",
				"note: kernel.dmesg_restrict=1 blocks non-root dmesg",
			},
		)}
	}

	var out []models.Insight

	if !m.ExceptionTraceEnabled {
		out = append(out, insight("WARN", "MTE",
			"ARM Memory Tagging Extension hardware support is present, but kernel fault-signal logging (debug.exception-trace) is off — any tag-check fault will crash a process silently with no forensic trail",
			[]string{
				"to enable (runtime): sysctl -w debug.exception-trace=1",
				"to persist: echo 'debug.exception-trace = 1' > /etc/sysctl.d/99-mte-trace.conf",
				"note: only matters if a workload here intentionally uses MTE (hardened allocators, memory-safety testing) — leaving it off is not itself a fault",
			},
		))
	}

	for _, ev := range m.RecentFaults {
		out = append(out, insight("CRIT", "MTE",
			fmt.Sprintf("process %s (pid %d) crashed on a hardware memory-safety fault (ARM MTE %s tag-check) — likely a genuine memory-corruption bug (buffer overflow / use-after-free), not resource exhaustion or app misbehavior", ev.Process, ev.PID, ev.FaultType),
			[]string{
				"to inspect: journalctl -k | grep -i 'tag check fault'   (full register dump)",
				"note: triage at the code level — this is a hardware-caught memory-safety violation, not a generic segfault",
			},
		))
	}

	return out
}

func checkPressure(p models.PressureInfo) []models.Insight {
	// Deliberate, not a gap: PSI absence is overwhelmingly a legitimate "not
	// applicable on this kernel" state (pre-4.20, or PSI disabled at build/boot)
	// — disclosing it would add INFO noise on every older-kernel run for a
	// failure mode that essentially does not occur. Left silent on purpose.
	if !p.Available {
		return nil
	}
	var out []models.Insight
	// Memory full stall > 10% in last 60s is severe
	if p.MemoryFull.Avg60 >= 10 {
		out = append(out, insight("CRIT", "Pressure",
			fmt.Sprintf("memory full stall %.1f%% avg60 — tasks blocked waiting for memory", p.MemoryFull.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/memory",
				inspectFreeH,
				inspectPsMemHead,
				"note: OOM kill may be imminent — act now",
			},
		))
	} else if p.MemorySome.Avg60 >= 20 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("memory pressure %.1f%% avg60 — some tasks delayed waiting for memory", p.MemorySome.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/memory",
				inspectFreeH,
			},
		))
	}
	// IO full stall > 5% in last 60s
	if p.IOFull.Avg60 >= 5 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("IO full stall %.1f%% avg60 — all tasks blocked on disk IO", p.IOFull.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/io",
				inspectIOStat,
				inspectIotop,
			},
		))
	}
	// CPU stall > 30% in last 60s (some stall, not full — CPU is never "full" stalled)
	if p.CPUSome.Avg60 >= 30 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("CPU pressure %.1f%% avg60 — tasks waiting for CPU time", p.CPUSome.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/cpu",
				"to inspect: uptime",
				"to inspect: ps aux --sort=-%cpu | head -10",
			},
		))
	}
	return out
}

func checkHugePages(h models.HugePagesInfo) []models.Insight {
	if h.Configured == 0 && !h.THPEnabled {
		return nil // not configured, not relevant
	}
	var out []models.Insight

	// Static huge pages configured but mostly unused — wasted locked RAM
	if h.Configured > 0 {
		usedPct := float64(h.Used) / float64(h.Configured) * 100
		if usedPct < 20 && h.ReservedGB >= 1 {
			out = append(out, insight("WARN", "HugePages",
				fmt.Sprintf("%.0f%% of huge pages unused — %.1f GB locked and wasted (used %d/%d pages)",
					100-usedPct, h.ReservedGB, h.Used, h.Configured),
				[]string{
					"to inspect: grep Huge /proc/meminfo",
					"note: static huge pages lock RAM at boot — free unused pages or reduce HugePages_Total",
					"to fix: echo 0 > /proc/sys/vm/nr_hugepages  (releases all — requires workload restart)",
				},
			))
		}
		// All huge pages used — may want more
		if usedPct >= 100 && h.Configured > 0 {
			out = append(out, insight("INFO", "HugePages",
				fmt.Sprintf("all %d huge pages in use (%.1f GB) — consider increasing if workload allows",
					h.Configured, h.ReservedGB),
				[]string{
					"to inspect: grep Huge /proc/meminfo",
					"to add more: sysctl -w vm.nr_hugepages=<N>",
				},
			))
		}
	}

	// THP set to "always" on a database server — causes latency spikes
	// THP is great for general workloads but known to cause pauses in:
	// MySQL, PostgreSQL, Redis, MongoDB, Oracle
	if h.THPMode == "always" {
		out = append(out, insight("INFO", "HugePages",
			"transparent huge pages mode is 'always' — may cause latency spikes for database workloads",
			[]string{
				"to inspect: cat /sys/kernel/mm/transparent_hugepage/enabled",
				"to check:   if running MySQL/PostgreSQL/Redis/MongoDB, set to 'madvise' or 'never'",
				"to fix:     echo madvise > /sys/kernel/mm/transparent_hugepage/enabled",
				"to persist: add to /etc/rc.local or a systemd service",
			},
		))
	}

	return out
}

func checkLaunchd(l models.LaunchdInfo) []models.Insight {
	if len(l.Failed) == 0 {
		return nil
	}
	var names []string
	for _, svc := range l.Failed {
		names = append(names, svc.Label)
	}
	// Show at most 3 names inline to keep message readable
	shown := names
	suffix := ""
	if len(shown) > 3 {
		shown = shown[:3]
		suffix = fmt.Sprintf(" (+%d more)", len(names)-3)
	}
	return []models.Insight{insight("WARN", "Launchd",
		fmt.Sprintf("%d launchd service(s) failed: %s%s",
			len(l.Failed), strings.Join(shown, ", "), suffix),
		[]string{
			"to inspect: launchctl list | awk '$2 != 0 && $2 != \"-\"'",
			"to inspect: log show --predicate 'subsystem == \"com.apple.launchd\"' --last 1h",
			"to fix:     launchctl kickstart system/<label>",
		},
	)}
}

// checkSessions surfaces active session anomalies (Spec H1):
// root login via SSH, sessions idle > 8h, unusual concurrent session count.
// Silent when only the current user is logged in normally.
func checkSessions(s models.SessionsInfo) []models.Insight {
	if s.TotalCount == 0 {
		return nil // w not available or no sessions — skip silently
	}
	var out []models.Insight

	// Root logged in via SSH. On Proxmox VE root SSH is required for cluster
	// management, so flagging it CRIT (as checkSecurity already declines to do for
	// PermitRootLogin on PVE) would fire on the operator's own management session.
	// Surface it as INFO there instead of a false CRIT.
	if s.RootSSH {
		if s.IsPVE {
			out = append(out, insight("INFO", "Sessions",
				"root is logged in via SSH — expected on Proxmox VE (cluster management requires it)",
				[]string{inspectW},
			))
		} else {
			out = append(out, insight("CRIT", "Sessions",
				"root is logged in via SSH — direct root SSH access is a security risk",
				[]string{
					inspectW,
					"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
					"to fix: use sudo or su instead of direct root SSH",
				},
			))
		}
	}

	// Sessions idle > 8 hours — unattended terminals
	if len(s.LongIdle) > 0 {
		users := strings.Join(unique(s.LongIdle), ", ")
		out = append(out, insight("WARN", "Sessions",
			fmt.Sprintf("%d session(s) idle > 8h: %s — unattended terminal risk",
				len(s.LongIdle), users),
			[]string{
				inspectW,
				"to fix: set ClientAliveInterval 300 in /etc/ssh/sshd_config to auto-disconnect",
			},
		))
	}

	// Unusual number of concurrent sessions (> 5 is worth noting on a typical server)
	if s.TotalCount > 5 {
		out = append(out, insight("WARN", "Sessions",
			fmt.Sprintf("%d concurrent sessions active — unusually high for a single server",
				s.TotalCount),
			[]string{inspectW, "to inspect: last | head -20"},
		))
	}

	// Informational: unique remote IPs when > 1 different source
	if len(s.UniqueIPs) > 1 {
		out = append(out, insight("INFO", "Sessions",
			fmt.Sprintf("%d session(s) from %d unique IP(s): %s",
				s.RemoteCount, len(s.UniqueIPs),
				strings.Join(s.UniqueIPs, ", ")),
			[]string{inspectW},
		))
	}

	return out
}

func checkCgroupV2(cg models.CgroupV2Info) []models.Insight {
	if !cg.Available {
		return nil
	}
	var out []models.Insight

	// OOM kills at root scope. memory.events oom_kill is a CUMULATIVE counter since
	// boot — it can't tell a kill from 5 minutes ago from one at boot weeks back, so
	// firing CRIT on >0 was a recency-gate (a single boot-time OOM = permanent CRIT).
	// Recency is owned by the timestamped Logs/OOM check (windowed to 24h); here we
	// surface the lifetime counter as INFO context, not a live alarm.
	if cg.OOMKills > 0 {
		out = append(out, insight("INFO", "Cgroup",
			fmt.Sprintf("cgroup OOM kill counter = %d since boot (lifetime total, not necessarily recent)",
				cg.OOMKills),
			[]string{
				"recency: see the Logs/OOM check — it windows OOM events to the last 24h",
				"to inspect: cat /sys/fs/cgroup/memory.events",
				"to identify: dmesg | grep -i 'oom_kill\\|out of memory'",
			},
		))
	}

	// CPU throttled slices. ThrottledPct is throttled_usec/usage_usec — both
	// cumulative since the slice was created, so this is a LIFETIME ratio, not the
	// current rate (a slice hammered at boot but idle now still reads high). The
	// wording reflects that; a high lifetime ratio is still a real "this slice is
	// chronically cpu-constrained" signal.
	for _, s := range cg.Slices {
		if s.ThrottledPct > 20 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot) — chronically hitting cpu.max",
					s.Name, s.ThrottledPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/cpu.stat", s.Name),
					fmt.Sprintf("to fix: increase or remove cpu.max in /sys/fs/cgroup/%s/cpu.max", s.Name),
					"note: lifetime ratio — throttling causes latency spikes even when overall CPU is idle",
				},
			))
		} else if s.ThrottledPct > 5 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot)",
					s.Name, s.ThrottledPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/cpu.stat", s.Name),
				},
			))
		}

		// Memory usage near limit
		if s.HasMemLimit && s.MemUsedPct > 90 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s memory %.0f%% of limit (%.0f/%.0f MB)",
					s.Name, s.MemUsedPct, s.MemCurrentMB, s.MemLimitMB),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.current", s.Name),
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.events", s.Name),
					"note: at 100% the kernel will OOM-kill processes in this slice",
				},
			))
		} else if s.HasMemLimit && s.MemUsedPct > 75 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s memory at %.0f%% of limit",
					s.Name, s.MemUsedPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.current", s.Name),
				},
			))
		}
	}

	// Individual systemd service units and containers one level below the
	// slices above — split into its own function purely to stay under the
	// funlen linter's line budget; same lifetime-ratio caveat and thresholds.
	out = append(out, checkCgroupUnits(cg.Units)...)

	return out
}

// checkCgroupUnits mirrors the per-slice throttle/memory checks in
// checkCgroupV2, keyed by individual systemd service unit / container
// instead of the coarser top-level slice. Only units that already crossed
// the "significant usage" bar in the collector (>5% CPU or >500MB RAM)
// appear here, so this loop is small.
func checkCgroupUnits(units []models.CgroupUnit) []models.Insight {
	var out []models.Insight
	for _, u := range units {
		var hint []string
		if u.IsContainer {
			hint = []string{fmt.Sprintf("to inspect: docker stats %s", strings.TrimPrefix(u.Name, "container:"))}
		} else {
			hint = []string{fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/%s/cpu.stat", u.ParentSlice, u.Name)}
		}

		if u.ThrottledPct > 20 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot) — chronically hitting cpu.max",
					u.Name, u.ThrottledPct),
				hint,
			))
		} else if u.ThrottledPct > 5 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot)",
					u.Name, u.ThrottledPct),
				hint,
			))
		}

		if u.HasMemLimit && u.MemUsedPct > 90 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s memory %.0f%% of limit (%.0f/%.0f MB)",
					u.Name, u.MemUsedPct, u.MemCurrentMB, u.MemLimitMB),
				hint,
			))
		} else if u.HasMemLimit && u.MemUsedPct > 75 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s memory at %.0f%% of limit",
					u.Name, u.MemUsedPct),
				hint,
			))
		}
	}
	return out
}

// unique returns a deduplicated copy of a string slice, preserving order.
func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
