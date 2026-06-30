package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Verdicts for the RHEL/Oracle-family maintenance collectors (see
// internal/collectors/maintenance_linux.go). All gate to nil when the subsystem is
// absent, so they add zero noise on hosts that don't run kdump/tuned/rpm/Ksplice.

// checkKdump flags the silent-failure case: kdump is enabled but not actually armed
// (no crash kernel loaded / no memory reserved), so a real panic produces no dump.
func checkKdump(d models.KdumpInfo) []models.Insight {
	if !d.Available || !d.Enabled {
		return nil // not installed, or admin deliberately left it off — not a fault
	}
	if d.ServiceState == "failed" {
		return []models.Insight{insight("WARN", "Kdump",
			"kdump.service is enabled but FAILED — no crash dump will be captured on a kernel panic",
			[]string{
				"to inspect: kdumpctl status   (or: systemctl status kdump)",
				"to inspect: journalctl -u kdump -b",
			})}
	}
	if !d.CrashLoaded || d.ReservedBytes == 0 {
		reason := "the crash kernel is not loaded"
		fix := "kdumpctl reset && systemctl restart kdump"
		if d.Crashkernel == "" {
			reason = "no crashkernel= memory reservation on the kernel cmdline"
			fix = "grubby --update-kernel=ALL --args='crashkernel=1G-64G:448M,64G-:512M', then reboot"
		}
		return []models.Insight{insight("WARN", "Kdump",
			"kdump is enabled but "+reason+" — a kernel panic will produce NO crash dump",
			[]string{
				"to inspect: cat /sys/kernel/kexec_crash_loaded   (1 = armed)",
				"to inspect: kdumpctl status",
				"to fix: " + fix,
			})}
	}
	return nil
}

// checkTuned flags an inactive tuned, or an active profile that disagrees with
// tuned's own recommendation for the host (e.g. a VM left on "balanced" instead of
// "virtual-guest").
func checkTuned(d models.TunedInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	if !d.Active {
		return []models.Insight{insight("INFO", "Tuned",
			"tuned is installed but not active — no performance profile is applied",
			[]string{"to fix: systemctl enable --now tuned"})}
	}
	if d.Profile != "" && d.Recommended != "" && d.Profile != d.Recommended {
		return []models.Insight{insight("INFO", "Tuned",
			fmt.Sprintf("tuned active profile %q differs from the recommended %q for this system", d.Profile, d.Recommended),
			[]string{
				fmt.Sprintf("note: tuned recommends %q for this hardware (e.g. virtual-guest tunes a VM for its hypervisor)", d.Recommended),
				fmt.Sprintf("to fix: tuned-adm profile %s", d.Recommended),
			})}
	}
	return nil
}

// checkKernelPatch flags "patched but still running the old kernel": a newer kernel
// package is installed than the one currently booted.
func checkKernelPatch(d models.KernelPatchInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	// SUSE: the zypp lock was held for the whole retry budget (a sibling zypper
	// collector contends for it under root), so reboot status is genuinely unknown.
	// Surface it honestly (INFO) rather than dropping the row or implying "Kernel OK".
	if d.CheckUnverified {
		return []models.Insight{insight("INFO", "Kernel",
			"kernel reboot-needed status could not be determined — the package manager (zypp) was locked by another process",
			[]string{"to inspect: zypper needs-rebooting   (re-run when no other zypper/PackageKit process holds the lock)"})}
	}
	if !d.RebootNeeded {
		return nil
	}
	// RHEL/Oracle knows the exact newer kernel; the SUSE (zypper) and Debian/Ubuntu
	// (/run/reboot-required) paths only know a reboot is needed.
	msg := "a kernel / core-library update has been installed but not yet applied — reboot to apply (you may still be running the pre-update, possibly-vulnerable kernel)"
	if d.LatestInstalled != "" {
		msg = fmt.Sprintf("a newer kernel (%s) is installed but the system is still running %s — reboot to apply", d.LatestInstalled, d.Running)
	}
	return []models.Insight{insight("WARN", "Kernel", msg,
		[]string{
			"note: until you reboot you are running the OLD kernel — any kernel CVE the update fixed is still exposed",
			"to inspect: rpm -q --last kernel-uek-core kernel-core (RHEL) / zypper needs-rebooting (SUSE) / cat /run/reboot-required.pkgs (Debian/Ubuntu)",
			"to fix: reboot  (schedule a maintenance window)",
		})}
}

// checkKsplice flags Oracle Ksplice live patches that are available but not applied
// (the running kernel is exposed despite a patch existing).
func checkKsplice(d models.KspliceInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	if d.CheckUnverified {
		return []models.Insight{insight("INFO", "Ksplice",
			"Ksplice is installed but its update status could not be read",
			[]string{"to inspect: uptrack-show   (or: uptrack-upgrade -n)"})}
	}
	if d.PendingUpdates > 0 {
		return []models.Insight{insight("WARN", "Ksplice",
			fmt.Sprintf("%d Ksplice live patch(es) available but not applied — the running kernel is still exposed", d.PendingUpdates),
			[]string{
				"to fix: uptrack-upgrade -y   (applies live, no reboot)",
				"to inspect: uptrack-show",
			})}
	}
	return nil
}

// checkServiceRestart flags processes mapping shared libraries that were replaced on
// disk by an update — until restarted they run the old (possibly vulnerable) code.
func checkServiceRestart(d models.ServiceRestartInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	if d.StaleCount > 0 {
		msg := fmt.Sprintf("%d process(es) are using libraries that were updated on disk (%s) — until restarted they run the OLD code",
			d.StaleCount, strings.Join(d.StaleNames, ", "))
		return []models.Insight{insight("WARN", "ServiceRestart", msg, []string{
			"note: after a glibc/openssl security update, unrestarted services stay vulnerable until restarted",
			"to inspect: needs-restarting -s   (dnf-utils), or: lsof +c0 -d DEL 2>/dev/null | grep '\\.so'",
			"to fix: systemctl restart <unit> for each, or reboot",
		})}
	}
	if d.NeedsRoot {
		return []models.Insight{insight("INFO", "ServiceRestart",
			"stale-library scan was partial — run as root to check every process for libraries updated underneath it",
			[]string{"to fix: re-run as root (sudo dsd health)"})}
	}
	return nil
}

// checkKernelRetention flags old kernels at risk of filling /boot (the next kernel
// update can fail mid-write), and the unbounded-retention policy that leads there.
func checkKernelRetention(d models.KernelRetentionInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	// Concrete risk: a small, near-full /boot with several kernels. A /boot on a roomy
	// root fs reports a large BootTotalGB and never trips this.
	if d.BootTotalGB > 0 && d.BootTotalGB < 2.0 && d.InstalledKernels >= 3 && d.BootUsedPct >= 80 {
		level := "WARN"
		if d.BootUsedPct >= 90 {
			level = "CRIT"
		}
		return []models.Insight{insight(level, "KernelRetention",
			fmt.Sprintf("/boot is %.0f%% full with %d kernels installed — the next kernel update can fail mid-write; remove old kernels",
				d.BootUsedPct, d.InstalledKernels),
			kernelRetentionHints(d.PackageManager))}
	}
	// Leading indicator: unbounded retention policy + a growing pile (before /boot bites).
	if d.Unbounded && d.InstalledKernels >= 5 {
		return []models.Insight{insight("WARN", "KernelRetention",
			fmt.Sprintf("kernel retention is unbounded (%s) and %d kernels are installed — they keep accumulating and will eventually fill /boot",
				d.RetentionPolicy, d.InstalledKernels),
			kernelRetentionHints(d.PackageManager))}
	}
	return nil
}

func kernelRetentionHints(pm string) []string {
	switch pm {
	case "zypper":
		return []string{
			"to clean: sudo purge-kernels",
			"to bound: set multiversion.kernels = latest,latest-1,running in /etc/zypp/zypp.conf",
		}
	case "dnf":
		return []string{
			"to clean: sudo dnf remove --oldinstallonly",
			"to bound: set installonly_limit=3 in /etc/dnf/dnf.conf",
		}
	default:
		return []string{"to clean: sudo apt autoremove --purge"}
	}
}

// checkLivePatch flags kernel live-patches that are loaded but not actually protecting
// the kernel — disabled (the running kernel executes the UN-patched code) or stuck in
// transition. Silent when all loaded patches are enabled, or when none are loaded.
func checkLivePatch(d models.LivePatchInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	var out []models.Insight
	if len(d.DisabledPatches) > 0 {
		out = append(out, insight("WARN", "LivePatch",
			fmt.Sprintf("%d kernel livepatch(es) loaded but NOT enabled (%s) — the running kernel is executing the UN-patched code for those fixes despite live patching being set up",
				len(d.DisabledPatches), strings.Join(firstN(d.DisabledPatches, 3), ", ")),
			[]string{"to inspect: cat /sys/kernel/livepatch/*/enabled", livePatchInspectHint(d.Tool)}))
	}
	if len(d.TransitioningPatches) > 0 {
		out = append(out, insight("WARN", "LivePatch",
			fmt.Sprintf("%d kernel livepatch(es) stuck in transition (%s) — some tasks have not migrated to the patched code, so the fix is only partially active",
				len(d.TransitioningPatches), strings.Join(firstN(d.TransitioningPatches, 3), ", ")),
			[]string{"to inspect: cat /sys/kernel/livepatch/*/transition"}))
	}
	return out
}

func livePatchInspectHint(tool string) string {
	switch tool {
	case "klp":
		return "to inspect: klp -v patches"
	case "kpatch":
		return "to inspect: kpatch list"
	default:
		return "to inspect: dmesg | grep -i livepatch"
	}
}

// checkTransactional flags a staged-but-not-booted transactional update — the booted
// btrfs snapshot differs from the default (next-boot) snapshot. On MicroOS / SLE Micro
// the running system stays on the OLD snapshot until reboot, so any security/kernel
// update in the new snapshot is NOT yet active — and `zypper needs-rebooting` misses it
// (it checks the unchanged running snapshot). Silent on a clean transactional host.
func checkTransactional(d models.TransactionalInfo) []models.Insight {
	if !d.Available || !d.RebootPending {
		return nil
	}
	return []models.Insight{insight("WARN", "Transactional",
		fmt.Sprintf("a transactional update is staged but NOT active — the system is running snapshot %d while the default (next boot) is snapshot %d. Any security/kernel update in the new snapshot is not applied until you reboot",
			d.BootedSnapshot, d.DefaultSnapshot),
		[]string{
			"to inspect: snapper list   (the booted '*' snapshot differs from the default '+')",
			"to apply: reboot   (boots into the new default snapshot)",
		})}
}
