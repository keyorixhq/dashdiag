package analysis

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	hInitOpenRC = "openrc"
	hFixPrefix  = "to fix: "
	hInitSysV   = "sysvinit"
	hInitRunit  = "runit"
	hCmdStatus  = "status"
	hCmdRestart = "restart"
	hCmdSuffix  = "&& <cmd>"
)

func ApplyThresholds(results []runner.Result, thresh Thresholds, _ platform.CloudEnvironment, ctrCtx platform.ContainerContext) []models.Insight {
	// Pre-scan results to extract context shared across checks.
	prescan := prescanContext(results, &thresh)

	// Inject SELinux enforcing state + ZFS-pool presence into SystemdInfo for
	// cross-check hints / failure-severity gating (§O.2); inject swap-activity into
	// SysctlInfo so the general-server vm.swappiness check only fires when the host
	// is actually swapping; inject a host-imposed VMware CPU limit into CPUInfo so
	// the steal heuristic can attribute high steal to the configured cap (§N.4).
	for i, r := range results {
		switch d := r.Data.(type) {
		case *models.SystemdInfo:
			if d != nil {
				d.SELinuxEnforcing = prescan.selinuxEnforcing
				d.ZFSPoolsPresent = prescan.zfsPoolsPresent
			}
		case models.SystemdInfo:
			d.SELinuxEnforcing = prescan.selinuxEnforcing
			d.ZFSPoolsPresent = prescan.zfsPoolsPresent
			results[i].Data = d
		case *models.SysctlInfo:
			if d != nil {
				d.SwapActive = prescan.swapActive
			}
		case models.SysctlInfo:
			d.SwapActive = prescan.swapActive
			results[i].Data = d
		case *models.CPUInfo:
			if d != nil {
				d.HostCPULimitMHz = prescan.vmwareCPULimitMHz
			}
		case models.CPUInfo:
			d.HostCPULimitMHz = prescan.vmwareCPULimitMHz
			results[i].Data = d
		}
	}

	var insights []models.Insight
	for _, r := range results {
		if r.Err != nil {
			insights = append(insights, insight("INFO", r.Name,
				fmt.Sprintf("check could not run — %v", r.Err), nil))
			continue
		}
		insights = append(insights, applyOne(r.Data, thresh, ctrCtx)...)
	}
	insights = dedupeSELinuxDenials(insights)
	return AdaptHostHints(insights)
}

// dedupeSELinuxDenials collapses the two SELinux-denial verdicts that `dsd health`
// would otherwise emit for the same audit data. `dsd health` runs both the
// KernelSec collector (authoritative tiered severity: CRIT/WARN, with the
// audit2allow workflow hints) and the security collector (Hardening: a flat WARN,
// but with the more actionable grouped scontext→tcontext fix hints). Reading the
// same enforced-denial count, they emitted a CRIT and a WARN for the identical
// event — contradictory and duplicative. Keep the KernelSec insight (its severity
// is the correct one), fold in the Hardening insight's unique hints, and drop the
// Hardening denial insight. Only `dsd health` reaches here; standalone
// `dsd security` calls checkSecurity directly (not ApplyThresholds), so it keeps
// its own denial report.
func dedupeSELinuxDenials(insights []models.Insight) []models.Insight {
	isDenial := func(ins models.Insight, check string) bool {
		return ins.Check == check &&
			strings.Contains(ins.Message, "SELinux denial") &&
			strings.Contains(ins.Message, "last hour")
	}
	var hardeningHints []string
	haveKernelSec, haveHardening := false, false
	for _, ins := range insights {
		switch {
		case isDenial(ins, "KernelSec"):
			haveKernelSec = true
		case isDenial(ins, "Hardening"):
			hardeningHints = ins.Hints
			haveHardening = true
		}
	}
	if !haveKernelSec || !haveHardening {
		return insights // not both present — nothing to collapse
	}
	out := make([]models.Insight, 0, len(insights))
	for _, ins := range insights {
		if isDenial(ins, "Hardening") {
			continue // drop the duplicate verdict
		}
		if isDenial(ins, "KernelSec") {
			// Fold the Hardening insight's grouped-fix hints in, skipping any line
			// KernelSec already carries.
			have := make(map[string]bool, len(ins.Hints))
			for _, h := range ins.Hints {
				have[h] = true
			}
			for _, h := range hardeningHints {
				if !have[h] {
					ins.Hints = append(ins.Hints, h)
					have[h] = true
				}
			}
		}
		out = append(out, ins)
	}
	return out
}

// AdaptHostHints rewrites fix-hint text to the host so the suggested command actually
// runs there: NixOS → configuration.nix; Gentoo → emerge; dnf/zypper/tdnf hosts get
// apt-first install hints re-led with their own tool; and Linux/systemd remedies are
// adapted for macOS / OpenRC. Applied once at the end of Analyze for `dsd health`, and
// by the exported guest *Insights wrappers so the standalone commands adapt too.
func AdaptHostHints(insights []models.Insight) []models.Insight {
	if hostIsNixOS() {
		insights = nixosifyHints(insights)
	}
	// On Gentoo the package-install fix hints (apt/dnf/zypper install …) name the
	// wrong tool — the host uses Portage. Rewrite to `emerge`. (Found on a Gentoo guest.)
	if hostIsGentoo() {
		insights = gentooifyHints(insights)
	}
	// On a transactional/immutable SUSE (MicroOS / Leap Micro / SLE Micro) the root is
	// read-only — `zypper install` won't persist; packages go in via
	// `transactional-update pkg install` + reboot. Rewrite install hints accordingly.
	// (Found live on a Leap Micro / VMware guest.)
	if hostIsTransactional() {
		insights = transactionalifyHints(insights)
	}
	// On an ostree-managed immutable host (Fedora CoreOS / Silverblue / Kinoite /
	// IoT / RHEL CoreOS) /usr is read-only — `dnf install` cannot persist; packages
	// are layered via `rpm-ostree install` + reboot. Rewrite install hints
	// accordingly. After this the hint no longer matches rePkgInstall, so the
	// dnf-lead distroifyInstallHints below is a no-op here. (Found live on a Fedora
	// CoreOS / VMware guest where open-vm-tools/rsyslog hints said `dnf install`.)
	if hostIsOstree() {
		insights = ostreeifyHints(insights)
	}
	// Many install hints are written apt-first ("apt install X (RHEL/SUSE: dnf/zypper
	// install X)"). On a dnf/zypper/tdnf host, lead with the host's own tool so the
	// command is copy-pasteable. (Found live: open-vm-tools on an AlmaLinux/VMware
	// guest.) After transactionalify — on an immutable SUSE that already rewrote the
	// hint to `transactional-update pkg install`, rePkgInstall no longer matches, so
	// this is a no-op there; on a normal dnf/zypper/tdnf host it leads with that tool.
	if pm := hostInstallPM(); pm != "" {
		insights = distroifyInstallHints(insights, pm)
	}
	// Remedy text is generated in its Linux/systemd form; rewrite commands that
	// don't exist on this platform (ss on macOS; systemctl on OpenRC/Alpine) so the
	// hint is runnable where dsd actually runs. Diagnosis is already correct; this
	// fixes only the "to inspect/to fix" line. (TRIAGE §A.)
	return adaptHintsToPlatform(insights, effectiveGOOS(), effectiveInitSystem())
}

// prescanResult holds the cross-check context prescanContext extracts in one
// pass over the collector results, before the per-check pass runs.
type prescanResult struct {
	selinuxEnforcing  bool // SELinux is enforcing (checkSystemd double-layer hints)
	zfsPoolsPresent   bool // host imports ZFS pools of its own (§O.2 import-unit severity)
	swapActive        bool // swap is configured AND in use (gates vm.swappiness check)
	vmwareCPULimitMHz int  // host-imposed VMware CPU cap, MHz (§N.4 steal attribution); 0 = none/unknown
}

// prescanContext walks the collector results once to extract context shared
// across checks before the per-check pass runs. It writes the package manager
// and CPU load into thresh, and returns the SELinux-enforcing state (used by
// checkSystemd for double-layer hints), whether the host imports any ZFS pools
// of its own (gates zfs-import-*.service failure severity, §O.2 — a failed
// zfs-import unit is benign when the ZFS HBA is passed through to a VM), and a
// host-imposed VMware CPU limit so the steal heuristic can attribute high steal
// to a configured cap rather than host over-provisioning (§N.4).
//
//nolint:cyclop // flat type-switch dispatch — each case extracts one shared field; splitting would obscure it
func prescanContext(results []runner.Result, thresh *Thresholds) prescanResult { // NOSONAR — flat type-switch dispatch; CC is entry count, not branch depth
	var p prescanResult
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		switch d := r.Data.(type) {
		case models.PackagesInfo:
			if d.PackageManager != "" {
				thresh.PackageManager = d.PackageManager
			}
		case *models.PackagesInfo:
			if d != nil && d.PackageManager != "" {
				thresh.PackageManager = d.PackageManager
			}
		case models.CPUInfo:
			thresh.CPULoadPct = d.LoadPct
		case *models.CPUInfo:
			if d != nil {
				thresh.CPULoadPct = d.LoadPct
			}
		case models.KernelSecurityInfo:
			if d.SELinuxPresent && d.SELinuxMode == "enforcing" {
				p.selinuxEnforcing = true
			}
		case *models.KernelSecurityInfo:
			if d != nil && d.SELinuxPresent && d.SELinuxMode == "enforcing" {
				p.selinuxEnforcing = true
			}
		case models.ZFSInfo:
			if len(d.Pools) > 0 {
				p.zfsPoolsPresent = true
			}
		case *models.ZFSInfo:
			if d != nil && len(d.Pools) > 0 {
				p.zfsPoolsPresent = true
			}
		case models.DiskInfo:
			if len(d.ZFSPools) > 0 {
				p.zfsPoolsPresent = true
			}
		case *models.DiskInfo:
			if d != nil && len(d.ZFSPools) > 0 {
				p.zfsPoolsPresent = true
			}
		case models.SwapInfo:
			if swapInUse(d) {
				p.swapActive = true
			}
		case *models.SwapInfo:
			if d != nil && swapInUse(*d) {
				p.swapActive = true
			}
		case models.VMwareInfo:
			if d.StatAvailable && d.CPULimitMHz > 0 {
				p.vmwareCPULimitMHz = d.CPULimitMHz
			}
		case *models.VMwareInfo:
			if d != nil && d.StatAvailable && d.CPULimitMHz > 0 {
				p.vmwareCPULimitMHz = d.CPULimitMHz
			}
		}
	}
	return p
}

// swapInUse reports whether swap is configured AND actually being used or paged —
// the only condition under which vm.swappiness affects behaviour. Used to gate the
// general-server swappiness check so the kernel default doesn't WARN an idle box.
func swapInUse(s models.SwapInfo) bool {
	return s.TotalGB > 0 && (s.UsedPct > 0 || s.PagesInPerSec > 0 || s.PagesOutPerSec > 0)
}

// hostInitSystem returns the init system ("systemd", hInitOpenRC, "unknown") so the
// hint adapter can pick the right service command. Indirection keeps
// adaptHintsToPlatform unit-testable without the real host.
var hostInitSystem = func() string { return platform.Detect().InitSystem }

// effectiveDistroID / effectiveGOOS / effectiveInitSystem return the CAPTURED host's
// values when replaying a bundle (platform.SetReplayPlatform pins them from the
// manifest), else live detection. This makes the fix-hint adaptation reflect the
// captured host on `dsd replay`, not the box doing the replay — so "to fix: dnf
// install X" stays dnf when replaying an AlmaLinux capture on a Debian box.
func effectiveDistroID() string {
	if id := platform.ReplayDistroID(); id != "" {
		return id
	}
	return cvedata.DetectDistroID()
}

func effectiveGOOS() string {
	if g := platform.ReplayGOOS(); g != "" {
		return g
	}
	return runtime.GOOS
}

func effectiveInitSystem() string {
	if i := platform.ReplayInitSystem(); i != "" {
		return i
	}
	return hostInitSystem()
}

// adaptHintsToPlatform rewrites each hint's platform-specific command for goos +
// initSystem. Pure dispatch over adaptHint so it can be tested per platform.
// nonSystemdInits are the init systems whose service-management and time tooling
// differ from systemd, so systemd-form remedy/inspect lines must be rewritten.
func isNonSystemdInit(initSystem string) bool {
	switch initSystem {
	case hInitOpenRC, hInitSysV, hInitRunit:
		return true
	}
	return false
}

func adaptHintsToPlatform(insights []models.Insight, goos, initSystem string) []models.Insight {
	if goos != "darwin" && !isNonSystemdInit(initSystem) {
		return insights // systemd (or unknown init): hints already correct / can't improve
	}
	for i := range insights {
		if len(insights[i].Hints) == 0 {
			continue
		}
		out := make([]string, 0, len(insights[i].Hints))
		for _, h := range insights[i].Hints {
			if nh, drop := adaptHint(h, goos, initSystem); !drop {
				out = append(out, nh)
			}
		}
		insights[i].Hints = out
	}
	return insights
}

var (
	// macOS has no `ss`; lsof is the listening-socket equivalent.
	reSSPortGrep = regexp.MustCompile(`^to inspect: ss -t(?:u)?lnp \| grep :(\d+)$`)
	reSSListen   = regexp.MustCompile(`^to inspect: ss -t(?:u)?lnp$`)
	// Non-systemd inits (OpenRC/sysvinit/runit) have none of systemctl/journalctl/
	// timedatectl. Rewrite service-management + `systemctl status`; drop timedatectl/
	// journalctl (no runnable equivalent — the diagnosis still stands).
	reSystemctlAction  = regexp.MustCompile(`^to fix: systemctl (restart|start|stop) (\S+)$`)
	reSystemctlEnable  = regexp.MustCompile(`^to fix: systemctl enable --now (\S+)$`)
	reSystemctlDisable = regexp.MustCompile(`^to fix: systemctl disable (\S.*)$`)
	reSystemctlStatus  = regexp.MustCompile(`^to inspect: systemctl status (\S.*)$`)
	reTimedatectl      = regexp.MustCompile(`^to inspect: timedatectl(?:\s.*)?$`)
	reJournalctl       = regexp.MustCompile(`^to inspect: journalctl(?:\s.*)?$`)
	// Embedded "&& systemctl restart <unit>" tail in a multi-step "to fix:" hint.
	reEmbeddedRestart = regexp.MustCompile(`&& systemctl restart (\S+)$`)
)

// serviceCmd maps a systemd service action (start/stop/restart/status) to the
// equivalent on a non-systemd init. Returns "" for an init with no clean
// equivalent of that verb (caller then leaves the line or drops it).
func serviceCmd(verb, unit, initSystem string) string {
	switch initSystem {
	case hInitOpenRC:
		return fmt.Sprintf("rc-service %s %s", unit, verb)
	case hInitSysV:
		return fmt.Sprintf("service %s %s", unit, verb)
	case hInitRunit:
		// runit's sv uses up/down for start/stop; restart/status are the same word.
		v := map[string]string{"start": "up", "stop": "down", hCmdRestart: hCmdRestart, hCmdStatus: hCmdStatus}[verb]
		if v == "" {
			return ""
		}
		return fmt.Sprintf("sv %s %s", v, unit)
	}
	return ""
}

// adaptHint rewrites a single hint for the platform, or returns drop=true when no
// runnable equivalent exists (the diagnosis still stands; only the remedy line is
// removed). Unknown hints pass through unchanged.
func adaptHint(hint, goos, initSystem string) (string, bool) {
	if goos == "darwin" {
		if m := reSSPortGrep.FindStringSubmatch(hint); m != nil {
			return "to inspect: lsof -nP -iTCP:" + m[1] + " -sTCP:LISTEN", false
		}
		if reSSListen.MatchString(hint) {
			return "to inspect: lsof -nP -iTCP -sTCP:LISTEN", false
		}
		return hint, false
	}
	if isNonSystemdInit(initSystem) {
		return adaptNonSystemdHint(hint, initSystem)
	}
	return hint, false
}

// adaptNonSystemdHint rewrites systemd-form service/time commands for OpenRC,
// sysvinit, or runit. enable/disable are init-specific (rc-update / update-rc.d /
// runit symlink); start/stop/restart/status route through serviceCmd. A
// timedatectl inspect line is dropped (no portable non-systemd equivalent; the
// chronyc/ntpq/date lines beside it remain).
func adaptNonSystemdHint(hint, initSystem string) (string, bool) {
	if m := reSystemctlAction.FindStringSubmatch(hint); m != nil {
		if c := serviceCmd(m[1], m[2], initSystem); c != "" {
			return hFixPrefix + c, false
		}
	}
	if m := reSystemctlStatus.FindStringSubmatch(hint); m != nil {
		// systemctl status may name several units; the per-unit tools take one.
		// systemd-only units (systemd-resolved, systemd-journald, …) have no
		// non-systemd equivalent — drop the line.
		svc := strings.Fields(m[1])
		if len(svc) == 0 || strings.HasPrefix(svc[0], "systemd-") {
			return "", true
		}
		if c := serviceCmd(hCmdStatus, svc[0], initSystem); c != "" {
			return "to inspect: " + c, false
		}
	}
	if reTimedatectl.MatchString(hint) || reJournalctl.MatchString(hint) {
		return "", true // no timedatectl/journalctl equivalent without systemd
	}
	if m := reEmbeddedRestart.FindStringSubmatch(hint); m != nil {
		if c := serviceCmd(hCmdRestart, m[1], initSystem); c != "" {
			return reEmbeddedRestart.ReplaceAllString(hint, "&& "+c), false
		}
	}
	if m := reSystemctlEnable.FindStringSubmatch(hint); m != nil {
		return enableHint(m[1], initSystem), false
	}
	if m := reSystemctlDisable.FindStringSubmatch(hint); m != nil {
		return disableHint(m[1], initSystem), false
	}
	return hint, false
}

func enableHint(unit, initSystem string) string {
	switch initSystem {
	case hInitOpenRC:
		return fmt.Sprintf("to fix: rc-update add %s && rc-service %s start", unit, unit)
	case hInitSysV:
		return fmt.Sprintf("to fix: update-rc.d %s enable && service %s start", unit, unit)
	case hInitRunit:
		return fmt.Sprintf("to fix: ln -s /etc/sv/%s /var/service/", unit)
	}
	return "to fix: systemctl enable --now " + unit
}

func disableHint(unit, initSystem string) string {
	switch initSystem {
	case hInitOpenRC:
		return "to fix: rc-update del " + unit
	case hInitSysV:
		return "to fix: update-rc.d " + unit + " disable"
	case hInitRunit:
		return "to fix: rm /var/service/" + unit
	}
	return "to fix: systemctl disable " + unit
}

// PlatformServiceCmd rewrites a systemd service-management command (e.g.
// "systemctl restart docker") into the form runnable on the running host's init
// system, returning it unchanged on systemd/macOS. It exists so subcommands that
// print remedy lines directly to stdout — outside the insight pipeline that
// adaptHintsToPlatform covers — share the same one source of truth as the
// adapter (it delegates to adaptHint). (TRIAGE §A audit.) Uses effectiveGOOS/
// effectiveInitSystem (not the raw runtime.GOOS/hostInitSystem) so a caller
// reached by `dsd replay` (e.g. CorrelateDeep's rngd/haveged remedy) reflects
// the CAPTURED host's init system, not the box doing the replay — live callers
// (dsd proc/docker/cron/kvm) are unaffected since the replay pin is unset then.
func PlatformServiceCmd(systemdCmd string) string {
	return platformServiceCmd(systemdCmd, effectiveGOOS(), effectiveInitSystem())
}

// platformServiceCmd is the host-independent core, split out so it is
// unit-testable without the real GOOS/init system (see hostInitSystem).
func platformServiceCmd(systemdCmd, goos, initSystem string) string {
	out, _ := adaptHint(hFixPrefix+systemdCmd, goos, initSystem)
	return strings.TrimPrefix(out, hFixPrefix)
}

// PlatformServiceCmdSudo is like PlatformServiceCmd but for callers that print the
// remedy as a privileged command. It applies `sudo` to EACH command in the result,
// because the OpenRC rewrite of `enable --now` is a `&&` pair (rc-update + rc-service)
// and a single leading `sudo` only elevates the first — the second (`rc-service X
// start`, which needs root) would fail for a non-root user copy-pasting the line.
func PlatformServiceCmdSudo(systemdCmd string) string {
	return platformServiceCmdSudo(systemdCmd, effectiveGOOS(), effectiveInitSystem())
}

func platformServiceCmdSudo(systemdCmd, goos, initSystem string) string {
	cmd := platformServiceCmd(systemdCmd, goos, initSystem)
	parts := strings.Split(cmd, " && ")
	for i, p := range parts {
		parts[i] = "sudo " + p
	}
	return strings.Join(parts, " && ")
}

// NixOS configures the system declaratively via configuration.nix + nixos-rebuild,
// not the imperative /etc/sysctl.d, /etc/ssh/sshd_config, and apt/dnf/zypper
// commands the generic fix hints assume. The patterns below are anchored so
// they only rewrite the intended hints; everything else passes through.
var (
	reNixSysctlPersist = regexp.MustCompile(`^to persist: echo '([^'=]+)=(.+)' >> /etc/sysctl\.d/99-dsd\.conf$`)
	reNixSSHDSet       = regexp.MustCompile(`^to fix: set (\S+) (.+) in /etc/ssh/sshd_config$`)
	reNixSSHDEchoSet   = regexp.MustCompile(`^to fix:\s+echo '(\S+) (.+)' >> /etc/ssh/sshd_config && systemctl restart sshd$`)
	reNixSSHRestart    = regexp.MustCompile(`^to fix: systemctl restart sshd$`)
	reNixSSHProtocol   = regexp.MustCompile(`^to fix: remove or comment out 'Protocol' line in /etc/ssh/sshd_config$`)
	reNixRsyslog       = regexp.MustCompile(`^to fix: apt install rsyslog\s+OR\s+dnf install rsyslog\s+OR\s+zypper install rsyslog$`)
	reNixJournald      = regexp.MustCompile(`^to (?:fix|persist):\s+echo '([^']+)' >> /etc/systemd/journald\.conf(?: && systemctl restart systemd-journald)?$`)
)

// hostIsNixOS reports whether the running host is NixOS, per /etc/os-release.
func hostIsNixOS() bool {
	return strings.Contains(strings.ToLower(effectiveDistroID()), "nixos")
}

// nixosifyHints rewrites every insight's fix hints into their configuration.nix
// equivalents. Hints that match no known pattern are left untouched.
func nixosifyHints(insights []models.Insight) []models.Insight {
	for i := range insights {
		if len(insights[i].Hints) == 0 {
			continue
		}
		rewritten := make([]string, 0, len(insights[i].Hints))
		for _, h := range insights[i].Hints {
			if nh, drop := nixosFixHint(h); !drop {
				rewritten = append(rewritten, nh)
			}
		}
		insights[i].Hints = rewritten
	}
	return insights
}

// nixosFixHint rewrites a single generic fix hint to its NixOS form. The bool
// return is true when the hint should be dropped on NixOS (a standalone sshd
// restart that the rebuild already covers); otherwise it returns the rewritten
// hint, or the hint unchanged when no NixOS rewrite applies.
func nixosFixHint(hint string) (string, bool) {
	if m := reNixSysctlPersist.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to persist (NixOS): boot.kernel.sysctl = { %q = %s; }; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if m := reNixSSHDSet.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.openssh.settings.%s = %q; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if m := reNixSSHDEchoSet.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.openssh.settings.%s = %q; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if reNixSSHRestart.MatchString(hint) {
		return "", true // configuration.nix rebuild already restarts sshd
	}
	if reNixSSHProtocol.MatchString(hint) {
		return "to fix (NixOS): remove any 'Protocol' line from services.openssh.extraConfig, then nixos-rebuild switch", false
	}
	if reNixRsyslog.MatchString(hint) {
		return "to fix (NixOS): services.rsyslogd.enable = true; in configuration.nix, then nixos-rebuild switch", false
	}
	if m := reNixJournald.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.journald.extraConfig = %q; in configuration.nix, then nixos-rebuild switch", m[1]), false
	}
	return hint, false
}

// rePkgInstall captures the package name from the first distro package-install
// suggestion embedded in a fix hint. Anchored on the manager keyword immediately
// before `install` so compound strings like "dnf/apt/zypper install rsyslog"
// still match (at "zypper install rsyslog"); apt-get is listed before apt so the
// longer keyword wins. One package token is captured — the install hints dsd
// emits are single-package, and the few wrong-category atoms on Gentoo (e.g.
// akmod-nvidia) are still a better pointer than apt/dnf/zypper.
var rePkgInstall = regexp.MustCompile(`\b(?:apt-get|apt|dnf|yum|tdnf|zypper)\s+install\s+([A-Za-z0-9][A-Za-z0-9._+-]*)`)

// hostIsGentoo reports whether the running host is Gentoo, per /etc/os-release.
func hostIsGentoo() bool {
	return strings.Contains(strings.ToLower(effectiveDistroID()), "gentoo")
}

// gentooifyHints rewrites every insight's package-install fix hints to their
// Portage `emerge` equivalent. Hints carrying no install suggestion (notes,
// inspect lines, sysctl/sshd edits) pass through untouched.
func gentooifyHints(insights []models.Insight) []models.Insight {
	for i := range insights {
		for j, h := range insights[i].Hints {
			insights[i].Hints[j] = gentooFixHint(h)
		}
	}
	return insights
}

// hostInstallPM maps the host distro to the package-install command its admin
// actually uses, so apt-first fix hints can be rewritten to lead with the right tool.
// Returns "" to leave hints unchanged: Debian/Ubuntu (apt is already first), distros
// with a dedicated rewriter (Gentoo→emerge, NixOS), and unknown distros (don't guess).
func hostInstallPM() string {
	id := strings.ToLower(effectiveDistroID())
	switch {
	case id == "" || strings.Contains(id, "gentoo") || strings.Contains(id, "nixos"):
		return ""
	case strings.Contains(id, "photon"):
		return "tdnf"
	case strings.Contains(id, "suse") || strings.Contains(id, "sle"):
		return "zypper"
	case idMatchesAny(id, "rhel", "centos", "almalinux", "alma", "rocky", "fedora", "oracle", "ol", "amzn", "rhpkg"):
		return "dnf"
	case idMatchesAny(id, "arch", "artix", "manjaro", "endeavouros", "garuda", "arcolinux"):
		return "pacman"
	case strings.Contains(id, "alpine"):
		return "apk"
	default:
		return "" // debian/ubuntu (apt-first already correct) or unknown
	}
}

func idMatchesAny(id string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(id, s) {
			return true
		}
	}
	return false
}

// distroifyInstallHints rewrites each insight's package-install fix hint to lead with
// the host's package manager (pm), preserving any trailing hCmdSuffix action. Hints
// with no install suggestion (notes, inspect lines, config edits) pass through.
func distroifyInstallHints(insights []models.Insight, pm string) []models.Insight {
	for i := range insights {
		hints := insights[i].Hints
		for j := range hints {
			hints[j] = distroFixHint(hints[j], pm)
		}
	}
	return insights
}

// distroFixHint rewrites one install hint to "to fix: <pm> install <pkg>", preserving
// any trailing hCmdSuffix action. Returns the hint unchanged when it carries no
// package-install suggestion (mirrors gentooFixHint).
func distroFixHint(hint, pm string) string {
	m := rePkgInstall.FindStringSubmatch(hint)
	if m == nil {
		return hint
	}
	out := hFixPrefix + pmInstallCmd(pm, m[1])
	if idx := strings.Index(hint, "&&"); idx >= 0 {
		out += " " + strings.TrimSpace(hint[idx:])
	}
	return out
}

// pmInstallCmd renders the package-install command for a package manager. Most use
// "<pm> install <pkg>"; pacman (Arch family) and apk (Alpine) use their own verbs.
func pmInstallCmd(pm, pkg string) string {
	switch pm {
	case "pacman":
		return "pacman -S " + pkg
	case "apk":
		return "apk add " + pkg
	default: // apt, apt-get, dnf, yum, tdnf, zypper
		return pm + " install " + pkg
	}
}

// gentooFixHint rewrites a single install hint to "to fix (Gentoo): emerge <pkg>",
// preserving any trailing hCmdSuffix action (e.g. enabling a service). Returns the
// hint unchanged when it carries no package-install suggestion.
func gentooFixHint(hint string) string {
	m := rePkgInstall.FindStringSubmatch(hint)
	if m == nil {
		return hint
	}
	out := "to fix (Gentoo): emerge " + m[1]
	if idx := strings.Index(hint, "&&"); idx >= 0 {
		out += " " + strings.TrimSpace(hint[idx:])
	}
	return out
}

// hostIsTransactional reports whether the host is a transactional/immutable SUSE —
// openSUSE MicroOS, Leap Micro, or SLE/SL Micro — where the root is read-only and
// packages are installed via `transactional-update pkg install` + reboot, not live
// `zypper install`. All such IDs carry "micro" (opensuse-leap-micro, opensuse-microos,
// sle-micro, sl-micro).
func hostIsTransactional() bool {
	return strings.Contains(strings.ToLower(effectiveDistroID()), "micro")
}

// transactionalifyHints rewrites every insight's package-install fix hints to the
// transactional-update form. Hints carrying no install suggestion pass through.
func transactionalifyHints(insights []models.Insight) []models.Insight {
	for i := range insights {
		hints := insights[i].Hints
		for j := range hints {
			hints[j] = transactionalFixHint(hints[j])
		}
	}
	return insights
}

// transactionalFixHint rewrites a single install hint to its transactional-update
// form. The "&& <service-enable>" tail is intentionally dropped: on a transactional
// system the install lands in a new snapshot that takes effect only after a reboot,
// so enabling the service in the same breath would not work. Returns the hint
// unchanged when it carries no package-install suggestion.
func transactionalFixHint(hint string) string {
	m := rePkgInstall.FindStringSubmatch(hint)
	if m == nil {
		return hint
	}
	return "to fix (transactional): transactional-update pkg install " + m[1] + " (then reboot)"
}

// ostreeifyHints rewrites every insight's package-install fix hint to its
// rpm-ostree layering form. Hints carrying no install suggestion (notes, inspect
// lines, sysctl/sshd edits) pass through untouched.
func ostreeifyHints(insights []models.Insight) []models.Insight {
	for i := range insights {
		hints := insights[i].Hints
		for j := range hints {
			hints[j] = ostreeFixHint(hints[j])
		}
	}
	return insights
}

// ostreeFixHint rewrites a single install hint to its rpm-ostree form. As with
// the transactional rewrite, the "&& <service-enable>" tail is dropped: a layered
// package only takes effect after the next boot, so enabling the service in the
// same breath would not work. Returns the hint unchanged when it carries no
// package-install suggestion.
func ostreeFixHint(hint string) string {
	m := rePkgInstall.FindStringSubmatch(hint)
	if m == nil {
		return hint
	}
	return "to fix (ostree): rpm-ostree install " + m[1] + " (then reboot)"
}

// isNilTypedPointer reports whether data is a non-nil interface{} boxing a nil
// pointer (e.g. a collector returning `var info *models.XInfo; return info, nil`).
// A typed nil still matches its `case *models.XInfo:` arm in the switches below,
// so every arm would otherwise need its own nil guard before dereferencing.
// Checking once here keeps every dispatch arm a flat, unconditional `return`.
func isNilTypedPointer(data any) bool {
	v := reflect.ValueOf(data)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

//nolint:cyclop // type dispatch — each case is trivial
func applyOne(data any, thresh Thresholds, ctrCtx platform.ContainerContext) []models.Insight { // NOSONAR — type dispatch; each case is trivial and independent
	if isNilTypedPointer(data) {
		return nil
	}
	switch d := data.(type) {
	case models.CPUInfo:
		return checkCPU(d, thresh, ctrCtx)
	case *models.CPUInfo:
		return checkCPU(*d, thresh, ctrCtx)
	case models.MemoryInfo:
		return checkMemory(d, thresh, ctrCtx)
	case *models.MemoryInfo:
		return checkMemory(*d, thresh, ctrCtx)
	case models.DiskInfo:
		return checkDisk(d, thresh)
	case *models.DiskInfo:
		return checkDisk(*d, thresh)
	case models.SwapInfo:
		return checkSwap(d, thresh)
	case *models.SwapInfo:
		return checkSwap(*d, thresh)
	case models.IOInfo:
		return checkIO(d, thresh)
	case *models.IOInfo:
		return checkIO(*d, thresh)
	case models.NetworkInfo:
		return checkNetwork(d)
	case *models.NetworkInfo:
		return checkNetwork(*d)
	case models.NFSInfo:
		return checkNFS(d)
	case *models.NFSInfo:
		return checkNFS(*d)
	case models.BINDInfo:
		return checkBIND(d)
	case *models.BINDInfo:
		return checkBIND(*d)
	case models.ClockInfo:
		return checkClock(d, thresh)
	case *models.ClockInfo:
		return checkClock(*d, thresh)
	case models.NetworkdConfigInfo:
		return checkNetworkdConfig(d)
	case *models.NetworkdConfigInfo:
		return checkNetworkdConfig(*d)
	case models.RootFSInfo:
		return checkRootFS(d)
	case *models.RootFSInfo:
		return checkRootFS(*d)
	case models.FstabInfo:
		return checkFstab(d)
	case *models.FstabInfo:
		return checkFstab(*d)
	}
	return applyOneExtended(data, thresh)
}

//nolint:cyclop // type dispatch — each case is trivial
func applyOneExtended(data any, thresh Thresholds) []models.Insight { //nolint:funlen // NOSONAR — flat type switch; CC is entry count, not branch depth
	if isNilTypedPointer(data) {
		return nil
	}
	switch d := data.(type) {
	case models.FDInfo:
		return checkFD(d, thresh)
	case *models.FDInfo:
		return checkFD(*d, thresh)
	case models.SystemdInfo:
		return checkSystemd(d)
	case *models.SystemdInfo:
		return checkSystemd(*d)
	case models.SysctlInfo:
		return checkSysctl(d)
	case *models.SysctlInfo:
		return checkSysctl(*d)
	case models.KernelSecurityInfo:
		return checkKernelSecurity(d, thresh)
	case *models.KernelSecurityInfo:
		return checkKernelSecurity(*d, thresh)
	case models.LogsInfo:
		return checkLogs(d, thresh)
	case *models.LogsInfo:
		return checkLogs(*d, thresh)
	case models.EntropyInfo:
		return checkEntropy(d)
	case *models.EntropyInfo:
		return checkEntropy(*d)
	case models.PackagesInfo:
		return checkPackages(d)
	case *models.PackagesInfo:
		return checkPackages(*d)
	case models.CVEAllResult:
		return checkCVEHealth(d)
	case *models.CVEAllResult:
		return checkCVEHealth(*d)
	case models.NVMeInfo:
		return checkNVMe(d)
	case *models.NVMeInfo:
		return checkNVMe(*d)
	case models.RAIDInfo:
		return checkRAID(d)
	case *models.RAIDInfo:
		return checkRAID(*d)
	case models.ZFSInfo:
		return checkZFS(d)
	case *models.ZFSInfo:
		return checkZFS(*d)
	case models.LVMInfo:
		return checkLVM(d)
	case *models.LVMInfo:
		return checkLVM(*d)
	case models.DRBDInfo:
		return checkDRBD(d)
	case *models.DRBDInfo:
		return checkDRBD(*d)
	case models.PVEInfo:
		return checkPVE(d)
	case *models.PVEInfo:
		return checkPVE(*d)
	case models.BatteryInfo:
		return checkBattery(d)
	case *models.BatteryInfo:
		return checkBattery(*d)
	case models.ThermalInfo:
		return checkThermal(d, thresh)
	case *models.ThermalInfo:
		return checkThermal(*d, thresh)
	case models.HealthDeepInfo:
		return checkHealthDeep(d)
	case *models.HealthDeepInfo:
		return checkHealthDeep(*d)
	case models.FirmwareInfo:
		return checkFirmware(d)
	case *models.FirmwareInfo:
		return checkFirmware(*d)
	case models.DockerInfo:
		return checkDocker(d)
	case *models.DockerInfo:
		return checkDocker(*d)
	case models.ContainerdInfo:
		return checkContainerd(d)
	case *models.ContainerdInfo:
		return checkContainerd(*d)
	case models.PostgresInfo:
		return checkPostgres(d)
	case *models.PostgresInfo:
		return checkPostgres(*d)
	case models.MySQLInfo:
		return checkMySQL(d)
	case *models.MySQLInfo:
		return checkMySQL(*d)
	case models.RedisInfo:
		return checkRedis(d)
	case *models.RedisInfo:
		return checkRedis(*d)
	case models.MemcachedInfo:
		return checkMemcached(d)
	case *models.MemcachedInfo:
		return checkMemcached(*d)
	case models.NginxInfo:
		return checkNginx(d)
	case *models.NginxInfo:
		return checkNginx(*d)
	case models.ApacheInfo:
		return checkApache(d)
	case *models.ApacheInfo:
		return checkApache(*d)
	case models.HAProxyInfo:
		return checkHAProxy(d)
	case *models.HAProxyInfo:
		return checkHAProxy(*d)
	case models.RabbitMQInfo:
		return checkRabbitMQ(d)
	case *models.RabbitMQInfo:
		return checkRabbitMQ(*d)
	case models.ElasticsearchInfo:
		return checkElasticsearch(d)
	case *models.ElasticsearchInfo:
		return checkElasticsearch(*d)
	case models.MongoDBInfo:
		return checkMongoDB(d)
	case *models.MongoDBInfo:
		return checkMongoDB(*d)
	case models.KafkaInfo:
		return checkKafka(d)
	case *models.KafkaInfo:
		return checkKafka(*d)
	case models.PrometheusInfo:
		return checkPrometheus(d)
	case *models.PrometheusInfo:
		return checkPrometheus(*d)
	case models.AlertmanagerInfo:
		return checkAlertmanager(d)
	case *models.AlertmanagerInfo:
		return checkAlertmanager(*d)
	case models.GrafanaInfo:
		return checkGrafana(d)
	case *models.GrafanaInfo:
		return checkGrafana(*d)
	case models.TraefikInfo:
		return checkTraefik(d)
	case *models.TraefikInfo:
		return checkTraefik(*d)
	case models.EnvoyInfo:
		return checkEnvoy(d)
	case *models.EnvoyInfo:
		return checkEnvoy(*d)
	case models.K8sInfo:
		return checkK8s(d)
	case *models.K8sInfo:
		return checkK8s(*d)
	case models.RancherInfo:
		return checkRancher(d)
	case *models.RancherInfo:
		return checkRancher(*d)
	case models.HAInfo:
		return checkHA(d)
	case *models.HAInfo:
		return checkHA(*d)
	case models.KVMInfo:
		return checkKVM(d)
	case *models.KVMInfo:
		return checkKVM(*d)
	case models.SteamOSInfo:
		return checkSteamOS(d)
	case *models.SteamOSInfo:
		return checkSteamOS(*d)
	case models.TLSInfo:
		return checkTLS(d)
	case *models.TLSInfo:
		return checkTLS(*d)
	case models.GPUInfo:
		return checkGPU(d)
	case *models.GPUInfo:
		return checkGPU(*d)
	case models.SecurityInfo:
		return checkSecurity(d)
	case *models.SecurityInfo:
		return checkSecurity(*d)
	case models.ProcessInfo:
		return checkProcesses(d, thresh)
	case *models.ProcessInfo:
		return checkProcesses(*d, thresh)
	case models.SnapperInfo:
		return checkSnapper(d)
	case *models.SnapperInfo:
		return checkSnapper(*d)
	case models.SUSEConnectInfo:
		return checkSUSEConnect(d)
	case *models.SUSEConnectInfo:
		return checkSUSEConnect(*d)
	case models.HardwareInfo:
		return checkHardware(d)
	case *models.HardwareInfo:
		return checkHardware(*d)
	case models.BondingInfo:
		return checkBonding(d)
	case *models.BondingInfo:
		return checkBonding(*d)
	case models.IPMIInfo:
		return checkIPMI(d)
	case *models.IPMIInfo:
		return checkIPMI(*d)
	case models.OOMInfo:
		return checkOOM(d)
	case *models.OOMInfo:
		return checkOOM(*d)
	case models.MTEInfo:
		return checkMTE(d)
	case *models.MTEInfo:
		return checkMTE(*d)
	case models.HBAInfo:
		return checkHBA(d)
	case *models.HBAInfo:
		return checkHBA(*d)
	case models.PressureInfo:
		return checkPressure(d)
	case *models.PressureInfo:
		return checkPressure(*d)
	case models.MultipathInfo:
		return checkMultipath(d)
	case *models.MultipathInfo:
		return checkMultipath(*d)
	case models.HWRaidInfo:
		return checkHWRaid(d)
	case *models.HWRaidInfo:
		return checkHWRaid(*d)
	case models.CephInfo:
		return checkCeph(d)
	case *models.CephInfo:
		return checkCeph(*d)
	case models.FirewallInfo:
		return checkFirewall(d)
	case *models.FirewallInfo:
		return checkFirewall(*d)
	case models.AuthInfo:
		return checkAuth(d)
	case *models.AuthInfo:
		return checkAuth(*d)
	case models.CloudInfo:
		return checkCloudMeta(d)
	case *models.CloudInfo:
		return checkCloudMeta(*d)
	case models.CloudInitInfo:
		return checkCloudInit(d)
	case *models.CloudInitInfo:
		return checkCloudInit(*d)
	case models.VMwareInfo:
		return checkVMware(d)
	case *models.VMwareInfo:
		return checkVMware(*d)
	case models.KVMGuestInfo:
		return checkKVMGuest(d)
	case *models.KVMGuestInfo:
		return checkKVMGuest(*d)
	case models.ContainerGuestInfo:
		return checkContainerGuest(d)
	case *models.ContainerGuestInfo:
		return checkContainerGuest(*d)
	case models.AWSInfo:
		return checkAWS(d)
	case *models.AWSInfo:
		return checkAWS(*d)
	case models.AzureInfo:
		return checkAzure(d)
	case *models.AzureInfo:
		return checkAzure(*d)
	case models.GCPInfo:
		return checkGCP(d)
	case *models.GCPInfo:
		return checkGCP(*d)
	case models.OCIInfo:
		return checkOCI(d)
	case *models.OCIInfo:
		return checkOCI(*d)
	case models.PostBootInfo:
		return checkPostBoot(d)
	case *models.PostBootInfo:
		return checkPostBoot(*d)
	case models.AuditInfo:
		return checkAuditd(d)
	case *models.AuditInfo:
		return checkAuditd(*d)
	case models.NUMAInfo:
		return checkNUMA(d)
	case *models.NUMAInfo:
		return checkNUMA(*d)
	case models.VLANInfo:
		return checkVLAN(d)
	case *models.VLANInfo:
		return checkVLAN(*d)
	case models.ISCSIInfo:
		return checkISCSI(d)
	case *models.ISCSIInfo:
		return checkISCSI(*d)
	case models.InfiniBandInfo:
		return checkInfiniBand(d)
	case *models.InfiniBandInfo:
		return checkInfiniBand(*d)
	case models.SRIOVInfo:
		return checkSRIOV(d)
	case *models.SRIOVInfo:
		return checkSRIOV(*d)
	case models.NspawnInfo:
		return checkNspawn(d)
	case *models.NspawnInfo:
		return checkNspawn(*d)
	case models.HugePagesInfo:
		return checkHugePages(d)
	case *models.HugePagesInfo:
		return checkHugePages(*d)
	case models.CPUFreqInfo:
		return checkCPUFreq(d, thresh)
	case *models.CPUFreqInfo:
		return checkCPUFreq(*d, thresh)
	case models.LaunchdInfo:
		return checkLaunchd(d)
	case *models.LaunchdInfo:
		return checkLaunchd(*d)
	case models.DBusInfo:
		return checkDBus(d)
	case *models.DBusInfo:
		return checkDBus(*d)
	case models.SessionsInfo:
		return checkSessions(d)
	case *models.SessionsInfo:
		return checkSessions(*d)
	case models.CronInfo:
		return checkCron(d)
	case *models.CronInfo:
		return checkCron(*d)
	case models.DNSResolverInfo:
		return checkDNS(d)
	case *models.DNSResolverInfo:
		return checkDNS(*d)
	case models.KdumpInfo:
		return checkKdump(d)
	case *models.KdumpInfo:
		return checkKdump(*d)
	case models.TunedInfo:
		return checkTuned(d)
	case *models.TunedInfo:
		return checkTuned(*d)
	case models.KernelPatchInfo:
		return checkKernelPatch(d)
	case *models.KernelPatchInfo:
		return checkKernelPatch(*d)
	case models.KspliceInfo:
		return checkKsplice(d)
	case *models.KspliceInfo:
		return checkKsplice(*d)
	case models.ServiceRestartInfo:
		return checkServiceRestart(d)
	case *models.ServiceRestartInfo:
		return checkServiceRestart(*d)
	case models.KernelRetentionInfo:
		return checkKernelRetention(d)
	case *models.KernelRetentionInfo:
		return checkKernelRetention(*d)
	case models.LivePatchInfo:
		return checkLivePatch(d)
	case *models.LivePatchInfo:
		return checkLivePatch(*d)
	case models.TransactionalInfo:
		return checkTransactional(d)
	case *models.TransactionalInfo:
		return checkTransactional(*d)
	case models.ServicesInfo:
		return checkServices(d)
	case *models.ServicesInfo:
		return checkServices(*d)
	case models.VaultInfo:
		return checkVault(d)
	case *models.VaultInfo:
		return checkVault(*d)
	}
	return nil
}

func levelPct(val, warn, crit float64) string {
	if val >= crit {
		return "CRIT"
	}
	if val >= warn {
		return "WARN"
	}
	return ""
}

func insight(level, check, message string, hints []string) models.Insight {
	return models.Insight{Level: level, Check: check, Message: message, Hints: hints}
}

// eccInsights turns EDAC corrected/uncorrected counts into insights. Shared by
// the health Memory check and the hardware check so their thresholds and wording
// can't drift. Uncorrected errors are an active RAM fault (CRIT); corrected
// errors above a small floor mean a DIMM is degrading (WARN).
func eccInsights(corrected, uncorrected int64, check string) []models.Insight {
	switch {
	case uncorrected > 0:
		return []models.Insight{insight("CRIT", check,
			fmt.Sprintf("%d uncorrected ECC memory error(s) — hardware RAM fault", uncorrected),
			[]string{"to inspect: edac-util -s 4", "to diagnose: run memtest86+ and check which DIMM"})}
	case corrected > 100:
		return []models.Insight{insight("WARN", check,
			fmt.Sprintf("%d corrected ECC memory error(s) — RAM degrading", corrected),
			[]string{"to inspect: edac-util -s 4", "note: rising corrected-error counts often precede an uncorrectable fault"})}
	}
	return nil
}

// diskGrowthMinGapGB and diskGrowthMinGapFrac are the thresholds for flagging a
// filesystem that wasn't resized after its device grew. BOTH must be exceeded: a
// >=10% relative gap is well above normal filesystem metadata overhead (~1-2% for
// ext4, less for xfs), and a >=1 GB absolute gap keeps small disks and rounding
// from ever tripping it.
const (
	diskGrowthMinGapGB   = 1.0
	diskGrowthMinGapFrac = 0.10
)

// cpuDeepSaturationLoadFloorPct mirrors the default CPU load warn multiplier
// (0.7): below this load-average ratio the box is not under sustained pressure,
// so a per-core "all saturated" reading is dsd's own collection overhead.
const cpuDeepSaturationLoadFloorPct = 70.0

// ── New heuristics: Bonding, IPMI, OOM, HBA, Pressure, Multipath ──────────

// ── Medium priority: Ceph, Firewall, Auth, CloudMeta, Auditd ──────────────
// ── Low priority: NUMA, VLAN, iSCSI, InfiniBand, SR-IOV, Nspawn ──────────

// ── HugePages and CPUFreq heuristics ────────────────────────────────────────

// firstN returns at most the first n elements of ss.
func firstN(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return ss[:n]
}

// ── SSH weak algorithm checks (Spec 13) ──────────────────────────────────────

// ── cgroup v2 heuristics ─────────────────────────────────────────────────────
// Integrated into checkHealthDeep (HealthDeepInfo) below.
