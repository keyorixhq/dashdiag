//go:build linux

package collectors

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// RHEL/Oracle-family maintenance & patch-effectiveness collectors. Each is gated
// (silent on hosts without the subsystem) and reads every input through the
// Source-routed helpers (readFile/runCmd*/glob/hasCmd) so capture → replay is
// faithful. See internal/models/maintenance.go for the recorded fields.

// The kdump / kernel-reboot / Ksplice checks are HOST-kernel concerns — a container
// shares the host's kernel (so `uname -r` shows the host's, which it can't reboot or
// kdump), making those checks meaningless and a quasi-false-OK inside a container.
// So each of those three collectors carries the ContainerContext (computed once in
// cmd/health.go, replay-safe) and gates off when InContainer — passed in (not
// fetched from global state) so the gate is deterministic and unit-testable.
// ServiceRestart deliberately does NOT gate: a container's own processes can still
// map a library replaced on disk.

// maintenanceSkip is the single gate decision shared by the three host-kernel
// collectors: skip when the subsystem is absent OR we're in a container. Centralised
// (one place to get right) and pure (the container regression — #655 — is pinned by
// TestMaintenanceSkip without faking the host's filesystem).
func maintenanceSkip(available, inContainer bool) bool { return !available || inContainer }

// ── Kdump ────────────────────────────────────────────────────────────────────

type KdumpCollector struct{ cc platform.ContainerContext }

func NewKdumpCollector(cc platform.ContainerContext) *KdumpCollector { return &KdumpCollector{cc: cc} }
func (c *KdumpCollector) Name() string                               { return "Kdump" }
func (c *KdumpCollector) Timeout() time.Duration                     { return 3 * time.Second }

// KdumpAvailable is true when the host ships kdump (kexec-tools) — i.e. the
// kdump.service unit exists. Gating on the unit (not on the kernel's kexec sysfs,
// which exists on nearly every kernel) means we never nag a host that never
// intended to use kdump.
func KdumpAvailable() bool {
	return fileExists("/usr/lib/systemd/system/kdump.service") ||
		fileExists("/lib/systemd/system/kdump.service") ||
		fileExists("/etc/systemd/system/kdump.service")
}

func (c *KdumpCollector) Collect(ctx context.Context) (interface{}, error) {
	if maintenanceSkip(KdumpAvailable(), c.cc.InContainer) {
		return &models.KdumpInfo{}, nil
	}
	info := &models.KdumpInfo{Available: true}

	if out, _ := runCmdOutput(ctx, "systemctl", "is-enabled", "kdump"); out != "" {
		s := strings.TrimSpace(out)
		info.Enabled = s == "enabled" || s == "static" || s == "enabled-runtime"
	}
	if out, _ := runCmdOutput(ctx, "systemctl", "is-active", "kdump"); out != "" {
		info.ServiceState = strings.TrimSpace(out)
		info.ServiceActive = info.ServiceState == "active"
	}
	if b, err := readFile("/sys/kernel/kexec_crash_loaded"); err == nil {
		info.CrashLoaded = strings.TrimSpace(string(b)) == "1"
	}
	if b, err := readFile("/sys/kernel/kexec_crash_size"); err == nil {
		info.ReservedBytes, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	if b, err := readFile("/proc/cmdline"); err == nil {
		for _, tok := range strings.Fields(string(b)) {
			if strings.HasPrefix(tok, "crashkernel=") {
				info.Crashkernel = strings.TrimPrefix(tok, "crashkernel=")
			}
		}
	}
	return info, nil
}

// ── tuned ────────────────────────────────────────────────────────────────────

type TunedCollector struct{}

func NewTunedCollector() *TunedCollector         { return &TunedCollector{} }
func (c *TunedCollector) Name() string           { return "Tuned" }
func (c *TunedCollector) Timeout() time.Duration { return 4 * time.Second }

func TunedAvailable() bool {
	return hasCmd("tuned-adm") ||
		fileExists("/usr/lib/systemd/system/tuned.service") ||
		fileExists("/lib/systemd/system/tuned.service")
}

func (c *TunedCollector) Collect(ctx context.Context) (interface{}, error) {
	if !TunedAvailable() {
		return &models.TunedInfo{}, nil
	}
	info := &models.TunedInfo{Available: true}

	if out, _ := runCmdOutput(ctx, "systemctl", "is-active", "tuned"); strings.TrimSpace(out) == "active" {
		info.Active = true
	}
	// "Current active profile: virtual-guest"
	if out, err := runCmd(ctx, "tuned-adm", "active"); err == nil {
		if i := strings.LastIndex(out, ":"); i >= 0 {
			info.Profile = strings.TrimSpace(out[i+1:])
		}
	}
	// tuned's own verdict for this hardware (e.g. "virtual-guest" on a VM).
	if out, err := runCmd(ctx, "tuned-adm", "recommend"); err == nil {
		info.Recommended = strings.TrimSpace(out)
	}
	return info, nil
}

// ── Kernel reboot-to-apply ───────────────────────────────────────────────────

type KernelPatchCollector struct{ cc platform.ContainerContext }

func NewKernelPatchCollector(cc platform.ContainerContext) *KernelPatchCollector {
	return &KernelPatchCollector{cc: cc}
}
func (c *KernelPatchCollector) Name() string           { return "Kernel" }
func (c *KernelPatchCollector) Timeout() time.Duration { return 5 * time.Second }

func KernelPatchAvailable() bool { return hasCmd("rpm") || debianRebootMechanism() }

// debianRebootMechanism reports whether the host uses Ubuntu/Debian's
// /run/reboot-required signal — written by update-notifier-common /
// unattended-upgrades after a kernel or core-library update. A minimal Debian
// without that hook has no such signal, so we don't claim to check it there.
func debianRebootMechanism() bool {
	return fileExists("/usr/share/update-notifier/notify-reboot-required") ||
		fileExists("/run/reboot-required")
}

// kernelNVRAToUname strips the package-name prefix off a kernel NVRA so it matches
// `uname -r` (e.g. "kernel-uek-6.12.0-203.el10uek.x86_64" → "6.12.0-203.el10uek.x86_64").
// Longest prefix first.
func kernelNVRAToUname(nvra string) string {
	for _, p := range []string{"kernel-uek-core-", "kernel-uek-", "kernel-core-", "kernel-"} {
		if strings.HasPrefix(nvra, p) {
			return strings.TrimPrefix(nvra, p)
		}
	}
	return nvra
}

func (c *KernelPatchCollector) Collect(ctx context.Context) (interface{}, error) {
	if maintenanceSkip(KernelPatchAvailable(), c.cc.InContainer) {
		return &models.KernelPatchInfo{}, nil
	}
	info := &models.KernelPatchInfo{}
	if b, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Running = strings.TrimSpace(string(b))
	}
	if hasCmd("rpm") {
		// RHEL/Oracle family: the running uname and the kernel package NVRA line up, so
		// compare directly against the newest-INSTALLED kernel (--last orders by install
		// time; rpm exits non-zero when a queried package is absent, so runCmdOutput to
		// keep the installed lines). kernel-uek-core is the actual UEK package on Oracle
		// Linux (the `kernel-uek` meta is often absent); kernel-core is EL9+ RHCK.
		out, _ := runCmdOutput(ctx, "rpm", "-q", "--last", "kernel-uek-core", "kernel-uek", "kernel-core", "kernel")
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			fields := strings.Fields(line)
			if len(fields) == 0 || strings.Contains(line, "not installed") || strings.HasPrefix(line, "package ") {
				continue
			}
			info.LatestInstalled = kernelNVRAToUname(fields[0])
			break
		}
		if info.LatestInstalled != "" {
			info.Available = true
			info.RebootNeeded = info.Running != "" && info.Running != info.LatestInstalled
			return info, nil
		}
		// SUSE (kernel-default): the package NVRA and uname don't line up (uname carries
		// the `-default` flavor), so use zypper's own signal instead of parsing versions.
		if hasCmd("zypper") {
			if ok, rebootNeeded, unverified := suseRebootSignal(ctx); ok {
				info.Available, info.RebootNeeded, info.CheckUnverified = true, rebootNeeded, unverified
				return info, nil
			}
		}
	}
	// Debian/Ubuntu: the canonical signal is /run/reboot-required, written by
	// update-notifier-common / unattended-upgrades after a kernel or core-library
	// update. The package NVRA→uname comparison above is RHEL-specific, so this file
	// is the right (and simpler) signal here.
	if debianRebootMechanism() {
		info.Available = true
		info.RebootNeeded = fileExists("/run/reboot-required")
		return info, nil
	}
	// No recognized kernel-package signal (e.g. a distro family we don't cover yet) —
	// leave Available=false so health does NOT show a misleading "Kernel OK" having
	// checked nothing.
	return info, nil
}

// suseRebootSignal maps `zypper needs-rebooting` to a reboot verdict by its EXIT
// CODE — robust to C-locale wording shifts the old stdout-text match couldn't see:
//
//	0   → no reboot needed
//	102 → ZYPPER_EXIT_INF_REBOOT_NEEDED (a kernel/core-lib update awaits a reboot)
//	7   → ZYPP_LOCKED (the one global zypp lock is held)
//
// The lock matters because `dsd health` runs the package collector's `zypper verify`
// concurrently under root; it holds the lock, so needs-rebooting fails fast with
// EMPTY stdout (exit 7). The previous code keyed on stdout text → read empty → the
// whole Kernel row was silently DROPPED under root only (BUG-088, the lock-race
// sibling of the #480 integrity false-OK). Retry the lock like the package collector
// does; if it stays locked for the whole budget, report unverified (surfaced as INFO
// "couldn't determine") rather than dropping the row or implying "Kernel OK".
//
// Returns ok=false for a non-lock zypper error so the caller falls through to other
// distro signals instead of asserting an unverified SUSE row on a misread.
func suseRebootSignal(ctx context.Context) (ok, rebootNeeded, unverified bool) {
	for attempt := 0; attempt < 5; attempt++ {
		out, err := runCmdCombined(ctx, "zypper", "needs-rebooting")
		var ce *cmdError
		isExit := errors.As(err, &ce)
		switch {
		case err == nil: // exit 0
			return true, false, false
		case isExit && ce.code == 102:
			return true, true, false
		}
		locked := (isExit && ce.code == 7) || zypperLocked(out)
		if !locked {
			return false, false, false // non-lock error — let the caller fall through
		}
		if !sleepCtx(ctx, 800*time.Millisecond) {
			break // ctx cancelled — don't spin
		}
	}
	return true, false, true // locked the whole budget — honest "couldn't measure"
}

// ── Ksplice (Oracle live patching) ───────────────────────────────────────────

type KspliceCollector struct{ cc platform.ContainerContext }

func NewKspliceCollector(cc platform.ContainerContext) *KspliceCollector {
	return &KspliceCollector{cc: cc}
}
func (c *KspliceCollector) Name() string           { return "Ksplice" }
func (c *KspliceCollector) Timeout() time.Duration { return 6 * time.Second }

func KspliceAvailable() bool {
	return hasCmd("uptrack-uname") || hasCmd("uptrack-upgrade") || fileExists("/var/lib/ksplice")
}

func (c *KspliceCollector) Collect(ctx context.Context) (interface{}, error) {
	if maintenanceSkip(KspliceAvailable(), c.cc.InContainer) {
		return &models.KspliceInfo{}, nil
	}
	info := &models.KspliceInfo{Available: true}
	if b, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		info.RunningKernel = strings.TrimSpace(string(b))
	}
	if out, err := runCmd(ctx, "uptrack-uname", "-r"); err == nil {
		info.EffectiveKernel = strings.TrimSpace(out)
		info.Patched = info.EffectiveKernel != "" && info.EffectiveKernel != info.RunningKernel
	}
	// Dry-run upgrade lists pending live patches. "Nothing to be done." => up to date.
	out, err := runCmdOutput(ctx, "uptrack-upgrade", "-n")
	if err != nil && out == "" {
		info.CheckUnverified = true
		return info, nil
	}
	info.PendingUpdates = countKsplicePending(out)
	return info, nil
}

// countKsplicePending parses `uptrack-upgrade -n` output. Up-to-date prints
// "Nothing to be done." / "is already up to date"; otherwise each pending patch is
// an "Installing ..." line.
func countKsplicePending(out string) int {
	low := strings.ToLower(out)
	if strings.Contains(low, "nothing to be done") || strings.Contains(low, "already up to date") {
		return 0
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Installing ") {
			n++
		}
	}
	return n
}

// ── Service restart (stale deleted libs) ─────────────────────────────────────

type ServiceRestartCollector struct{}

func NewServiceRestartCollector() *ServiceRestartCollector { return &ServiceRestartCollector{} }
func (c *ServiceRestartCollector) Name() string            { return "ServiceRestart" }
func (c *ServiceRestartCollector) Timeout() time.Duration  { return 8 * time.Second }

// ServiceRestartAvailable: the /proc/<pid>/maps "(deleted)" scan is package-manager
// agnostic, so gate on any mainstream Linux (rpm OR dpkg) — Ubuntu/Debian have the
// exact same "patched but not restarted" problem after an apt glibc/openssl update.
func ServiceRestartAvailable() bool { return hasCmd("rpm") || hasCmd("dpkg") }

// mapsHasDeletedLib reports whether a /proc/<pid>/maps body maps a shared library
// whose on-disk file was replaced (the kernel marks the stale mapping "(deleted)").
// Restricted to .so paths under a system lib dir to avoid flagging deleted temp
// files / memfd mappings.
func mapsHasDeletedLib(maps string) bool {
	for _, line := range strings.Split(maps, "\n") {
		if !strings.HasSuffix(strings.TrimRight(line, " "), "(deleted)") {
			continue
		}
		if !strings.Contains(line, ".so") {
			continue
		}
		if strings.Contains(line, "/lib") || strings.Contains(line, "/usr/") {
			return true
		}
	}
	return false
}

func (c *ServiceRestartCollector) Collect(_ context.Context) (interface{}, error) {
	if !ServiceRestartAvailable() {
		return &models.ServiceRestartInfo{}, nil
	}
	info := &models.ServiceRestartInfo{Available: true, ToolUsed: "proc-maps"}
	mapsFiles, _ := glob("/proc/[0-9]*/maps")
	nonRoot := os.Geteuid() != 0
	seen := map[string]bool{}
	deniedOthers := false
	for _, mapPath := range mapsFiles {
		b, err := readFile(mapPath)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "permission") {
				deniedOthers = true
			}
			continue
		}
		if !mapsHasDeletedLib(string(b)) {
			continue
		}
		pid := strings.TrimSuffix(strings.TrimPrefix(mapPath, "/proc/"), "/maps")
		name := pid
		if cb, e := readFile("/proc/" + pid + "/comm"); e == nil {
			name = strings.TrimSpace(string(cb))
		}
		if !seen[name] {
			seen[name] = true
			info.StaleCount++
			if len(info.StaleNames) < 20 {
				info.StaleNames = append(info.StaleNames, name)
			}
		}
	}
	// Non-root can't read other users' maps → the scan is partial, not a clean OK.
	info.NeedsRoot = nonRoot && deniedOthers
	return info, nil
}

// ── Kernel retention / /boot space ───────────────────────────────────────────

type KernelRetentionCollector struct{ cc platform.ContainerContext }

func NewKernelRetentionCollector(cc platform.ContainerContext) *KernelRetentionCollector {
	return &KernelRetentionCollector{cc: cc}
}
func (c *KernelRetentionCollector) Name() string           { return "KernelRetention" }
func (c *KernelRetentionCollector) Timeout() time.Duration { return 5 * time.Second }

// KernelRetentionAvailable gates on a recognized kernel package manager.
func KernelRetentionAvailable() bool { return hasCmd("rpm") || hasCmd("dpkg") }

func (c *KernelRetentionCollector) Collect(_ context.Context) (interface{}, error) {
	if maintenanceSkip(KernelRetentionAvailable(), c.cc.InContainer) {
		return &models.KernelRetentionInfo{}, nil
	}
	info := &models.KernelRetentionInfo{}

	// Count kernel images occupying /boot. The bare `vmlinuz`/`initrd` symlinks have no
	// version suffix and are excluded — this counts the per-version images, the
	// cross-distro proxy for what actually fills /boot regardless of package naming.
	imgs, _ := glob("/boot/vmlinuz-*")
	info.InstalledKernels = len(imgs)

	switch {
	case hasCmd("zypper"):
		info.PackageManager = "zypper"
		if b, err := readFile("/etc/zypp/zypp.conf"); err == nil {
			info.RetentionPolicy, info.Unbounded = parseMultiversionKernels(string(b))
		}
	case hasCmd("dnf") || hasCmd("yum"):
		info.PackageManager = "dnf"
		if b, err := readFile("/etc/dnf/dnf.conf"); err == nil {
			info.RetentionPolicy, info.Unbounded = parseInstallonlyLimit(string(b))
		}
	case hasCmd("dpkg"):
		info.PackageManager = "apt"
		// apt has no built-in retention limit; old kernels are cleared by `apt autoremove`.
		// Don't claim a policy is unbounded — just report the boot-space risk below.
	}

	// /boot space. statFs follows the mount, so a SEPARATE small /boot reports a small
	// BootTotalGB (the at-risk case), while a /boot on a roomy root reports the root
	// size — large, so the heuristic never trips on it.
	if st, err := statFs("/boot"); err == nil && st.Blocks > 0 {
		info.BootTotalGB = float64(st.Blocks) * float64(st.Bsize) / (1 << 30)
		info.BootUsedPct = (1 - float64(st.Bavail)/float64(st.Blocks)) * 100
	}

	info.Available = info.InstalledKernels > 0 && info.PackageManager != ""
	return info, nil
}

// parseMultiversionKernels extracts zypper's `multiversion.kernels` value. "all" (alone
// or in the comma list) means libzypp keeps EVERY installed kernel — unbounded growth.
// An absent/empty setting is NOT unbounded: without multiversion, zypper removes the
// superseded kernel on update (keeps one).
func parseMultiversionKernels(conf string) (policy string, unbounded bool) {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "multiversion.kernels") {
			continue
		}
		_, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		policy = strings.TrimSpace(val)
		for _, tok := range strings.Split(policy, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "all") {
				unbounded = true
			}
		}
		return policy, unbounded
	}
	return "", false
}

// parseInstallonlyLimit extracts dnf's installonly_limit (kernels to keep). 0 means
// "keep all" — unbounded growth. The dnf default is 3 when unset.
func parseInstallonlyLimit(conf string) (policy string, unbounded bool) {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "installonly_limit") {
			continue
		}
		_, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v := strings.TrimSpace(val)
		policy = "installonly_limit=" + v
		if n, err := strconv.Atoi(v); err == nil && n == 0 {
			unbounded = true
		}
		return policy, unbounded
	}
	return "", false
}

// ── Kernel live patching (klp / kpatch / generic livepatch sysfs) ────────────

type LivePatchCollector struct{ cc platform.ContainerContext }

func NewLivePatchCollector(cc platform.ContainerContext) *LivePatchCollector {
	return &LivePatchCollector{cc: cc}
}
func (c *LivePatchCollector) Name() string           { return "LivePatch" }
func (c *LivePatchCollector) Timeout() time.Duration { return 3 * time.Second }

// LivePatchAvailable is true when at least one kernel livepatch is loaded
// (/sys/kernel/livepatch/<name>/). A kernel can support livepatch with none loaded —
// there's then nothing to verify, so the check stays silent.
func LivePatchAvailable() bool {
	dirs, _ := glob("/sys/kernel/livepatch/*")
	return len(dirs) > 0
}

func (c *LivePatchCollector) Collect(_ context.Context) (interface{}, error) {
	if maintenanceSkip(LivePatchAvailable(), c.cc.InContainer) {
		return &models.LivePatchInfo{}, nil
	}
	info := &models.LivePatchInfo{}
	dirs, _ := glob("/sys/kernel/livepatch/*")
	for _, p := range dirs {
		info.PatchesLoaded++
		name := p[strings.LastIndex(p, "/")+1:]
		// enabled=1 means the patch is active; 0 means loaded-but-not-applied (the kernel
		// runs the OLD code). transition=1 means tasks are still migrating to the patch.
		if en, err := readFile(p + "/enabled"); err == nil && strings.TrimSpace(string(en)) == "1" {
			info.PatchesEnabled++
		} else {
			info.DisabledPatches = append(info.DisabledPatches, name)
		}
		if tr, err := readFile(p + "/transition"); err == nil && strings.TrimSpace(string(tr)) == "1" {
			info.TransitioningPatches = append(info.TransitioningPatches, name)
		}
	}
	info.Available = info.PatchesLoaded > 0
	switch {
	case hasCmd("klp"):
		info.Tool = "klp"
	case hasCmd("kpatch"):
		info.Tool = "kpatch"
	}
	return info, nil
}
