//go:build linux

package collectors

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RHEL/Oracle-family maintenance & patch-effectiveness collectors. Each is gated
// (silent on hosts without the subsystem) and reads every input through the
// Source-routed helpers (readFile/runCmd*/glob/hasCmd) so capture → replay is
// faithful. See internal/models/maintenance.go for the recorded fields.

// ── Kdump ────────────────────────────────────────────────────────────────────

type KdumpCollector struct{}

func NewKdumpCollector() *KdumpCollector         { return &KdumpCollector{} }
func (c *KdumpCollector) Name() string           { return "Kdump" }
func (c *KdumpCollector) Timeout() time.Duration { return 3 * time.Second }

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
	if !KdumpAvailable() {
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

type KernelPatchCollector struct{}

func NewKernelPatchCollector() *KernelPatchCollector   { return &KernelPatchCollector{} }
func (c *KernelPatchCollector) Name() string           { return "Kernel" }
func (c *KernelPatchCollector) Timeout() time.Duration { return 5 * time.Second }

func KernelPatchAvailable() bool { return hasCmd("rpm") }

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
	if !KernelPatchAvailable() {
		return &models.KernelPatchInfo{}, nil
	}
	info := &models.KernelPatchInfo{Available: true}
	if b, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Running = strings.TrimSpace(string(b))
	}
	// --last orders by install time (newest first); rpm exits non-zero when ANY
	// queried package is absent, so use runCmdOutput to keep the installed lines.
	out, _ := runCmdOutput(ctx, "rpm", "-q", "--last", "kernel-uek", "kernel-core", "kernel")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.Contains(line, "not installed") || strings.HasPrefix(line, "package ") {
			continue
		}
		info.LatestInstalled = kernelNVRAToUname(fields[0])
		break
	}
	if info.Running != "" && info.LatestInstalled != "" && info.Running != info.LatestInstalled {
		info.RebootNeeded = true
	}
	return info, nil
}

// ── Ksplice (Oracle live patching) ───────────────────────────────────────────

type KspliceCollector struct{}

func NewKspliceCollector() *KspliceCollector       { return &KspliceCollector{} }
func (c *KspliceCollector) Name() string           { return "Ksplice" }
func (c *KspliceCollector) Timeout() time.Duration { return 6 * time.Second }

func KspliceAvailable() bool {
	return hasCmd("uptrack-uname") || hasCmd("uptrack-upgrade") || fileExists("/var/lib/ksplice")
}

func (c *KspliceCollector) Collect(ctx context.Context) (interface{}, error) {
	if !KspliceAvailable() {
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

func ServiceRestartAvailable() bool { return hasCmd("rpm") }

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
