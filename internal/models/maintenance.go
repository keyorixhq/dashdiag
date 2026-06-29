package models

// RHEL/Oracle-family maintenance & patch-effectiveness checks. Each struct backs
// one gated health collector (silent when the subsystem is absent). All fields are
// recorded by the collector (not derived live in the analysis layer) so capture →
// replay reproduces the verdict faithfully.

// KdumpInfo captures whether crash-dump capture is actually armed — not just
// whether kdump.service is "enabled". The silent-failure case is a service that is
// enabled but has no crash kernel loaded (no memory reserved via crashkernel=), so
// a real panic produces NO dump.
type KdumpInfo struct {
	Available     bool   `json:"available"` // kdump.service is present on the host
	ServiceState  string `json:"service_state,omitempty"`
	ServiceActive bool   `json:"service_active"`
	Enabled       bool   `json:"enabled"`
	CrashLoaded   bool   `json:"crash_loaded"`          // /sys/kernel/kexec_crash_loaded == 1
	ReservedBytes int64  `json:"reserved_bytes"`        // /sys/kernel/kexec_crash_size
	Crashkernel   string `json:"crashkernel,omitempty"` // crashkernel= token from /proc/cmdline ("" = absent)
}

// TunedInfo captures the active vs. recommended tuned profile. tuned ships on
// RHEL/Oracle/Fedora; the active profile materially affects performance, and a VM
// left on "balanced" instead of tuned's own "virtual-guest" recommendation is a
// common, silent miss (found live on Oracle Linux 9).
type TunedInfo struct {
	Available   bool   `json:"available"` // tuned is installed
	Active      bool   `json:"active"`    // tuned.service is running
	Profile     string `json:"profile,omitempty"`
	Recommended string `json:"recommended,omitempty"` // tuned-adm recommend (tuned's own verdict for this host)
}

// KernelPatchInfo flags "you patched but you're still running the old kernel": a
// kernel package newer than the running one is installed, but the box hasn't been
// rebooted, so it's still running the pre-update (possibly vulnerable) kernel.
type KernelPatchInfo struct {
	Available       bool   `json:"available"` // rpm-based (RHEL/Oracle family)
	Running         string `json:"running,omitempty"`
	LatestInstalled string `json:"latest_installed,omitempty"`
	RebootNeeded    bool   `json:"reboot_needed"`
}

// KspliceInfo captures Oracle Ksplice (zero-downtime kernel patching) state:
// whether live patches are pending-but-unapplied (the running kernel is exposed
// despite a patch being available). Silent on hosts without Ksplice installed.
type KspliceInfo struct {
	Available       bool   `json:"available"` // ksplice/uptrack tooling installed
	EffectiveKernel string `json:"effective_kernel,omitempty"`
	RunningKernel   string `json:"running_kernel,omitempty"`
	PendingUpdates  int    `json:"pending_updates"`
	Patched         bool   `json:"patched"` // live patches are currently applied
	CheckUnverified bool   `json:"check_unverified,omitempty"`
}

// ServiceRestartInfo flags processes still mapping shared libraries that were
// replaced on disk by an update (the file shows "(deleted)" in /proc/<pid>/maps).
// Until restarted they run the OLD code — the real reason "patched but not
// protected" after a glibc/openssl update.
type ServiceRestartInfo struct {
	Available  bool     `json:"available"`
	StaleCount int      `json:"stale_count"`
	StaleNames []string `json:"stale_names,omitempty"`
	NeedsRoot  bool     `json:"needs_root,omitempty"` // non-root could only scan own processes
	ToolUsed   string   `json:"tool_used,omitempty"`  // "proc-maps" or "needs-restarting"
}
