package models

// ContainerGuestInfo reports guest-side health for a workload running inside a
// container (Docker/Podman/LXC/containerd or a Kubernetes pod). A container is a
// tenant too — it runs inside an isolation boundary someone else manages — so it
// gets the same guest-vs-host framing as a VM: what the deployer can fix in the
// container spec vs. resource limits being enforced against it.
//
// Populated only when running inside a container (gate: ContainerGuestAvailable);
// nil/zero elsewhere.
type ContainerGuestInfo struct {
	InContainer bool   `json:"in_container"`
	Runtime     string `json:"runtime,omitempty"` // docker / podman / kubernetes / lxc / container
	CgroupV2    bool   `json:"cgroup_v2"`
	// CgroupV1Measured is true when, on a cgroup v1 host, the throttle/OOM counters
	// (cpu.stat / memory.oom_control under the per-controller dirs) were actually
	// readable. When false on a v1 container they're unverified — the verdict must say
	// so, not imply "no throttling or OOM-kills".
	CgroupV1Measured bool `json:"cgroup_v1_measured,omitempty"`
	// CgroupV2Measured is the v2 analog of CgroupV1Measured: true when at least one
	// of memory.current/memory.events/cpu.stat under the container's OWN cgroup dir
	// (resolved via /proc/self/cgroup) was actually readable. False means a TOCTOU
	// race, a hardened LSM profile, a minimal cgroupfs mount, or a --cgroupns=host
	// self-path resolution failure left every v2 counter unreadable — 0 must not
	// read as "healthy" in that case (internal-collectors-05-02).
	CgroupV2Measured bool `json:"cgroup_v2_measured,omitempty"`

	// Memory limit + usage (cgroup). LimitBytes 0 = no limit set (memory.max == max).
	MemLimitBytes   int64 `json:"mem_limit_bytes"`
	MemCurrentBytes int64 `json:"mem_current_bytes"`
	OOMKills        int64 `json:"oom_kills"` // memory.events oom_kill — host killed a process for exceeding the limit

	// CPU quota (cgroup). QuotaCores 0 = no limit (cpu.max == max). ThrottledPct is
	// the share of scheduler periods the workload was throttled at its quota — the
	// container analog of CPU steal, and the usual hidden cause of a "slow" container.
	CPUQuotaCores float64 `json:"cpu_quota_cores"`
	ThrottledPct  float64 `json:"throttled_pct"`

	RunAsRoot      bool `json:"run_as_root"`     // effective uid 0 inside the container
	WritableRootfs bool `json:"writable_rootfs"` // / mounted rw (vs an immutable read-only root)

	// Best-effort view of the layer BENEATH the container: from inside a container
	// the host's DMI is often (not always) readable, so we can say "…and you're on a
	// QEMU/VMware VM". Empty when masked (hardened containers) or bare metal — we
	// degrade honestly rather than guess.
	UnderlyingVM string `json:"underlying_vm,omitempty"` // "QEMU/KVM" | "VMware" | ""
}
