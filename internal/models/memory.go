package models

type MemoryInfo struct {
	TotalGB       float64 `json:"total_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedPct       float64 `json:"used_pct"`
	SlabMB        float64 `json:"slab_mb"`
	CommitLimitMB float64 `json:"commit_limit_mb"`
	CommittedAsMB float64 `json:"committed_as_mb"`
	OverCommitted bool    `json:"over_committed"`
	// OvercommitMode is vm.overcommit_memory: 0 = heuristic (default), 1 = always
	// overcommit, 2 = strict accounting. CommitLimit is only ENFORCED in mode 2,
	// so Committed_AS exceeding it is an OOM risk only there; in modes 0/1 it is
	// normal and must not be flagged.
	OvercommitMode int `json:"overcommit_mode"`
	// EDAC / ECC memory error counts (physical hosts only; zero on VMs/consumer
	// hardware where EDAC is unavailable). Surfaced in default `dsd health` so a
	// failing DIMM is caught without needing the heavier `dsd hardware`.
	EDACAvailable     bool  `json:"edac_available,omitempty"`
	CorrectedErrors   int64 `json:"corrected_ecc_errors,omitempty"`
	UncorrectedErrors int64 `json:"uncorrected_ecc_errors,omitempty"`
	// EDACCountersUnreadable is true when EDACAvailable but at least one
	// controller's ce_count/ue_count could not be read/parsed — Corrected/
	// UncorrectedErrors are then an incomplete sum, not proof of zero errors.
	EDACCountersUnreadable bool `json:"edac_counters_unreadable,omitempty"`

	// Memory hot-plug onlining. A hypervisor that hot-adds RAM to a running guest
	// (VMware hot-add, KVM virtio-mem, Hyper-V Dynamic Memory, cloud vertical
	// scaling) adds memory blocks the guest must ONLINE to use. When auto-onlining
	// is disabled and the blocks aren't onlined, the guest sees the RAM in sysfs
	// but never uses it — the "I gave it 16 GB but it shows 8" class of bug. Linux
	// only (sysfs /sys/devices/system/memory); zero on non-Linux / no-hotplug.
	MemHotplugChecked   bool  `json:"mem_hotplug_checked,omitempty"`   // memory-hotplug sysfs present
	OfflineMemoryBlocks int   `json:"offline_memory_blocks,omitempty"` // count of offline memory blocks
	OfflineMemoryMB     int64 `json:"offline_memory_mb,omitempty"`     // their total size (0 if block size unknown)
	AutoOnlineBlocks    bool  `json:"auto_online_blocks,omitempty"`    // auto_online_blocks == "online"

	// CgroupMemMeasured is true when, inside a memory-limited container, UsedPct/
	// FreeGB were recomputed against the container's OWN cgroup usage counter
	// (memory.current / memory.usage_in_bytes) rather than left derived from
	// host-wide /proc/meminfo. When false in a memory-limited container, the
	// heuristic must not score UsedPct against TotalGB — they'd be measuring two
	// different things (host-wide usage vs. the container's ceiling).
	CgroupMemMeasured bool `json:"cgroup_mem_measured,omitempty"`

	// MeminfoUnreadable is true on Linux when /proc/meminfo could not be read or
	// parsed through the active Source (e.g. a replay bundle that never recorded
	// it) — TotalGB/FreeGB/UsedPct are all zero-valued and must not be scored,
	// since falling back to a live read would silently report the replaying
	// machine's own memory instead of the captured host's.
	MeminfoUnreadable bool `json:"meminfo_unreadable,omitempty"`

	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}
