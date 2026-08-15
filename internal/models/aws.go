package models

// AWSInfo reports guest-side health for a Linux EC2 instance — the AWS-specific
// signals a guest can see about itself that the generic collectors miss. Populated
// only when running on EC2 (gate: DMI "Amazon EC2"); nil/zero everywhere else so it
// adds no noise off AWS.
//
// Scope is strictly guest-side, no AWS API credentials: instance metadata (IMDS),
// kernel/driver telemetry (ENA ethtool stats, EBS NVMe vendor log page), and local
// daemon state. The hard-to-see failures it targets are the *silent throttles* —
// network allowance and EBS performance limits that drop packets / cap IOPS with no
// error anywhere else, so the instance looks healthy while AWS quietly throttles it.
type AWSInfo struct {
	IsEC2        bool   `json:"is_ec2"`
	InstanceType string `json:"instance_type,omitempty"` // from IMDS, e.g. "t4g.small"

	// --- ENA network allowance-exceeded counters (per ENA interface) ---
	// The Nitro network stack enforces per-instance bandwidth / packets-per-second /
	// connection-tracking / link-local allowances; exceeding one means packets are
	// silently shaped or dropped, visible ONLY in these ethtool counters.
	ENA []ENAStats `json:"ena,omitempty"`

	// --- EBS volume performance throttle (per EBS NVMe device) ---
	EBS              []EBSStats `json:"ebs,omitempty"`
	EBSReadAttempted bool       `json:"ebs_read_attempted"`        // an EBS NVMe device was found and we tried to read its stats
	EBSNeedsRoot     bool       `json:"ebs_needs_root,omitempty"`  // the vendor log-page read failed and we are non-root (couldn't measure)
	EBSReadFailed    bool       `json:"ebs_read_failed,omitempty"` // read failed as root, or returned a value we won't trust (no magic)
	// EBSDeltaReadFailed is true when the SECOND (delta) sample's read
	// failed after a successful first read — distinct from EBSReadFailed
	// (the first read). internal-collectors-02-01: without this, a failed
	// second read silently produced a zero-value snapshot, and subSat's
	// saturating subtraction turned that into a false zero "not currently
	// throttled" delta instead of an honest "couldn't verify".
	EBSDeltaReadFailed bool `json:"ebs_delta_read_failed,omitempty"`

	// A second snapshot was taken ~1s after the first (only when a first-pass
	// counter was non-zero, and never under replay) so a live, *active* throttle can
	// be told apart from a stale historical one. False = single snapshot only.
	Sampled bool `json:"sampled"`

	// --- IMDS security posture ---
	IMDSChecked   bool `json:"imds_checked"`
	IMDSv1Enabled bool `json:"imds_v1_enabled,omitempty"` // a token-less IMDS request succeeded (HttpTokens=optional — SSRF-reachable)

	// --- Amazon Time Sync Service ---
	TimeSyncChecked    bool `json:"time_sync_checked"`
	UsesAmazonTimeSync bool `json:"uses_amazon_time_sync,omitempty"` // chrony/timesyncd configured against 169.254.169.123 (or the PHC refclock)

	// --- SSM agent ---
	SSMInstalled bool `json:"ssm_installed"`
	SSMRunning   bool `json:"ssm_running"`

	// --- spot rebalance recommendation (distinct from the spot-termination notice
	// CloudMeta handles — this fires earlier, at elevated interruption risk) ---
	RebalanceChecked     bool `json:"rebalance_checked"`
	RebalanceRecommended bool `json:"rebalance_recommended,omitempty"`

	// --- Nitro Enclaves (recognition/context) ---
	// /dev/nitro_enclaves exists when the instance was launched with --enclave-options
	// and the driver is loaded; the allocator service reserves the enclave's CPUs/memory.
	// Informational, not a fault — surfaces that an isolated-compute facility is present.
	NitroEnclavesPresent       bool `json:"nitro_enclaves_present"`
	NitroEnclavesAllocatorRuns bool `json:"nitro_enclaves_allocator_running,omitempty"`

	// --- ENA Express / SRD (recognition/context) ---
	// ENA Express moves eligible TCP/UDP traffic onto the SRD transport (lower tail
	// latency, higher single-flow bandwidth). When enabled, the ENA driver exposes
	// ena_srd_* counters in `ethtool -S`. ENAExpressChecked is false when no ENA
	// interface was readable, so an unread NIC never reads as "no ENA Express".
	ENAExpressChecked bool `json:"ena_express_checked"`
	ENAExpressActive  bool `json:"ena_express_active,omitempty"` // SRD counters present and carrying packets
}

// ENAStats holds the allowance-exceeded counters for one ENA interface. Total is
// the cumulative count since the driver loaded; Active is the increase observed
// during the ~1s sample window (only populated when Sampled). Both are keyed by a
// canonical short allowance name: "bw_in", "bw_out", "pps", "conntrack", "linklocal".
type ENAStats struct {
	Iface  string            `json:"iface"`
	Total  map[string]uint64 `json:"total"`
	Active map[string]uint64 `json:"active,omitempty"`
}

// EBSStats holds the EBS performance-exceeded counters for one EBS NVMe device,
// parsed from the Amazon vendor log page (0xD0). Each "Exceeded" field is the
// cumulative microseconds the corresponding limit was exceeded since attach; the
// "Active" siblings are the increase during the ~1s sample window (Sampled). The
// volume-* counters are the volume's own IOPS/throughput limit; the instance-*
// counters are the aggregate EBS limit across all volumes on the instance.
type EBSStats struct {
	Device string `json:"device"`

	VolumeIOPSExceededUs   uint64 `json:"volume_iops_exceeded_us"`
	VolumeTPExceededUs     uint64 `json:"volume_tp_exceeded_us"`
	InstanceIOPSExceededUs uint64 `json:"instance_iops_exceeded_us"`
	InstanceTPExceededUs   uint64 `json:"instance_tp_exceeded_us"`

	ActiveVolumeIOPSUs   uint64 `json:"active_volume_iops_us,omitempty"`
	ActiveVolumeTPUs     uint64 `json:"active_volume_tp_us,omitempty"`
	ActiveInstanceIOPSUs uint64 `json:"active_instance_iops_us,omitempty"`
	ActiveInstanceTPUs   uint64 `json:"active_instance_tp_us,omitempty"`
}
