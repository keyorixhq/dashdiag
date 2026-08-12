package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The "unverified signal" surface: struct-field names (usually bool) that encode
// "we could NOT measure this" — the input to the false-OK bug class (a green OK
// rendered when nothing was actually checked; see cmd/falseok_verdict_test.go and
// the recurring fleet-review fixes). This test is a COMPLETENESS TRIPWIRE, not a
// correctness proof: it fails when a NEW such field appears in internal/models
// without a line in guardedUnverifiedSignals, forcing the author to consciously
// decide how it is guarded (a standalone-renderer case in
// cmd/falseok_verdict_test.go, or a note that it only feeds a health heuristic
// that folds to INFO/WARN). It does NOT prove the guard is correct — that is the
// per-case tests' job. Why it exists: #575/#576 regressed because a false-OK fix
// landed in the heuristic but the matching field's RENDERER path was silently left
// unguarded, and nothing flagged the omission.
var unverifiedSignalRe = regexp.MustCompile(`(Verified|Unverified|Unreadable|Queried|Reachable|ScanFailed|ReadFailed|NeedsRoot|NeedRoot|ScanOK|Checked|Measured)$`)

// guardedUnverifiedSignals maps "TypeName.FieldName" → how that signal is
// accounted for (the test/heuristic that prevents a green OK when it is set). Add a
// line when you add such a field. A note is a factual pointer, not a correctness
// certificate — the linked test is.
var guardedUnverifiedSignals = map[string]string{
	// Standalone renderers that can show an all-clear — guarded case-by-case in
	// cmd/falseok_verdict_test.go (the renderer must not print its green line when
	// the signal is unset).
	"K8sInfo.APIReachable":                  "cmd/falseok_verdict_test.go (k8s renderer) + analysis/pve_apireachable_test.go",
	"CronInfo.FailureScanOK":                "cmd/falseok_verdict_test.go (cron) + analysis/cron_logs_unverified_test.go",
	"LogsInfo.ErrorCountUnverified":         "cmd/falseok_verdict_test.go (logs) + analysis/cron_logs_unverified_test.go",
	"LogsInfo.NeedsRoot":                    "cmd/falseok_verdict_test.go (logs non-root)",
	"LogsInfo.ErrorScanFailed":              "analysis/cron_logs_unverified_test.go (scan-failed → not 'none')",
	"ServicesDeepInfo.FailedUnitsQueried":   "cmd/falseok_verdict_test.go (services deep)",
	"ServicesDeepInfo.SSHDStatusUnverified": "cmd/falseok_verdict_test.go TestServicesDeepSSHDUnverifiedNotNone (a suppressed sshd@ instance's unreadable exit status must not render the same green 'none' a genuinely-clean host gets)",
	"SystemdInfo.SSHDStatusUnverified":      "analysis/heuristics_round2_test.go TestCheckSystemd_SSHDStatusUnverified (INFO, not a silent fold into 'no non-benign sshd@ failures')",
	"CVEAllResult.ScanFailed":               "cmd/falseok_verdict_test.go (cve) + collectors/cve_stale_metadata_test.go",

	// dsd security — renderer shares health's verdict via the heuristic.
	"SecurityInfo.NeedsRoot":              "analysis/heuristics_security_full_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.PortsNeedRoot":          "analysis/heuristics_security_full_test.go (ports → 'run as root')",
	"SecurityInfo.ShadowUnreadable":       "analysis/mac_shadow_unverified_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.SudoersUnreadable":      "cis/rules_test.go (5.3.4 sudo-nopasswd rule: SudoersUnreadable → CISSkipped, never false-OK)",
	"SecurityInfo.FailedLoginsUnreadable": "analysis/failedlogins_pam_unverified_test.go",
	"SecurityInfo.PAMFailuresUnreadable":  "analysis/failedlogins_pam_unverified_test.go",
	"SecurityInfo.SSHConfigUnreadable":    "cis/ssh_unverified_test.go + cmd/security_falseok_test.go",
	"SecurityInfo.FirewallUnreadable":     "collectors/firewall_barename_linux_test.go (nft unreadable → INFO)",
	"SecurityInfo.AuditRulesUnreadable":   "cis/rules_test.go TestEvaluate_AuditUnreadableNotFailed (4.1.1 non-root → Skipped, not Fail) + collectors/medium_low_linux_test.go TestAuditRulesFromOutput",
	"AuditInfo.AuditLogSizeUnreadable":    "analysis/heuristics_round6_test.go TestCheckAuditd (non-root → INFO, not a silent 0-size OK)",

	// Storage — heuristic folds an unreadable read to INFO/WARN, never OK.
	"CephInfo.NeedsRoot":                "analysis/heuristics_round3_test.go (configured+non-root → INFO, not false 'unreachable' CRIT)",
	"DiskInfo.ZFSListReadFailed":        "analysis/zfs_btrfs_unverified_test.go",
	"ZFSInfo.ListReadFailed":            "analysis/zfs_btrfs_unverified_test.go",
	"ZFSPool.StatusReadFailed":          "analysis/zfs_btrfs_unverified_test.go + heuristics_security_storage_test.go",
	"BtrfsVolume.DevReadUnverified":     "collectors/btrfs_linux_test.go + analysis/heuristics_round2_test.go (BUG-070)",
	"LVMInfo.LVReadFailed":              "analysis/san_unverified_test.go",
	"LVMInfo.VGReadFailed":              "analysis/san_unverified_test.go",
	"LVMInfo.PVReadFailed":              "analysis/san_unverified_test.go",
	"LVMInfo.RaidReadFailed":            "analysis/heuristics_round7_test.go",
	"InfiniBandInfo.ReadFailed":         "analysis/heuristics_round5_test.go TestCheckInfiniBand_ReadFailedNotSilentlyAbsent (/sys/class/infiniband unreadable → INFO, not folded into the same silence as no IB hardware)",
	"LVMInfo.PresenceReadFailed":        "analysis/san_unverified_test.go TestLVMPresenceCheckFailedNotSilentlyAbsent + cmd/disk_report_test.go TestPrintDiskLVM + cmd/disk_issues_test.go TestDiskHasUnverifiedReads",
	"DRBDInfo.Unverified":               "analysis/san_unverified_test.go (DRBD 9 non-root → INFO 'needs root', not silent omission)",
	"ISCSIInfo.NeedsRoot":               "analysis/san_unverified_test.go (active sessions unreadable non-root → INFO, not silent)",
	"FilesystemInfo.BusyCheckNeedsRoot": "analysis/heuristics_disk_busy_test.go (TestCheckDisk_BusyProcessHints_NeedsRoot: non-root busy-process scan → explicit caveat hint, not a silent 'no processes found')",

	// PVE — API/section verified flags; folded by the PVE heuristic.
	"PVEInfo.APIReachable":     "analysis/pve_apireachable_test.go",
	"PVEInfo.NeedsRoot":        "analysis/pve_apireachable_test.go + pve_unverified_test.go",
	"PVEInfo.StoragesVerified": "analysis/pve_unverified_test.go",
	"PVEInfo.TasksVerified":    "analysis/pve_unverified_test.go",
	"PVEInfo.BackupVerified":   "analysis/pve_unverified_test.go + heuristics_round5_test.go",
	"PVEInfo.HAVerified":       "analysis/pve_unverified_test.go",

	// Cloud / virt / other — heuristic folds the unmeasured state to INFO/WARN.
	"AWSInfo.EBSNeedsRoot":              "analysis/heuristics_aws_test.go (non-root EBS read → INFO)",
	"AWSInfo.EBSReadFailed":             "analysis/heuristics_aws_test.go (sibling of EBSNeedsRoot)",
	"KVMInfo.VMsUnreadable":             "collectors/kvm_pve_test.go + analysis/heuristics_round4_test.go",
	"GPUDevice.Unreadable":              "analysis (gpu all-zero/unreadable → not OK); see memory gpu-allzero-falseok-deferred",
	"NFSMount.ServerReachable":          "analysis (NFS reachability heuristic, net deep)",
	"CloudInitInfo.StatusUnverified":    "analysis/firmware_cloudinit_unverified_test.go",
	"SUSEConnectInfo.StatusUnverified":  "analysis/heuristics_round7_test.go TestCheckRHELSubscription_StatusUnverified + collectors/suseconnect_collector_test.go (unparseable subscription-manager output → INFO, not silent 'current')",
	"SteamOSInfo.UpdateServerReachable": "analysis/steamos_test.go + heuristics_round9_test.go",
	"ServiceResult.Reachable":           "service-collector heuristic (DEGRADED when unreachable; analysis/heuristics_round9_test.go)",
	"VaultInfo.Reachable":               "analysis/heuristics_vault.go checkVault (!Reachable → WARN, never silent OK)",
	"IPMIInfo.NeedsRoot":                "analysis/heuristics_round9_test.go (non-root BMC read → INFO 're-run as root', not a WARN) + collectors/ipmi_linux_test.go",

	// RHEL/Oracle maintenance — heuristic folds the unmeasured state to INFO, never OK.
	"ServiceRestartInfo.NeedsRoot":    "analysis/heuristics_maintenance_test.go (non-root partial /proc scan → INFO 'partial', not a clean OK)",
	"KspliceInfo.CheckUnverified":     "analysis/heuristics_maintenance_test.go (uptrack status unread → INFO 'could not be read', not OK)",
	"KernelPatchInfo.CheckUnverified": "analysis/heuristics_maintenance_test.go + collectors/maintenance_linux_test.go (BUG-088: SUSE zypp lock held the whole budget → INFO 'could not be determined', never a silent drop or 'Kernel OK')",
	"TransactionalInfo.Unverified": "analysis/heuristics_maintenance_test.go + collectors/maintenance_linux_test.go (found via " +
		"TestAllChecksRegistered's completeness guard: a failed btrfs subvolume get-default read — commonly " +
		"non-root, needs CAP_SYS_ADMIN — left RebootPending's false zero value indistinguishable from a " +
		"genuinely clean host; now → INFO 'could not verify', never a silent 'Transactional: OK')",

	// CIS benchmark — CISSkipped alone conflated "confirmed not applicable"
	// (rsync not installed) with "could not verify" (sshd_config unreadable,
	// non-root) across ~59 of ~132 skip sites in internal/cis/rules.go. Both
	// now carry Unverified; cmd/cis.go's renderers give it a distinct ❓ icon
	// and print the Finding (previously discarded for every skip, genuine or
	// not); the NIS2/BSI rollups (internal/cis/nis2.go, bsi.go) use it to
	// avoid reporting a plain "PASS" on compliance evidence for an
	// article/requirement where some sibling rules were never actually
	// checked.
	"CISResult.Unverified": "cmd/cis_test.go TestCisIcon (❓ vs ⏭️, and Finding is printed for both) + " +
		"internal/cis/rules_test.go (unverifiedr sites) + internal/cis/nis2_test.go/bsi_test.go (rollup Status " +
		"is \"UNVERIFIED\" not \"PASS\" when Pass>0 and a sibling is unverified)",
	"CISReport.Unverified": "internal/cis/rules_test.go TestEvaluate (tally of CISResult.Unverified==true results, " +
		"surfaced in cmd/cis.go's summary line as \"N unverified\" distinct from \"N skipped\")",

	// Insight.Unverified — the analysis-layer signal that a Level downgrade
	// (usually to INFO) reflects "couldn't measure this" rather than a genuine
	// finding. Set via analysis.unverifiedInsight() at every call site gated
	// on one of the model-level signals already registered above (NeedsRoot,
	// *Unreadable, *ReadFailed, etc.) — this registry line covers the shared
	// mechanism; the per-field lines above already point at each site's test.
	// Consumed by internal/baseline: BuildSnapshot copies it onto
	// CheckResult.Unverified, and ComputeDiff forces Improved=false on any
	// diff where either side is Unverified — see baseline_unverified_test.go.
	// Before this, a WARN/CRIT that became unmeasurable on a re-run (e.g.
	// non-root) read as a false "->INFO, Improved=true" recovery in
	// `dsd health --diff`, `dsd baseline diff`, and the MCP dsd_diff tool.
	"Insight.Unverified": "internal/baseline/baseline_unverified_test.go (ComputeDiff never marks an " +
		"unverified transition Improved) + internal/analysis/heuristics_unverified_insight_test.go " +
		"(unverifiedInsight sites carry Unverified through to the Insight)",

	// Hardware RAID controller CLIs are root-only; unread output must never read healthy.
	"HWRaidInfo.NeedsRoot":  "analysis/heuristics_hwraid_test.go (TestCheckHWRaidHonestDegradation: controller CLI root-gated → INFO 're-run as root', never a clean OK or WARN/CRIT over unread state)",
	"HWRaidInfo.ReadFailed": "analysis/heuristics_hwraid_test.go (TestCheckHWRaidHonestDegradation: CLI output unparseable → INFO 'treat as UNVERIFIED, not healthy')",

	// /proc/<pid>/io is gated to the owning user; a non-root sample can miss the
	// true top I/O consumer entirely.
	"HealthDeepInfo.TopIOProcsNeedsRoot": "analysis/correlate_deep_test.go (TestRuleIOWaitCulprit: partial visibility caveat appended to the culprit summary, never a silent unqualified attribution)",

	// /proc/<pid>/status and /proc/<pid>/stat are gated the same way, and glob()
	// silently omits other users' PID directories entirely under hidepid=2 (no
	// error raised) — TopProcs/TopCPUProcs rankings and TotalProcsMB can miss the
	// true top consumer with no signal unless disclosed at render.
	"HealthDeepInfo.TopProcsNeedsRoot":    "cmd/falseok_verdict_test.go (TestPrintTopProcsWithCgroup_NeedsRootCaveat: partial-visibility caveat printed above the top-memory table, never a silent unqualified ranking)",
	"HealthDeepInfo.TopCPUProcsNeedsRoot": "cmd/falseok_verdict_test.go (TestPrintTopCPUProcsWithCgroup_NeedsRootCaveat: partial-visibility caveat printed above the top-CPU table, never a silent unqualified ranking)",

	// K8s OS-layer — "*Checked" companions gate whether the paired field is a real
	// verdict or "not applicable/unknown". Audited 2026-07-08 alongside #742's live
	// root-vs-non-root validation: KubeForwardChecked/KubeServicesChecked/CNIChecked
	// are genuinely privilege-gated (iptables/nft/ipvsadm need CAP_NET_ADMIN;
	// /etc/cni/net.d, /opt/cni/bin are commonly root-only) and now disclosed via
	// OSLayerNeedsRoot; Kubelet/Containerd/FirewalldChecked are "not applicable"
	// gates (no node marker / service not active), correctly silent, no root would
	// help.
	"K8sOSLayer.KubeletChecked":       "analysis/heuristics_virt.go checkK8sNodeDaemons (gated, no verdict on kubectl-only client host — not privilege-related)",
	"K8sOSLayer.ContainerdChecked":    "analysis/heuristics_virt.go checkK8sNodeDaemons (same gate as KubeletChecked)",
	"K8sOSLayer.IPForwardChecked":     "analysis/heuristics_virt.go CheckK8sOSLayer (gated; /proc unreadable → unknown, not disabled)",
	"K8sOSLayer.KubeForwardChecked":   "analysis/heuristics_virt.go CheckK8sOSLayer (gated) + analysis/k8s_oslayer_unverified_test.go (OSLayerNeedsRoot discloses the privilege-gated cause)",
	"K8sOSLayer.KubeServicesChecked":  "analysis/heuristics_virt.go checkK8sServicesChain (gated) + analysis/k8s_oslayer_unverified_test.go (OSLayerNeedsRoot discloses the privilege-gated cause)",
	"K8sOSLayer.CNIChecked":           "analysis/heuristics_virt.go CheckK8sOSLayer (gated) + analysis/k8s_oslayer_unverified_test.go (OSLayerNeedsRoot discloses the privilege-gated cause)",
	"K8sOSLayer.FirewalldChecked":     "analysis/heuristics_virt.go checkK8sNodeDaemons (gated, no verdict when firewalld.service isn't active — not privilege-related)",
	"K8sOSLayer.FlannelCNIUnreadable": "analysis/k8s_oslayer_unverified_test.go (FIXED 2026-07-08: /etc/cni/net.d 0700 on a real pve01 host silently read FlannelInUse=false under non-root; now disclosed)",
	"K8sOSLayer.OSLayerNeedsRoot":     "analysis/k8s_oslayer_unverified_test.go (blanket INFO, mirrors SecurityInfo.NeedsRoot)",

	// Cloud metadata "*Checked" — audited 2026-07-08. All are IMDS/metadata-server
	// probes or local config-file reads, none require root; Checked=false is a
	// legitimate "not applicable/unreachable" state, and every consuming heuristic
	// already gates on it (no false verdict). Left as-is — intentionally silent,
	// see e.g. TestCheckAzure_UnreadStorageProfileNotClaimedOK.
	"AWSInfo.IMDSChecked":            "analysis/heuristics_aws.go (gated; IMDS unreachable is normal off-AWS)",
	"AWSInfo.TimeSyncChecked":        "analysis/heuristics_aws.go (gated; local time-sync config absent is normal)",
	"AWSInfo.RebalanceChecked":       "analysis/heuristics_aws.go (gated; IMDS unreachable is normal)",
	"AWSInfo.ENAExpressChecked":      "analysis/heuristics_aws.go (gated; no ENA interface is normal off-AWS)",
	"AzureInfo.TimeSyncChecked":      "analysis/heuristics_azure.go (gated; local config absent is normal)",
	"AzureInfo.DisksChecked":         "analysis/heuristics_azure_test.go TestCheckAzure_UnreadStorageProfileNotClaimedOK (gated, exactly-one-recognition-line already asserted — intentionally silent, not a false OK)",
	"AzureInfo.NVMeIOTimeoutChecked": "analysis/heuristics_azure.go (gated; NVMe present but param unreadable is rare/normal)",
	"GCPInfo.MaintenanceChecked":     "analysis/heuristics_gcp_test.go (gated, same intentionally-silent pattern as Azure.DisksChecked)",
	"GCPInfo.OSLoginChecked":         "analysis/heuristics_gcp.go (gated; attribute unreadable is normal)",
	"GCPInfo.TimeSyncChecked":        "analysis/heuristics_gcp.go (gated; local config absent is normal)",
	"OCIInfo.IMDSChecked":            "analysis/heuristics_oci.go (gated; IMDS unreachable is normal off-OCI)",
	"OCIInfo.AgentChecked":           "analysis/heuristics_oci.go (gated; false on non-systemd hosts, rare)",
	"OCIInfo.TimeSyncChecked":        "analysis/heuristics_oci.go (gated; local config absent is normal)",
	"OCIInfo.VNICChecked":            "analysis/heuristics_oci.go (gated; no virtio_net readable is normal off-OCI)",

	// Misc host-level "*Checked" — audited 2026-07-08.
	"AuthInfo.Checked":                      "analysis/heuristics_security.go checkAuth (explicit INFO 'SSH auth log could not be read' — already the target pattern)",
	"AuthInfo.SSHConfigChecked":             "analysis/heuristics_security.go checkAuth (gated: 'unknown policy keeps the WARN' — fails toward warning, not OK)",
	"BINDInfo.PortsChecked":                 "analysis/heuristics (gated; ss unavailable → explicit INFO disclosure already present)",
	"DockerInfo.IPForwardChecked":           "analysis/heuristics_virt.go (gated; proc unreadable on macOS/proc-less container → unknown, not disabled)",
	"FstabInfo.Checked":                     "analysis/heuristics_fstab.go (gated, no verdict when unchecked)",
	"MemoryInfo.MemHotplugChecked":          "analysis/heuristics (gated; hotplug sysfs genuinely absent on non-hotplug kernels — not privilege-related)",
	"MemoryInfo.EDACCountersUnreadable":     "analysis/heuristics_resources.go checkMemory (FIXED: a failed ce_count/ue_count read now emits an explicit INFO alongside whatever counters WERE read, instead of silently folding into a clean 0)",
	"HardwareMemory.EDACCountersUnreadable": "analysis/heuristics_hardware.go (same fix as MemoryInfo.EDACCountersUnreadable — shared readEDACCounts collector)",
	"MemoryInfo.MeminfoUnreadable":          "analysis/heuristics_resources.go checkMemory (FIXED: proc meminfo unreadable/unparseable on Linux — e.g. a replay bundle missing it — now emits an explicit INFO instead of falling back to a live gopsutil read)",
	"PackagesInfo.Checked":                  "collectors/packages_linux.go markStaleMetadata feeds Status; analysis/heuristics_packages.go checkPackageUpdates already discloses query-failed/stale-metadata as INFO",
	"PackagesInfo.DBHealthChecked":          "analysis/heuristics_packages.go checkPackageDBHealth (collector invariant: DBUpdatesBlocked is never true when DBHealthChecked is false — verified 2026-07-08, no live bug; defensively gated anyway)",
	"PostBootInfo.ShutdownChecked":          "analysis/heuristics (gated; tool-absent/wtmp-inconclusive reads as unknown, not clean)",
	"VMwareInfo.SCSIDisksChecked":           "analysis/heuristics (gated; no sd* disks on an NVMe-only guest is normal)",
	"SteamOSRemotePlay.ARPChecked":          "internal only (json:\"-\", not part of the --json contract); analysis gates on it before firing the isolation-suspected insight",
	"SessionsInfo.Checked":                  "analysis/heuristics_system.go checkSessions (FIXED: `w` unavailable now emits an explicit INFO, not a silent skip indistinguishable from 'nobody logged in')",

	// "*Measured" — cgroup read-success flags. Host /proc-derived values can't be
	// validly scored against a container's cgroup limit when the cgroup side
	// couldn't be read; the heuristic must say so, not silently pass.
	"MemoryInfo.CgroupMemMeasured":        "analysis/heuristics_resources.go checkMemory (FIXED: unmeasurable cgroup memory now emits an explicit INFO instead of silently dropping the RAM check)",
	"ContainerGuestInfo.CgroupV1Measured": "analysis/heuristics_containerguest.go checkContainerGuest (already correct: cgroup v1 throttle/OOM unmeasured → explicit INFO)",
	"ContainerGuestInfo.CgroupV2Measured": "analysis/heuristics_containerguest.go checkContainerGuest (FIXED: cgroup v2 throttle/OOM unmeasured now emits an explicit INFO, matching the pre-existing v1 guard)",
}

func TestUnverifiedSignalFieldsAllRegistered(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/models: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, f := range st.Fields.List {
				for _, fname := range f.Names { // skip embedded (no names)
					if unverifiedSignalRe.MatchString(fname.Name) {
						found[ts.Name.Name+"."+fname.Name] = true
					}
				}
			}
			return true
		})
	}

	var unregistered, stale []string
	for key := range found {
		if _, ok := guardedUnverifiedSignals[key]; !ok {
			unregistered = append(unregistered, key)
		}
	}
	for key := range guardedUnverifiedSignals {
		if !found[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("%d unverified-signal field(s) are not registered in guardedUnverifiedSignals:\n  %s\n\n"+
			"Each encodes a 'could not measure' state. Register it with a note on how a green OK is "+
			"prevented when it is set — add a standalone-renderer case in cmd/falseok_verdict_test.go if "+
			"the field has a renderer that can show an all-clear, else note the heuristic that folds it to "+
			"INFO/WARN. (Completeness tripwire — see this file's doc comment.)",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d registry entr(y/ies) no longer exist in internal/models (remove them):\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}
