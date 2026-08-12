package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Deep-coverage tests for the remaining partially-covered large functions:
// disk extras (SMART), Docker resources, health-deep core imbalance, the rest of
// the sysctl workload profiles, systemd boot offenders, K8s workloads/events and
// OS-layer, snapper space, and the package-manager fix-command switch.

func TestCheckDiskExtras_SMART(t *testing.T) {
	drive := func(s models.SMARTInfo) models.DiskInfo {
		return models.DiskInfo{Drives: []models.PhysicalDrive{{Name: "sda", SMART: &s}}}
	}
	assertLevel(t, checkDiskExtras(drive(models.SMARTInfo{Healthy: true})), "")
	assertLevel(t, checkDiskExtras(drive(models.SMARTInfo{Healthy: false})), "CRIT")
	assertLevel(t, checkDiskExtras(drive(models.SMARTInfo{Healthy: true, PercentUsed: 95})), "WARN")
	assertLevel(t, checkDiskExtras(drive(models.SMARTInfo{Healthy: true, MediaErrors: 1})), "WARN")

	// SMART.Error set means the log itself couldn't be read — the drive must be
	// skipped (continue), not scored as unhealthy, even though Healthy is false.
	unread := models.DiskInfo{Drives: []models.PhysicalDrive{
		{Name: "sdb", SMART: &models.SMARTInfo{Healthy: false, Error: "smartctl: Permission denied"}},
	}}
	assertLevel(t, checkDiskExtras(unread), "")

	// SteamOS disk section is wired through when SteamOS is populated.
	withSteamOS := models.DiskInfo{SteamOS: &models.SteamOSDisk{ShaderCacheGB: 40}}
	if !hasInsightMsg(checkDiskExtras(withSteamOS), "CRIT", "shader cache") {
		t.Errorf("expected the SteamOS shader-cache CRIT to be wired through checkDiskExtras, got %+v", checkDiskExtras(withSteamOS))
	}
}

func TestCheckDockerResources(t *testing.T) {
	tests := []struct {
		name string
		d    models.DockerInfo
		want string
	}{
		{"devicemapper driver is WARN", models.DockerInfo{Daemon: &models.DockerDaemon{StorageDriver: "devicemapper"}}, "WARN"},
		{"daemon errors is WARN", models.DockerInfo{Daemon: &models.DockerDaemon{RecentErrors: 3}}, "WARN"},
		// Dangling-image count surfaces as INFO (the size-based WARN tier and the
		// orphaned-volumes WARN were removed — their fields were never populated).
		{"dangling images is INFO", models.DockerInfo{DanglingImages: 5}, "INFO"},
		{"no dangling images is silent", models.DockerInfo{DanglingImages: 0}, ""},
		{"MTU mismatch is WARN", models.DockerInfo{MTUMismatch: true, ContainerMTU: 1500, HostMTU: 1450}, "WARN"},
		{"ip forward disabled is CRIT", models.DockerInfo{Available: true, IPForwardChecked: true, IPForwardEnabled: false}, "CRIT"},
		{"firewalld nftables is WARN", models.DockerInfo{FirewalldActive: true, FirewalldBackend: "nftables"}, "WARN"},
		{"DNS trap is WARN", models.DockerInfo{DNSTrap: true, DNSTrapServer: "127.0.0.53"}, "WARN"},
		{
			name: "both compose v1 and v2 installed is WARN",
			d:    models.DockerInfo{Daemon: &models.DockerDaemon{ComposeStandalone: "1.29.2", ComposePlugin: "2.29.1"}},
			want: "WARN",
		},
		{
			name: "compose v1 only (no v2 plugin) is WARN",
			d:    models.DockerInfo{Daemon: &models.DockerDaemon{ComposeStandalone: "1.29.2"}},
			want: "WARN",
		},
		{
			name: "daemon errors with a last-error message is WARN",
			d:    models.DockerInfo{Daemon: &models.DockerDaemon{RecentErrors: 2, LastDaemonError: "context deadline exceeded"}},
			want: "WARN",
		},
		{
			name: "large log files is WARN",
			d:    models.DockerInfo{LogDriver: &models.DockerLogDriverInfo{LargeLogCount: 2}},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerResources(tt.d), tt.want)
		})
	}
}

func TestCheckHealthDeep_CoreImbalance(t *testing.T) {
	// Sustained single-thread saturation (loadavg1 ≥ 1.0 → a thread has been
	// continuously runnable) AND concentrated on one core → real bottleneck, WARN.
	hd := models.HealthDeepInfo{
		CoreImbalance: 85, MaxCorePct: 90, MinCorePct: 5, NumCPU: 8, LoadAvg1: 1.5,
		Cores: []models.CoreStat{{Core: 0, UsagePct: 90}, {Core: 1, UsagePct: 5}},
	}
	assertLevel(t, checkHealthDeep(hd), "WARN")

	// Same imbalance but the box is essentially idle (loadavg 0.25 on 12 cores):
	// one hot core with plenty of spare capacity is normal foreground work, NOT a
	// bottleneck. Suppressed. (Regression guard — false alarm seen on a real
	// AMD/12-core host, 2026-06-18.)
	idleImbalance := models.HealthDeepInfo{
		CoreImbalance: 94, MaxCorePct: 98, MinCorePct: 4, NumCPU: 12, LoadAvg1: 0.25,
		Cores: []models.CoreStat{{Core: 3, UsagePct: 98}, {Core: 1, UsagePct: 4}},
	}
	assertLevel(t, checkHealthDeep(idleImbalance), "")

	// All cores pegged AND the load average corroborates → WARN.
	pegged := models.HealthDeepInfo{
		MaxCorePct: 97, MinCorePct: 95, NumCPU: 2, LoadAvg1: 2.0,
		Cores: []models.CoreStat{{Core: 0, UsagePct: 97}, {Core: 1, UsagePct: 95}},
	}
	assertLevel(t, checkHealthDeep(pegged), "WARN")

	// All cores read pegged but the box is idle by load average (0.05) — this is
	// dsd's own deep collection saturating a small host, not real pressure.
	// Suppressed. (Regression guard for the observer-effect false positive.)
	observerNoise := models.HealthDeepInfo{
		MaxCorePct: 100, MinCorePct: 100, NumCPU: 2, LoadAvg1: 0.05,
		Cores: []models.CoreStat{{Core: 0, UsagePct: 100}, {Core: 1, UsagePct: 100}},
	}
	assertLevel(t, checkHealthDeep(observerNoise), "")
}

func TestCheckSysctl_Profiles(t *testing.T) {
	tests := []struct {
		name string
		s    models.SysctlInfo
		want string
	}{
		{"database high swappiness is WARN", models.SysctlInfo{Workload: "database", VMSwappiness: 30}, "WARN"},
		{"database high dirty ratio is WARN", models.SysctlInfo{Workload: "database", VMDirtyRatio: 40}, "WARN"},
		// internal-collectors-32-01: -1 is the "read failed / unmeasured" sentinel
		// (same convention as TCPTWReuse). It must never itself satisfy a "> N"
		// high-value check — that would be a false WARN on an unmeasured sysctl.
		{"database unmeasured swappiness (-1 sentinel) is silent", models.SysctlInfo{Workload: "database", VMSwappiness: -1}, ""},
		{"database unmeasured dirty ratio (-1 sentinel) is silent", models.SysctlInfo{Workload: "database", VMDirtyRatio: -1}, ""},
		{"webserver no tw_reuse is WARN", models.SysctlInfo{Workload: "webserver", TCPTWReuse: 0}, "WARN"},
		{"webserver low rmem is WARN", models.SysctlInfo{Workload: "webserver", TCPTWReuse: 1, NetRmemMax: 1000}, "WARN"},
		{"container low max_map_count is WARN", models.SysctlInfo{Workload: "container", VMMaxMapCount: 1000}, "WARN"},
		{"container low inotify is WARN", models.SysctlInfo{Workload: "container", VMMaxMapCount: 300000, FSInotifyWatches: 1000}, "WARN"},
		{"k8s low inotify is WARN", models.SysctlInfo{Workload: "k8s", FSInotifyWatches: 1000}, "WARN"},
		// Regression: a general-profile host at (or below) the kernel-default rmem_max
		// must NOT warn — flagging the universal default was first-run noise. rmem
		// tuning is workload-specific (see the "webserver" case above).
		{"default kernel-default rmem is silent", models.SysctlInfo{Workload: "", NetRmemMax: 212992}, ""},
		{"default low rmem still silent (rmem is role-specific)", models.SysctlInfo{Workload: "", NetRmemMax: 1000}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSysctl(tt.s), tt.want)
		})
	}
}

func TestCheckSystemd_Boot(t *testing.T) {
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true, SlowUnits: []models.SlowUnit{{Name: "NetworkManager-wait-online.service", Duration: 25}}}), "WARN")
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true, TotalBootSec: 45}), "INFO")
}

func TestCheckK8sWorkloadsAndEvents(t *testing.T) {
	assertLevel(t, checkK8sWorkloadsAndEvents(models.K8sInfo{PVCsNotBound: 1}), "WARN")
	assertLevel(t, checkK8sWorkloadsAndEvents(models.K8sInfo{
		WorkloadsDown: 1, Workloads: []models.K8sWorkloadInfo{{Namespace: "default", Name: "web", Ready: 0, Desired: 2}},
	}), "WARN")
	assertLevel(t, checkK8sWorkloadsAndEvents(models.K8sInfo{
		Events: []models.K8sEvent{{Reason: "BackOff", Message: "back-off restarting"}},
	}), "WARN")
}

func TestParseK8sEventAgeSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"47s", 47, true},
		{"6m5s", 365, true},
		{"92m", 5520, true},
		{"2d3h", 183600, true},
		{"5h", 18000, true},
		{"", 0, false},
		{"<unknown>", 0, false},
		{"12", 0, false},  // digits without a unit
		{"5m3", 0, false}, // trailing digits without a unit
		{"abc", 0, false}, // garbage
		{"5x", 0, false},  // unknown unit
	}
	for _, c := range cases {
		got, ok := parseK8sEventAgeSeconds(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseK8sEventAgeSeconds(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestK8sWarningEventRecencyGate(t *testing.T) {
	// All events quiesced (last seen well beyond the window) → INFO, not a verdict flip.
	// This is the live k3s-on-VMware false-alarm: startup warnings 5-6m old on a
	// now-healthy cluster.
	stale := []models.K8sEvent{
		{Reason: "FailedCreatePodSandBox", Age: "6m5s", Message: "subnet.env"},
		{Reason: "Unhealthy", Age: "5m43s"},
		{Reason: "BackOff", Age: "5m22s"},
	}
	assertLevel(t, k8sWarningEventInsight(stale), "INFO")

	// A still-recurring event (within the window) drives the WARN.
	assertLevel(t, k8sWarningEventInsight([]models.K8sEvent{
		{Reason: "BackOff", Age: "30s"},
	}), "WARN")

	// Mixed: any recent event keeps it a WARN.
	assertLevel(t, k8sWarningEventInsight([]models.K8sEvent{
		{Reason: "FailedCreatePodSandBox", Age: "6m5s"},
		{Reason: "Unhealthy", Age: "5m43s"},
		{Reason: "FailedScheduling", Age: "12s"},
	}), "WARN")

	// Unparseable age is treated as recent (never hide a possibly-live event).
	assertLevel(t, k8sWarningEventInsight([]models.K8sEvent{
		{Reason: "BackOff", Age: ""},
	}), "WARN")

	// No events → no insight.
	if got := k8sWarningEventInsight(nil); got != nil {
		t.Errorf("k8sWarningEventInsight(nil) = %v, want nil", got)
	}
}

func TestCheckK8sOSLayer(t *testing.T) {
	// Healthy OS layer (all gates pass; ip_forward read and enabled).
	ok := models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: true, FlannelSubnetOK: true, CNIChecked: true, CNIBinsOK: true, KubeForwardChecked: true, KubeForwardChain: true}
	tests := []struct {
		name string
		l    models.K8sOSLayer
		want string
	}{
		{"healthy is clean", ok, ""},
		{"ip forward checked + off is CRIT", models.K8sOSLayer{IPForwardChecked: true, FlannelSubnetOK: true, CNIBinsOK: true, KubeForwardChain: true}, "CRIT"},
		// /proc unreadable (IPForwardChecked=false) must NOT produce a false
		// "IP forwarding disabled" CRIT — state is unknown, not disabled.
		// CNIChecked/KubeForwardChecked set true here to isolate the IPForward
		// condition under test from checkK8sOSLayerCoverageGaps' own INFO
		// disclosure (fires whenever either is false — see TestCheckK8sOSLayerCoverageGaps_UnverifiedFieldsDiscloseWithoutFalseCritWarn below for that case).
		{"ip forward unchecked is not CRIT", models.K8sOSLayer{IPForwardChecked: false, FlannelSubnetOK: true, CNIBinsOK: true, KubeForwardChain: true, CNIChecked: true, KubeForwardChecked: true}, ""},
		{"missing flannel subnet WHEN flannel in use is CRIT", models.K8sOSLayer{IPForwardEnabled: true, FlannelInUse: true, CNIChecked: true, CNIBinsOK: true, KubeForwardChain: true}, "CRIT"},
		// The false-alarm fix: on a non-flannel CNI (Calico/Cilium) subnet.env is
		// absent by design — must NOT CRIT.
		{"missing flannel subnet but flannel NOT in use is clean", models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: true, FlannelInUse: false, FlannelSubnetOK: false, CNIChecked: true, CNIBinsOK: true, KubeForwardChain: true, KubeForwardChecked: true}, ""},
		{"empty CNI bins is CRIT", models.K8sOSLayer{IPForwardEnabled: true, FlannelSubnetOK: true, CNIChecked: true, KubeForwardChain: true}, "CRIT"},
		{"missing kube-forward chain (checked) is WARN", models.K8sOSLayer{IPForwardEnabled: true, FlannelSubnetOK: true, CNIChecked: true, CNIBinsOK: true, KubeForwardChecked: true}, "WARN"},
		{"expired cert is CRIT", func() models.K8sOSLayer { l := ok; l.CertExpiredNames = []string{"apiserver"}; return l }(), "CRIT"},
		{"cert expiring soon is WARN", func() models.K8sOSLayer { l := ok; l.CertExpirySoon = true; l.CertExpirySoonDays = 5; return l }(), "WARN"},
		// Regression: a cert expiring TODAY (0 days, within 24h) must WARN, not read as
		// the zero-value "none" (the 0-day false-OK — flag-gated, days==0 is valid).
		{"cert expiring today (0 days) is WARN", func() models.K8sOSLayer { l := ok; l.CertExpirySoon = true; l.CertExpirySoonDays = 0; return l }(), "WARN"},
		{"kubelet errors is WARN", func() models.K8sOSLayer { l := ok; l.KubeletErrors = []string{"failed to pull image"}; return l }(), "WARN"},
		{"kubelet down on a confirmed node is CRIT", func() models.K8sOSLayer { l := ok; l.KubeletChecked = true; l.KubeletActive = false; return l }(), "CRIT"},
		// A kubectl-only client host (no on-disk node marker) has no kubelet at all —
		// KubeletChecked stays false, must NOT read as "kubelet down".
		{"kubelet absent on an unchecked (remote-client) host is not CRIT", func() models.K8sOSLayer { l := ok; l.KubeletChecked = false; l.KubeletActive = false; return l }(), ""},
		{"containerd down on a confirmed node is CRIT", func() models.K8sOSLayer { l := ok; l.ContainerdChecked = true; l.ContainerdActive = false; return l }(), "CRIT"},
		{"containerd absent on an unchecked host is not CRIT", func() models.K8sOSLayer { l := ok; l.ContainerdChecked = false; l.ContainerdActive = false; return l }(), ""},
		{"firewalld active without masquerade on flannel is WARN", func() models.K8sOSLayer {
			l := ok
			l.FirewalldChecked = true
			l.FlannelInUse = true
			l.FirewalldMasquOK = false
			return l
		}(), "WARN"},
		// firewalld not running at all (the k3s/RKE2 default) must NOT WARN even
		// though FirewalldMasquOK is the zero-value false.
		{"firewalld not active is not WARN", func() models.K8sOSLayer {
			l := ok
			l.FirewalldChecked = false
			l.FlannelInUse = true
			l.FirewalldMasquOK = false
			return l
		}(), ""},
		// firewalld active+misconfigured but flannel isn't the CNI — masquerade isn't
		// flannel's requirement here, must NOT WARN.
		{"firewalld misconfigured but non-flannel CNI is not WARN", func() models.K8sOSLayer {
			l := ok
			l.FirewalldChecked = true
			l.FlannelInUse = false
			l.FirewalldMasquOK = false
			return l
		}(), ""},
		// Spec 23e: KUBE-SERVICES chain check.
		{"iptables mode, 0 KUBE-SERVICES entries is WARN", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = true
			l.KubeProxyMode = "iptables"
			l.KubeServicesCount = 0
			return l
		}(), "WARN"},
		{"iptables mode, entries present is clean", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = true
			l.KubeProxyMode = "iptables"
			l.KubeServicesCount = 2
			return l
		}(), ""},
		{"ipvs mode, 0 virtual servers is WARN", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = true
			l.KubeProxyMode = "ipvs"
			l.KubeServicesCount = 0
			return l
		}(), "WARN"},
		{"ipvs mode, virtual servers present is clean", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = true
			l.KubeProxyMode = "ipvs"
			l.KubeServicesCount = 3
			return l
		}(), ""},
		// nftables-backend kube-proxy never populates the legacy chain — mode "nft"
		// must never WARN regardless of count.
		{"nft mode is never WARN", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = true
			l.KubeProxyMode = "nft"
			l.KubeServicesCount = 0
			return l
		}(), ""},
		// kube-proxy pod not found / iptables-save unavailable → unchecked → must
		// NOT WARN (state unknown, not "missing").
		{"unchecked kube-services is not WARN", func() models.K8sOSLayer {
			l := ok
			l.KubeServicesChecked = false
			l.KubeProxyMode = ""
			l.KubeServicesCount = 0
			return l
		}(), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, CheckK8sOSLayer(tt.l), tt.want)
		})
	}
}

// checkK8sOSLayerCoverageGaps discloses via INFO whenever KubeForwardChecked or
// CNIChecked is false (see its doc comment) — these two cases used to be pure
// "" (zero-insight) rows in TestCheckK8sOSLayer's table, which no longer holds
// now that the unverified state is disclosed; pulled out so each can assert
// the full three-part expectation the table's two-column (name, want) shape
// can't express: the disclosure fires, AND no false CRIT/WARN fires alongside it.
func TestCheckK8sOSLayerCoverageGaps_UnverifiedFieldsDiscloseWithoutFalseCritWarn(t *testing.T) {
	t.Run("unreadable CNI bins (unchecked) discloses, does not CRIT", func(t *testing.T) {
		// /opt/cni/bin unreadable (permission) → CNIChecked=false.
		got := CheckK8sOSLayer(models.K8sOSLayer{
			IPForwardChecked: true, IPForwardEnabled: true, FlannelSubnetOK: true,
			CNIChecked: false, CNIBinsOK: false, KubeForwardChain: true, KubeForwardChecked: true,
		})
		if !hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
			t.Errorf("unchecked CNI bins must disclose, got %+v", got)
		}
		if hasLevel(got, "CRIT") {
			t.Errorf("unchecked CNI bins must NOT produce a false CRIT, got %+v", got)
		}
	})
	t.Run("unchecked kube-forward (no tools) discloses, does not WARN", func(t *testing.T) {
		// [19] fix: neither nft nor iptables available (e.g. k3s) → unchecked →
		// must NOT WARN (previously defaulted to "present", a false-OK; gating
		// flips it).
		got := CheckK8sOSLayer(models.K8sOSLayer{
			IPForwardChecked: true, IPForwardEnabled: true, FlannelSubnetOK: true,
			CNIChecked: true, CNIBinsOK: true, KubeForwardChain: true, KubeForwardChecked: false,
		})
		if !hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
			t.Errorf("unchecked kube-forward must disclose, got %+v", got)
		}
		if hasLevel(got, "WARN") {
			t.Errorf("unchecked kube-forward must NOT produce a false WARN, got %+v", got)
		}
	})
}

func TestCheckSnapper_Space(t *testing.T) {
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 60}), "CRIT")
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 25}), "WARN")
	// Healthy snapper emits an OK insight.
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 2}), "OK")
}

func TestCheckPackages_ManagerVariants(t *testing.T) {
	// Exercise the distro fix-command switch arms. apt is excluded: it has no CVSS,
	// so its "Critical" is name-inferred and must fold to WARN (asserted below).
	// brew is excluded: it has NO security metadata at all (the real collector
	// never populates CriticalUpdates), so brew unconditionally folds to an
	// honest INFO regardless — see TestCheckPackages's dedicated brew case.
	for _, pm := range []string{"dnf", "zypper", "pacman", "yum"} {
		got := checkPackages(models.PackagesInfo{SecurityUpdates: 3, CriticalUpdates: 1, PackageManager: pm})
		if !hasLevel(got, "CRIT") {
			t.Errorf("pm=%s: expected CRIT, got %+v", pm, got)
		}
	}
	// apt name-inferred "Critical" must NOT mint a CRIT — WARN with the caveat.
	assertLevel(t, checkPackages(models.PackagesInfo{SecurityUpdates: 3, CriticalUpdates: 1, PackageManager: "apt"}), "WARN")
	// Plain security updates (no critical/important) is a WARN.
	assertLevel(t, checkPackages(models.PackagesInfo{SecurityUpdates: 4, PackageManager: "apt"}), "WARN")
}
