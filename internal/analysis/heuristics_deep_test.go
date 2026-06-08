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
}

func TestCheckDockerResources(t *testing.T) {
	tests := []struct {
		name string
		d    models.DockerInfo
		want string
	}{
		{"devicemapper driver is WARN", models.DockerInfo{Daemon: &models.DockerDaemon{StorageDriver: "devicemapper"}}, "WARN"},
		{"daemon errors is WARN", models.DockerInfo{Daemon: &models.DockerDaemon{RecentErrors: 3}}, "WARN"},
		{"large dangling images is WARN", models.DockerInfo{DanglingImages: 5, DanglingImagesMB: 2048}, "WARN"},
		{"some dangling images is INFO", models.DockerInfo{DanglingImages: 2, DanglingImagesMB: 100}, "INFO"},
		{"orphaned volumes is WARN", models.DockerInfo{OrphanedVolumes: 5}, "WARN"},
		{"MTU mismatch is WARN", models.DockerInfo{MTUMismatch: true, ContainerMTU: 1500, HostMTU: 1450}, "WARN"},
		{"ip forward disabled is CRIT", models.DockerInfo{Available: true, IPForwardChecked: true, IPForwardEnabled: false}, "CRIT"},
		{"firewalld nftables is WARN", models.DockerInfo{FirewalldActive: true, FirewalldBackend: "nftables"}, "WARN"},
		{"DNS trap is WARN", models.DockerInfo{DNSTrap: true, DNSTrapServer: "127.0.0.53"}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerResources(tt.d), tt.want)
		})
	}
}

func TestCheckHealthDeep_CoreImbalance(t *testing.T) {
	hd := models.HealthDeepInfo{
		CoreImbalance: 85, MaxCorePct: 90, MinCorePct: 5,
		Cores: []models.CoreStat{{Core: 0, UsagePct: 90}, {Core: 1, UsagePct: 5}},
	}
	assertLevel(t, checkHealthDeep(hd), "WARN")

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

func TestCheckK8sOSLayer(t *testing.T) {
	// Healthy OS layer (all gates pass; ip_forward read and enabled).
	ok := models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: true, FlannelSubnetOK: true, CNIBinsOK: true, KubeForwardChain: true}
	tests := []struct {
		name string
		l    models.K8sOSLayer
		want string
	}{
		{"healthy is clean", ok, ""},
		{"ip forward checked + off is CRIT", models.K8sOSLayer{IPForwardChecked: true, FlannelSubnetOK: true, CNIBinsOK: true, KubeForwardChain: true}, "CRIT"},
		// /proc unreadable (IPForwardChecked=false) must NOT produce a false
		// "IP forwarding disabled" CRIT — state is unknown, not disabled.
		{"ip forward unchecked is not CRIT", models.K8sOSLayer{IPForwardChecked: false, FlannelSubnetOK: true, CNIBinsOK: true, KubeForwardChain: true}, ""},
		{"missing flannel subnet is CRIT", models.K8sOSLayer{IPForwardEnabled: true, CNIBinsOK: true, KubeForwardChain: true}, "CRIT"},
		{"empty CNI bins is CRIT", models.K8sOSLayer{IPForwardEnabled: true, FlannelSubnetOK: true, KubeForwardChain: true}, "CRIT"},
		{"missing kube-forward chain is WARN", models.K8sOSLayer{IPForwardEnabled: true, FlannelSubnetOK: true, CNIBinsOK: true}, "WARN"},
		{"expired cert is CRIT", func() models.K8sOSLayer { l := ok; l.CertExpiredNames = []string{"apiserver"}; return l }(), "CRIT"},
		{"cert expiring soon is WARN", func() models.K8sOSLayer { l := ok; l.CertExpirySoonDays = 5; return l }(), "WARN"},
		{"kubelet errors is WARN", func() models.K8sOSLayer { l := ok; l.KubeletErrors = []string{"failed to pull image"}; return l }(), "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkK8sOSLayer(tt.l), tt.want)
		})
	}
}

func TestCheckSnapper_Space(t *testing.T) {
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 60}), "CRIT")
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 25}), "WARN")
	// Healthy snapper emits an OK insight.
	assertLevel(t, checkSnapper(models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 1, TotalSpaceGB: 2}), "OK")
}

func TestCheckPackages_ManagerVariants(t *testing.T) {
	// Exercise the distro fix-command switch arms.
	for _, pm := range []string{"dnf", "zypper", "pacman", "yum", "brew", "apt"} {
		got := checkPackages(models.PackagesInfo{SecurityUpdates: 3, CriticalUpdates: 1, PackageManager: pm})
		if !hasLevel(got, "CRIT") {
			t.Errorf("pm=%s: expected CRIT, got %+v", pm, got)
		}
	}
	// Plain security updates (no critical/important) is a WARN.
	assertLevel(t, checkPackages(models.PackagesInfo{SecurityUpdates: 4, PackageManager: "apt"}), "WARN")
}
