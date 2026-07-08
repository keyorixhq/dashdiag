package cmd

// cmd_health_consistency_test.go — guards the recurring "sibling divergence" bug
// class (#235/#275/#335, BUG-050): a standalone `dsd <cmd>` verdict drifting from
// the `dsd health` verdict on the SAME data, because each cmd kept a hand-tallied
// issues count with thresholds copied out of analysis/heuristics.go.
//
// The invariant: for a given model, the standalone cmd's "is there a concern?"
// (its extracted *Concerns tally) must agree with whether `dsd health`'s heuristic
// (analysis.ApplyThresholds → the same checkX) raises a WARN/CRIT. Run over the
// documented past-divergence cases plus boundaries, this fails the moment a future
// threshold edit re-diverges the two paths.
//
// Deterministic (pure model in → verdict out), so it's a unit test, not a flaky
// live CI job — the right home for a cross-cutting verdict invariant.
//
// SCOPE: this guards WARN/CRIT *concern* parity only. It deliberately does NOT cover
// the "unverified-state false-OK" class (a renderer showing green OK while health
// shows an INFO "not verified") — an INFO collapses to "no concern" on BOTH sides, so
// concern-parity is structurally blind to it. That class is guarded at the rendered-
// output level in falseok_verdict_test.go.

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// healthHasConcern reports whether `dsd health` raises a WARN or CRIT for a single
// collector result — i.e. the same heuristic path health runs, on one model.
func healthHasConcern(t *testing.T, name string, data any) bool {
	t.Helper()
	env := platform.CloudEnvironment(0) // non-cloud; matches a plain host
	ins := analysis.ApplyThresholds(
		[]runner.Result{{Name: name, Data: data}},
		analysis.DefaultThresholds(env), env, platform.ContainerContext{},
	)
	for _, i := range ins {
		if i.Level == "WARN" || i.Level == "CRIT" {
			return true
		}
	}
	return false
}

func TestCmdHealthConsistency_GPU(t *testing.T) {
	cases := []struct {
		name string
		dev  models.GPUDevice
	}{
		{"healthy", models.GPUDevice{TempC: 50, UtilPct: 20}},
		{"hot crit", models.GPUDevice{TempC: 95}},
		{"elevated warn", models.GPUDevice{TempC: 82}},
		// #275: an APU's shared-RAM "VRAM" fills to 90%+ by design — must NOT be a
		// concern in EITHER path.
		{"APU vram 92 (carve-out)", models.GPUDevice{TempC: 50, VRAMUsedPct: 92, IsAPU: true}},
		// A real discrete GPU at 92% VRAM IS a concern in both paths.
		{"discrete vram 92", models.GPUDevice{TempC: 50, VRAMUsedPct: 92}},
		// §L/§Q: a garbage hwmon temp (thousands of °C) must be a concern (unverified
		// sensor WARN) in BOTH paths — and crucially never a false thermal CRIT.
		{"implausible temp (garbage sensor)", models.GPUDevice{TempC: 11000}},
		// Driver-reported throttling, util maxed, and an unreadable device — all
		// previously-untested gpuConcerns conditions that mirror checkGPUDevice.
		{"throttling", models.GPUDevice{TempC: 50, Throttling: true}},
		{"util maxed", models.GPUDevice{TempC: 50, UtilPct: 96}},
		{"unreadable device", models.GPUDevice{Unreadable: true}},
		{"discrete mem 96", models.GPUDevice{TempC: 50, MemUsedPct: 96}},
		// DPM "low" while idle is legitimate power-saving, not a concern, in EITHER
		// path — a power profile parking an idle GPU at "low" must not false-WARN.
		{"power dpm low but idle", models.GPUDevice{TempC: 50, PowerDPMLevel: "low", UtilPct: 5}},
		// DPM "low" under real load (util >= 50) IS a concern in both paths — the GPU
		// failed to ramp up under demand.
		{"power dpm low under load", models.GPUDevice{TempC: 50, PowerDPMLevel: "low", UtilPct: 60}},
		// Busy GPU (high util, low power) is NOT a fault in EITHER path — pins the
		// BUG-089 fix so a future edit can't re-add a bare-util WARN to `dsd gpu`.
		{"busy but healthy (util 100, low power)", models.GPUDevice{TempC: 55, UtilPct: 100, PowerDrawW: 30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &models.GPUInfo{Devices: []models.GPUDevice{tc.dev}}
			crits, warns := gpuConcerns(info)
			cmdConcern := crits > 0 || warns > 0
			healthConcern := healthHasConcern(t, "GPU", info)
			if cmdConcern != healthConcern {
				t.Errorf("GPU verdict divergence: `dsd gpu` concern=%v but `dsd health` concern=%v (crits=%d warns=%d)",
					cmdConcern, healthConcern, crits, warns)
			}
		})
	}
}

func TestCmdHealthConsistency_KVM(t *testing.T) {
	cases := []struct {
		name string
		info models.KVMInfo
	}{
		{"clean", models.KVMInfo{Detected: true}},
		// Collector-realistic: it sets the VMsCrashed COUNTER by counting crashed VMs
		// in the list, and health iterates the list while cmd reads the counter — so a
		// faithful fixture sets both (a counter without its list entry is a state the
		// collector never emits).
		{"crashed vm", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{State: models.KVMCrashed}}, VMsCrashed: 1}},
		// #275: libvirt up but `virsh list` failed — must not read as healthy.
		{"enum-failed", models.KVMInfo{Detected: true, Status: "enum-failed"}},
		{"pool near full", models.KVMInfo{Detected: true, PoolsNearFull: 1}},
		// Previously-untested kvmConcerns counters — each is read directly by checkKVM/
		// checkKVMVMs (no list iteration needed, unlike the crashed-VM CRIT above).
		{"paused vm", models.KVMInfo{Detected: true, VMsPaused: 1}},
		{"abnormal vm", models.KVMInfo{Detected: true, VMsAbnormal: 1}},
		{"unreadable vm", models.KVMInfo{Detected: true, VMsUnreadable: 1}},
		{"down autostart vm", models.KVMInfo{Detected: true, VMsDownAutostart: 1}},
		{"disk io errors", models.KVMInfo{Detected: true, DiskIOErrors: 1}},
		{"networks inactive", models.KVMInfo{Detected: true, NetworksInactive: 1}},
		{"pools inactive", models.KVMInfo{Detected: true, PoolsInactive: 1}},
		// Deep-only per-VM XML findings — found live-testing against a real libvirt
		// host (2026-07-01): `dsd kvm --deep` said "healthy" while `dsd health --deep`
		// correctly WARNed/CRITed on the same VM. kvmConcerns previously never read
		// these three fields at all.
		{"missing disk file (deep)", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMShutOff, MissingDiskPath: "/var/lib/libvirt/images/vm1.qcow2"}}}},
		{"emulated nic (deep)", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMRunning, EmulatedNICs: []string{"aa:bb (e1000)"}}}}},
		{"emulated disk (deep)", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMRunning, EmulatedDisks: []string{"sda (sata)"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := kvmConcerns(&tc.info) > 0
			healthConcern := healthHasConcern(t, "KVM", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("KVM verdict divergence: `dsd kvm` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

func TestCmdHealthConsistency_Net(t *testing.T) {
	cases := []struct {
		name string
		info models.NetworkInfo
	}{
		{"healthy", models.NetworkInfo{GatewayPingMs: 1}},
		// #275: cmd flagged latency only >200ms; health (and now cmd) WARN >50ms.
		{"slow gateway", models.NetworkInfo{GatewayPingMs: 120}},
		// #275: cmd flagged conntrack only >=80%; aligned to health's >=60%.
		{"conntrack high", models.NetworkInfo{GatewayPingMs: 1, ConntrackUsedPct: 72}},
		{"dns failed", models.NetworkInfo{GatewayPingMs: 1, DNSFailed: true}},
		// Primary interface down → checkNetwork WARNs (heuristics_network.go:428).
		{"primary interface down", models.NetworkInfo{PrimaryInterfaceDown: true, GatewayPingMs: 1}},
		// Gateway packet loss — both paths share analysis.GatewayPacketLossLevel (≥10% WARN).
		{"gateway packet loss", models.NetworkInfo{GatewayPingMs: 1, GatewayPacketLossPct: 15}},
		// CLOSE_WAIT leak — cmd flags >100; checkNetwork WARNs >100 (heuristics_network.go:485).
		{"close_wait leak", models.NetworkInfo{GatewayPingMs: 1, CloseWaitCount: 150}},
		// HIGH TIME_WAIT count — `dsd net --deep` renders the row and `dsd health`
		// WARN/CRITs via analysis.TimeWaitLevel, but netConcerns never read
		// TimeWaitCount at all (a red row under a green "✅ Network healthy" summary).
		{"time_wait high", models.NetworkInfo{GatewayPingMs: 1, TimeWaitCount: 60000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := netConcerns(&tc.info) > 0
			healthConcern := healthHasConcern(t, "Network", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("Network verdict divergence: `dsd net` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

func TestCmdHealthConsistency_K8s(t *testing.T) {
	// Detected + APIReachable so the health heuristic actually evaluates the cluster
	// (kubectl present but no successful query reads as "not verified", not healthy).
	base := models.K8sInfo{Detected: true, APIReachable: true}
	mk := func(mut func(*models.K8sInfo)) models.K8sInfo { i := base; mut(&i); return i }
	cases := []struct {
		name string
		info models.K8sInfo
	}{
		{"healthy", base},
		// #275: cmd verdict previously ignored these; checkK8s WARNs.
		{"workloads down", mk(func(i *models.K8sInfo) { i.WorkloadsDown = 1 })},
		{"pvc not bound", mk(func(i *models.K8sInfo) { i.PVCsNotBound = 1 })},
		{"warning events", mk(func(i *models.K8sInfo) { i.Events = make([]models.K8sEvent, 1) })},
		{"crash looping", mk(func(i *models.K8sInfo) { i.CrashLooping = 1 })},
		// Previously-untested k8sHasConcern terms — pin each against checkK8s.
		{"nodes not ready", mk(func(i *models.K8sInfo) { i.NodesNotReady = 1 })},
		{"pods pending", mk(func(i *models.K8sInfo) { i.Pending = 1 })},
		{"pods not ready", mk(func(i *models.K8sInfo) { i.PodsNotReady = 1 })},
		{"high restarts", mk(func(i *models.K8sInfo) { i.HighRestarts = 1 })},
		// Spec 23f: a pod stuck in Unknown status (node likely unreachable) — pins
		// k8sHasConcern reading info.UnknownStatus so `dsd k8s` can't print "Cluster
		// healthy" while `dsd health` WARNs on the same data.
		{"unknown status", mk(func(i *models.K8sInfo) { i.UnknownStatus = 1 })},
		// HIGH bug fix: `dsd k8s --deep` OS-layer faults (dead kubelet/containerd,
		// disabled ip_forward, missing CNI, expired certs) previously CRITed in
		// `dsd health --deep` but rendered "✅ Cluster healthy" here — k8sHasConcern
		// never read info.OSLayer at all. A nil OSLayer (fast `dsd k8s`, no --deep)
		// must NOT diverge either — both sides treat it as no additional signal.
		{"nil OSLayer diverges from neither side", base},
		{"OSLayer kubelet down", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{KubeletChecked: true, KubeletActive: false}
		})},
		{"OSLayer containerd down", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{ContainerdChecked: true, ContainerdActive: false}
		})},
		{"OSLayer ip_forward disabled", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: false}
		})},
		{"OSLayer cert expired", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{CertExpiredNames: []string{"apiserver"}}
		})},
		{"OSLayer cert expiring soon (WARN)", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{CertExpirySoon: true, CertExpirySoonDays: 5}
		})},
		{"OSLayer kubelet errors (WARN)", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{KubeletErrors: []string{"failed to start container"}}
		})},
		{"OSLayer all clean is not a concern", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{KubeletChecked: true, KubeletActive: true, ContainerdChecked: true, ContainerdActive: true}
		})},
		// Spec 23e: KUBE-SERVICES chain — generic OSLayer pass-through (k8sOSLayerInsights
		// runs the exact same CheckK8sOSLayer as health), so no cmd/k8s.go special-casing
		// was needed; this pins that the pass-through actually covers it.
		{"OSLayer kube-services empty (iptables mode, WARN)", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{KubeServicesChecked: true, KubeProxyMode: "iptables", KubeServicesCount: 0}
		})},
		{"OSLayer kube-services nft mode is not a concern", mk(func(i *models.K8sInfo) {
			i.OSLayer = &models.K8sOSLayer{KubeServicesChecked: true, KubeProxyMode: "nft", KubeServicesCount: 0}
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := k8sHasConcern(&tc.info)
			healthConcern := healthHasConcern(t, "K8s", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("K8s verdict divergence: `dsd k8s` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// `dsd security`'s verdict now derives from the SAME heuristic health uses
// (analysis.SecurityConcernCount → checkSecurity, the BUG-072 fix), so the two
// cannot diverge by construction. These cases include the ones the OLD hand-tallied
// countSecurityIssues silently MISSED (StrictModes-disabled, PermitEmptyPasswords)
// — they now register as concerns in both paths. That's the regression guard: if
// anyone reverts `dsd security` to a parallel tally, those diverge again and fail.
// (healthy sets SSHStrictModes, enabled by default on a real host.)
func TestCmdHealthConsistency_Security(t *testing.T) {
	cases := []struct {
		name string
		info models.SecurityInfo
	}{
		{"healthy", models.SecurityInfo{SSHStrictModes: true}},
		{"ssh password auth", models.SecurityInfo{SSHStrictModes: true, SSHPasswordAuth: true}},
		{"ssh permit root", models.SecurityInfo{SSHStrictModes: true, SSHPermitRoot: true}},
		// Previously missed by countSecurityIssues — now counted via checkSecurity:
		{"strictmodes disabled", models.SecurityInfo{SSHStrictModes: false}},
		{"permit empty passwords", models.SecurityInfo{SSHStrictModes: true, SSHPermitEmptyPwd: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := analysis.SecurityConcernCount(tc.info) > 0
			healthConcern := healthHasConcern(t, "Security", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("Security verdict divergence: `dsd security` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

func TestCmdHealthConsistency_Docker(t *testing.T) {
	cases := []struct {
		name string
		info models.DockerInfo
	}{
		{"clean", models.DockerInfo{Available: true, RunningCount: 2}},
		// Collector-realistic: health iterates the Unhealthy list, cmd reads the count.
		{"unhealthy", models.DockerInfo{Available: true, RunningCount: 2, Unhealthy: []string{"c1"}, UnhealthyCount: 1}},
		{"oom events", models.DockerInfo{Available: true, RunningCount: 1, OOMEvents: 2}},
		// #275: root-user containers — checkDockerSecurity WARNs; the standalone
		// verdict previously ignored them.
		{"root containers", models.DockerInfo{Available: true, RunningCount: 1, RunningAsRootCount: 1}},
		// Daemon reachable but enumeration failed → checkDocker WARNs on Status=="error".
		{"status error", models.DockerInfo{Available: true, Status: "error"}},
		// Crash-looping container — health iterates the CrashLooping list, cmd reads the count.
		{"crash looping", models.DockerInfo{Available: true, RunningCount: 1, CrashLooping: []string{"c1"}, CrashLoopCount: 1}},
		// Failed systemd-managed Podman quadlet → checkPodmanQuadlets WARNs. Collector-
		// realistic: a failed quadlet carries State=="failed" (a bare Failed:true with an
		// empty State is the "unverified" case, which checkPodmanQuadlets treats as INFO).
		{"podman quadlet failed", models.DockerInfo{Available: true, Runtime: "podman", RunningCount: 1,
			PodmanQuadlets: []models.PodmanQuadlet{{Name: "app", ServiceUnit: "app.service", Failed: true, State: "failed"}}}},
		// Plaintext env secrets → checkDockerSecurity WARNs.
		{"plaintext secrets", models.DockerInfo{Available: true, RunningCount: 1, ContainersWithSecrets: 1}},
		// docker.sock mounted into a container → checkDockerSecurity WARNs.
		{"socket mounted", models.DockerInfo{Available: true, RunningCount: 1, SocketMountedCount: 1}},
		// Containers present but ALL stopped — dockerConcerns counts it; this case pins
		// whether checkDocker agrees (the previously-untested condition).
		{"all stopped", models.DockerInfo{Available: true, RunningCount: 0, StoppedCount: 2}},
		// Log driver (deep-only) — checkDocker WARNs on either signal; dockerConcerns
		// previously never read info.LogDriver at all (a red [Log driver] row under a
		// green "✅ Docker healthy" summary).
		{"log driver unbounded", models.DockerInfo{Available: true, RunningCount: 1,
			LogDriver: &models.DockerLogDriverInfo{Driver: "json-file", UnboundedContainers: []string{"web"}}}},
		{"log driver large logs", models.DockerInfo{Available: true, RunningCount: 1,
			LogDriver: &models.DockerLogDriverInfo{Driver: "json-file", LargeLogCount: 2}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := dockerConcerns(&tc.info) > 0
			healthConcern := healthHasConcern(t, "Docker", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("Docker verdict divergence: `dsd docker` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// `dsd vmware` derives its concern tally from analysis.VMwareInsights — the SAME
// checkVMware `dsd health` dispatches to — so the two are consistent by construction.
// This guard documents that invariant and fails if a future change re-derives the
// tally from model fields (the drift trap) or unwires the health dispatch. Cases
// cover the demo path incl. the non-binding limit that must be INFO in BOTH paths.
func TestCmdHealthConsistency_VMware(t *testing.T) {
	base := func() models.VMwareInfo {
		return models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true, StatAvailable: true}
	}
	cases := []struct {
		name string
		mut  func(*models.VMwareInfo)
	}{
		{"clean paravirtual", func(v *models.VMwareInfo) { v.NICDrivers = map[string]string{"ens192": "vmxnet3"} }},
		{"tools not installed", func(v *models.VMwareInfo) { v.ToolsInstalled = false; v.ToolsRunning = false }},
		{"emulated NIC", func(v *models.VMwareInfo) {
			v.EmulatedNICs = []string{"ens33"}
			v.NICDrivers = map[string]string{"ens33": "e1000"}
		}},
		{"low SCSI timeout", func(v *models.VMwareInfo) {
			v.LowSCSITimeouts = []string{"sda"}
			v.SCSITimeouts = map[string]int{"sda": 30}
		}},
		{"EnableUUID off", func(v *models.VMwareInfo) { v.SCSIDisksChecked = true; v.DisksNoStableID = []string{"sdb"} }},
		{"ballooning", func(v *models.VMwareInfo) { v.BalloonMB = 256 }},
		{"binding CPU limit", func(v *models.VMwareInfo) { v.CPULimitMHz = 1500; v.NumVCPU = 2; v.HostMHzPerCPU = 2993 }},
		// §N: a limit at/above capacity is INFO — must be a non-concern in BOTH paths.
		{"non-binding mem limit", func(v *models.VMwareInfo) { v.MemLimitMB = 2048; v.TotalRAMMB = 1920 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := base()
			tc.mut(&info)
			cmdConcern := vmwareConcerns(&info) > 0
			healthConcern := healthHasConcern(t, "VMware", &info)
			if cmdConcern != healthConcern {
				t.Errorf("VMware verdict divergence: `dsd vmware` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// `dsd kvm-guest` derives its tally from analysis.KVMGuestInsights — the SAME
// checkKVMGuest `dsd health` dispatches to — so the two agree by construction. Cases
// cover the guest-fixable WARNs, the host-side steal WARN, and the INFO-only states
// (clean, qga-channel-absent, low steal, non-kvm clock) that must be non-concerns in
// BOTH paths.
func TestCmdHealthConsistency_KVMGuest(t *testing.T) {
	base := func() models.KVMGuestInfo {
		return models.KVMGuestInfo{
			IsGuest: true, QGAChannelPresent: true, QGAInstalled: true, QGARunning: true,
			Clocksource: "kvm-clock",
		}
	}
	cases := []struct {
		name string
		mut  func(*models.KVMGuestInfo)
	}{
		{"clean paravirtual", func(v *models.KVMGuestInfo) { v.NICDrivers = map[string]string{"eth0": "virtio_net"} }},
		{"qga not running", func(v *models.KVMGuestInfo) { v.QGARunning = false }},
		// Host hasn't enabled the channel → INFO, not a concern in either path.
		{"qga channel absent", func(v *models.KVMGuestInfo) {
			v.QGAChannelPresent = false
			v.QGAInstalled = false
			v.QGARunning = false
		}},
		{"emulated NIC", func(v *models.KVMGuestInfo) {
			v.EmulatedNICs = []string{"eth0"}
			v.NICDrivers = map[string]string{"eth0": "e1000"}
		}},
		{"emulated disk", func(v *models.KVMGuestInfo) {
			v.EmulatedDisks = []string{"sda"}
			v.DiskBuses = map[string]string{"sda": "sata"}
		}},
		{"high steal", func(v *models.KVMGuestInfo) { v.StealPct = 15 }},
		{"low steal", func(v *models.KVMGuestInfo) { v.StealPct = 2 }},
		// Non-kvm clocksource → INFO, not a concern.
		{"tsc clocksource", func(v *models.KVMGuestInfo) { v.Clocksource = "tsc" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := base()
			tc.mut(&info)
			cmdConcern := kvmGuestConcerns(&info) > 0
			healthConcern := healthHasConcern(t, "KVMGuest", &info)
			if cmdConcern != healthConcern {
				t.Errorf("KVMGuest verdict divergence: `dsd kvm-guest` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// `dsd guest` (container case) counts WARN/CRIT from analysis.ContainerGuestInsights
// — the SAME checkContainerGuest `dsd health` dispatches to — so the tally can't
// drift. INFO-level states (no CPU limit, writable rootfs, recognition) must be
// non-concerns in both paths.
func TestCmdHealthConsistency_ContainerGuest(t *testing.T) {
	base := func() models.ContainerGuestInfo {
		// A clean container: limits set, non-root, read-only root, no throttle/OOM.
		return models.ContainerGuestInfo{
			InContainer: true, Runtime: "docker", CgroupV2: true,
			MemLimitBytes: 128 << 20, CPUQuotaCores: 1.0,
		}
	}
	concerns := func(v models.ContainerGuestInfo) int {
		n := 0
		for _, in := range analysis.ContainerGuestInsights(v) {
			if in.Level == "WARN" || in.Level == "CRIT" {
				n++
			}
		}
		return n
	}
	cases := []struct {
		name string
		mut  func(*models.ContainerGuestInfo)
	}{
		{"clean", func(v *models.ContainerGuestInfo) {}},
		{"no mem limit", func(v *models.ContainerGuestInfo) { v.MemLimitBytes = 0 }},
		{"runs as root", func(v *models.ContainerGuestInfo) { v.RunAsRoot = true }},
		{"cpu throttled", func(v *models.ContainerGuestInfo) { v.ThrottledPct = 40 }},
		{"oom killed", func(v *models.ContainerGuestInfo) { v.OOMKills = 3 }},
		// INFO-only states — non-concerns in both paths:
		{"no cpu limit", func(v *models.ContainerGuestInfo) { v.CPUQuotaCores = 0 }},
		{"writable rootfs", func(v *models.ContainerGuestInfo) { v.WritableRootfs = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := base()
			tc.mut(&info)
			cmdConcern := concerns(info) > 0
			healthConcern := healthHasConcern(t, "ContainerGuest", &info)
			if cmdConcern != healthConcern {
				t.Errorf("ContainerGuest divergence: `dsd guest` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// `dsd steamos` keeps its own hand-tally (steamOSConcernCount) for the summary
// line while `dsd health` evaluates the same SteamOSInfo through checkSteamOS —
// the exact two-paths-on-one-model shape this file guards. All fixtures set
// Detected:true (checkSteamOS no-ops otherwise, and the cmd only runs on a real
// SteamOS host) plus a verified-good RAUC/readonly baseline, so each case isolates
// one condition. If a future threshold edit moves only one path, this fails.
func TestCmdHealthConsistency_SteamOS(t *testing.T) {
	secureBootOn := true
	// healthy: every condition the tally counts is in its OK state.
	base := models.SteamOSInfo{
		Detected: true, RAUCAvailable: true,
		RAUCBootedStatus: "good", RAUCInactiveStatus: "good",
		ReadonlyKnown: true, ReadonlyEnabled: true,
	}
	mk := func(mut func(*models.SteamOSInfo)) models.SteamOSInfo { i := base; mut(&i); return i }
	cases := []struct {
		name string
		info models.SteamOSInfo
	}{
		{"healthy", base},
		// Booted RAUC slot bad — updates won't install (CRIT in both paths).
		{"rauc booted bad", mk(func(i *models.SteamOSInfo) { i.RAUCBootedStatus = "bad" })},
		// Writable rootfs — the #1 "an update broke my packages" cause (CRIT).
		{"readonly disabled", mk(func(i *models.SteamOSInfo) { i.ReadonlyEnabled = false })},
		// /var filling at the 70% boundary the tally and levelPct(70,85) share (WARN).
		{"var filling", mk(func(i *models.SteamOSInfo) { i.VarUsedPct = 75 })},
		// In Game Mode but gamescope crashed — device stuck (CRIT).
		{"gamemode no gamescope", mk(func(i *models.SteamOSInfo) {
			i.SessionMode = "gamemode"
			i.GamescopeActive = false
		})},
		// Secure Boot enabled on a non-Deck handheld — blocks USB recovery (WARN).
		{"secure boot enabled", mk(func(i *models.SteamOSInfo) {
			i.SecureBootApplicable = true
			i.SecureBootEnabled = &secureBootOn
		})},
		// A Remote Play primary (non-optional) port unbound — Steam down / RP off (WARN).
		{"remote play unbound", mk(func(i *models.SteamOSInfo) {
			i.RemotePlay = &models.SteamOSRemotePlay{
				Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27031, Bound: false}},
			}
		})},
		// Previously-untested steamOSConcernCount conditions — each mirrors checkSteamOS.
		{"rauc inactive bad", mk(func(i *models.SteamOSInfo) { i.RAUCInactiveStatus = "bad" })},
		{"channel config missing", mk(func(i *models.SteamOSInfo) { i.ChannelConfigMissing = true })},
		{"home filling", mk(func(i *models.SteamOSInfo) { i.HomeUsedPct = 88 })},
		{"update server unreachable", mk(func(i *models.SteamOSInfo) { i.UpdateServerKnown = true; i.UpdateServerReachable = false })},
		{"flatpak bloat", mk(func(i *models.SteamOSInfo) { i.FlatpakDataGB = 25 })},
		{"remote play firewall blocking", mk(func(i *models.SteamOSInfo) {
			i.RemotePlay = &models.SteamOSRemotePlay{FirewallBlocking: true}
		})},
		{"remote play ap isolation", mk(func(i *models.SteamOSInfo) {
			i.RemotePlay = &models.SteamOSRemotePlay{ARPChecked: true, APIsolationSuspected: true}
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmdConcern := steamOSConcernCount(&tc.info) > 0
			healthConcern := healthHasConcern(t, "SteamOS", &tc.info)
			if cmdConcern != healthConcern {
				t.Errorf("SteamOS verdict divergence: `dsd steamos` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}

// TestCmdHealthConsistency_Disk pins `dsd disk`'s filesystem verdict (countDiskIssues)
// to `dsd health`'s Disk check on the same FilesystemInfo. Disk is where the sibling-
// divergence class was first found (BUG-050); it aggregates several checks (Drives/ZFS/
// LVM are scored under their own checks + tested separately), so this guards the clean
// 1:1 dimension — filesystem usage/inode + the read-only-image-fs skip (#382), which had
// reached checkDisk but NOT dsd disk's countDiskIssues until this change.
func TestCmdHealthConsistency_Disk(t *testing.T) {
	cases := []struct {
		name string
		fs   models.FilesystemInfo
	}{
		{"clean ext4", models.FilesystemInfo{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 20, UsedPct: 20}},
		{"full ext4 crit", models.FilesystemInfo{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 96, UsedPct: 96}},
		{"inodes full", models.FilesystemInfo{Mount: "/", FSType: "ext4", TotalGB: 100, UsedGB: 10, UsedPct: 10, InodesUsedPct: 97}},
		// Read-only image filesystems are 100%-full by design — a concern in NEITHER
		// path (#382). Was a `dsd disk`-only false-alarm before this change.
		{"squashfs 100 (image)", models.FilesystemInfo{Mount: "/snap/x", FSType: "squashfs", TotalGB: 1, UsedGB: 1, UsedPct: 100}},
		{"iso9660 100 (cdrom)", models.FilesystemInfo{Mount: "/cdrom", FSType: "iso9660", TotalGB: 1, UsedGB: 1, UsedPct: 100}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &models.DiskInfo{Filesystems: []models.FilesystemInfo{tc.fs}}
			cmdConcern := countDiskIssues(info, nil) > 0
			healthConcern := healthHasConcern(t, "Disk", info)
			if cmdConcern != healthConcern {
				t.Errorf("Disk verdict divergence: `dsd disk` concern=%v but `dsd health` concern=%v",
					cmdConcern, healthConcern)
			}
		})
	}
}
