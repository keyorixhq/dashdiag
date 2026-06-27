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

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// healthHasConcern reports whether `dsd health` raises a WARN or CRIT for a single
// collector result — i.e. the same heuristic path health runs, on one model.
func healthHasConcern(t *testing.T, name string, data interface{}) bool {
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
