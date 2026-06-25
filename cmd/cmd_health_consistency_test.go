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
