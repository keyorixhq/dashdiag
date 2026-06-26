package analysis

// §N.4 — CPU steal attributed to a configured VMware host CPU limit.
//
// A VMware vSphere CPU limit throttles the guest below its vCPU capacity, which
// presents inside the guest as steal time. Before this, `dsd health` reported the
// steal generically ("host over-provisioned — migrate to a less-loaded host"),
// which is the WRONG remediation for a configured cap (migration doesn't help; you
// must remove the limit). These tests lock in: (1) the helper rewords + re-hints
// when a limit is known, and (2) the pre-scan actually threads the VMware result's
// cpu_limit_mhz into the CPU heuristic end-to-end.

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestCPUStealInsight(t *testing.T) {
	cases := []struct {
		name       string
		steal      float64
		limitMHz   int
		wantOK     bool
		wantLevel  string
		wantInMsg  string
		wantInHint string
	}{
		{"below floor, no limit", 5, 0, false, "", "", ""},
		{"below floor, limit known", 5, 1500, false, "", "", ""},
		{"warn, no limit → generic", 12, 0, true, "WARN", "not getting all requested", "migration"},
		{"crit, no limit → generic", 25, 0, true, "CRIT", "withholding CPU time", "migrate to a less-loaded host"},
		{"warn, limit → attributed", 12, 1500, true, "WARN", "host CPU limit of 1500 MHz", "vSphere"},
		{"crit, limit → attributed", 25, 2000, true, "CRIT", "host CPU limit of 2000 MHz", "will NOT help"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins, ok := cpuStealInsight(tc.steal, tc.limitMHz)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ins.Level != tc.wantLevel {
				t.Errorf("level=%q want %q", ins.Level, tc.wantLevel)
			}
			if ins.Check != "CPU Load/Steal" {
				t.Errorf("check=%q want CPU Load/Steal", ins.Check)
			}
			if !strings.Contains(ins.Message, tc.wantInMsg) {
				t.Errorf("message %q missing %q", ins.Message, tc.wantInMsg)
			}
			if !hintsContain(ins.Hints, tc.wantInHint) {
				t.Errorf("hints %v missing %q", ins.Hints, tc.wantInHint)
			}
			// When a limit is attributed, the misleading generic remedy must be gone.
			if tc.limitMHz > 0 && hintsContain(ins.Hints, "less-loaded host") {
				t.Errorf("limit-attributed steal must not advise migration; hints=%v", ins.Hints)
			}
		})
	}
}

// TestApplyThresholds_VMwareStealAttribution is the end-to-end proof that the
// pre-scan threads VMwareInfo.CPULimitMHz into CPUInfo so the steal heuristic can
// use it. The SAME CPUInfo yields the generic message alone and the attributed
// message when a VMware result with a configured limit is present.
func TestApplyThresholds_VMwareStealAttribution(t *testing.T) {
	env := platform.CloudEnvironment(0)
	cpu := models.CPUInfo{StealPct: 25, NumCPU: 2}

	steal := func(results []runner.Result) models.Insight {
		t.Helper()
		ins := ApplyThresholds(results, DefaultThresholds(env), env, platform.ContainerContext{})
		for _, i := range ins {
			if i.Check == "CPU Load/Steal" {
				return i
			}
		}
		t.Fatalf("no CPU Load/Steal insight produced")
		return models.Insight{}
	}

	// No VMware context → generic over-provisioning message.
	generic := steal([]runner.Result{{Name: "CPU Load", Data: cpu}})
	if strings.Contains(generic.Message, "host CPU limit") {
		t.Errorf("without a VMware limit the steal should be generic, got %q", generic.Message)
	}
	if !hintsContain(generic.Hints, "migrate to a less-loaded host") {
		t.Errorf("generic steal should advise migration, got %v", generic.Hints)
	}

	// With a VMware result carrying a configured CPU limit → attributed message.
	vmw := models.VMwareInfo{
		IsGuest: true, ToolsInstalled: true, ToolsRunning: true,
		StatAvailable: true, CPULimitMHz: 1500,
	}
	attributed := steal([]runner.Result{
		{Name: "CPU Load", Data: cpu},
		{Name: "VMware", Data: vmw},
	})
	if !strings.Contains(attributed.Message, "host CPU limit of 1500 MHz") {
		t.Errorf("with a VMware limit the steal should be attributed, got %q", attributed.Message)
	}
	if hintsContain(attributed.Hints, "less-loaded host") {
		t.Errorf("attributed steal must drop the migration advice, got %v", attributed.Hints)
	}

	// A VMware result whose stat channel was unreadable (StatAvailable=false) must
	// NOT attribute — CPULimitMHz is then an unverified zero-or-stale value (§N.1).
	vmwNoStat := models.VMwareInfo{IsGuest: true, ToolsInstalled: true, ToolsRunning: true, CPULimitMHz: 1500}
	notAttributed := steal([]runner.Result{
		{Name: "CPU Load", Data: cpu},
		{Name: "VMware", Data: vmwNoStat},
	})
	if strings.Contains(notAttributed.Message, "host CPU limit") {
		t.Errorf("unreadable stat channel must not attribute steal to a limit, got %q", notAttributed.Message)
	}
}

func hintsContain(hints []string, sub string) bool {
	for _, h := range hints {
		if strings.Contains(h, sub) {
			return true
		}
	}
	return false
}

// TestCPUOfflineInsight covers the allocated-but-offline vCPU check, including the
// gating that keeps it from false-warning on intentional offlining (SMT-off /
// isolcpus). The 14-present/2-online case is the real VMware hot-add-not-onlined
// state found live.
func TestCPUOfflineInsight(t *testing.T) {
	cases := []struct {
		name    string
		cpu     models.CPUInfo
		wantOK  bool
		wantLvl string
		wantMsg string
	}{
		{"all online → silent", models.CPUInfo{PresentCPUs: 8, OnlineCPUs: 8}, false, "", ""},
		{"not read (non-linux) → silent", models.CPUInfo{}, false, "", ""},
		{"hot-add not onlined → WARN", models.CPUInfo{PresentCPUs: 14, OnlineCPUs: 2, SMTControl: "on"}, true, "WARN", "allocated vCPUs are offline"},
		{"SMT off → INFO not WARN", models.CPUInfo{PresentCPUs: 8, OnlineCPUs: 4, SMTControl: "off"}, true, "INFO", "SMT is disabled"},
		{"SMT forceoff → INFO", models.CPUInfo{PresentCPUs: 8, OnlineCPUs: 4, SMTControl: "forceoff"}, true, "INFO", "SMT is disabled"},
		{"isolcpus → INFO not WARN", models.CPUInfo{PresentCPUs: 16, OnlineCPUs: 12, CPUsIsolated: true}, true, "INFO", "isolcpus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins, ok := cpuOfflineInsight(tc.cpu)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ins.Level != tc.wantLvl {
				t.Errorf("level=%q want %q (%q)", ins.Level, tc.wantLvl, ins.Message)
			}
			if !strings.Contains(ins.Message, tc.wantMsg) {
				t.Errorf("message %q missing %q", ins.Message, tc.wantMsg)
			}
			if ins.Check != "CPU Load" {
				t.Errorf("check=%q want CPU Load", ins.Check)
			}
		})
	}
}
