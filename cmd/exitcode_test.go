package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestRecordExitCodeRaisesMonotonically(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	recordExitCode(1)
	if pendingExitCode != 1 {
		t.Fatalf("after WARN: got %d, want 1", pendingExitCode)
	}
	recordExitCode(2)
	if pendingExitCode != 2 {
		t.Fatalf("after CRIT: got %d, want 2", pendingExitCode)
	}
	// A lower code must not lower the recorded worst severity.
	recordExitCode(1)
	if pendingExitCode != 2 {
		t.Fatalf("WARN must not override CRIT: got %d, want 2", pendingExitCode)
	}
}

func TestRecordWorstInsight(t *testing.T) {
	cases := []struct {
		name     string
		insights []models.Insight
		want     int
	}{
		{"empty", nil, 0},
		{"info only", []models.Insight{{Level: "INFO"}}, 0},
		{"warn", []models.Insight{{Level: "INFO"}, {Level: "WARN"}}, 1},
		{"crit wins", []models.Insight{{Level: "WARN"}, {Level: "CRIT"}, {Level: "WARN"}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordWorstInsight(tc.insights)
			if pendingExitCode != tc.want {
				t.Errorf("got %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}

// TestServicesGatesExitCode is a regression guard for the bug where ApplyThresholds
// had no case for *models.ServicesInfo: `dsd services` rendered per-service CRIT/WARN
// icons but always exited 0 because recordResultSeverity produced zero insights. A
// CI job gating on `dsd services`'s exit code got a silent pass while a configured
// service was down or returning 5xx.
func TestServicesGatesExitCode(t *testing.T) {
	cases := []struct {
		name string
		info *models.ServicesInfo
		want int
	}{
		{"all reachable and OK", &models.ServicesInfo{Results: []models.ServiceResult{
			{Name: "web", Host: "127.0.0.1", Port: 80, Reachable: true, Status: "OK"},
		}}, 0},
		{"unreachable service", &models.ServicesInfo{Results: []models.ServiceResult{
			{Name: "db", Host: "127.0.0.1", Port: 5432, Reachable: false, Status: "WARN"},
		}}, 1},
		{"5xx service", &models.ServicesInfo{Results: []models.ServiceResult{
			{Name: "api", Host: "127.0.0.1", Port: 443, Reachable: true, StatusCode: 503, Status: "CRIT"},
		}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordResultSeverity([]runner.Result{{Name: "Services", Data: tc.info}})
			if pendingExitCode != tc.want {
				t.Errorf("got exit %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}

// TestKVMGatesExitCode is a regression guard for cmd-08-03: runKVM never
// called recordResultSeverity, so `dsd kvm` always exited 0 even with a
// CRASHED VM — a CI job gating on it got a silent pass.
func TestKVMGatesExitCode(t *testing.T) {
	cases := []struct {
		name string
		info *models.KVMInfo
		want int
	}{
		{"not detected", &models.KVMInfo{Detected: false}, 0},
		{"detected, no VMs", &models.KVMInfo{Detected: true}, 0},
		{"enum failed", &models.KVMInfo{Detected: true, Status: "enum-failed", StatusReason: "virsh list failed"}, 1},
		{"crashed VM", &models.KVMInfo{Detected: true, VMs: []models.KVMVM{
			{Name: "web1", State: models.KVMCrashed},
		}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordResultSeverity([]runner.Result{{Name: "KVM", Data: tc.info}})
			if pendingExitCode != tc.want {
				t.Errorf("got exit %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}

// TestKVMGuestGatesExitCode is a regression guard for cmd-08-04: runKVMGuest
// never recorded severity from analysis.KVMGuestInsights (the same source
// kvmGuestConcerns scores the printed verdict from), so `dsd kvm-guest`
// always exited 0 even with CRIT-level guest findings.
func TestKVMGuestGatesExitCode(t *testing.T) {
	cases := []struct {
		name string
		info models.KVMGuestInfo
		want int
	}{
		{"not a guest", models.KVMGuestInfo{IsGuest: false}, 0},
		{"clean guest", models.KVMGuestInfo{IsGuest: true}, 0},
		{"emulated NIC", models.KVMGuestInfo{IsGuest: true, EmulatedNICs: []string{"eth0"}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordWorstInsight(analysis.KVMGuestInsights(tc.info))
			if pendingExitCode != tc.want {
				t.Errorf("got exit %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}

func TestRecordCVEResultSeverity(t *testing.T) {
	cases := []struct {
		name string
		r    *models.CVEResult
		want int
	}{
		{"nil", nil, 0},
		{"patched", &models.CVEResult{Status: models.CVEPatched}, 0},
		{"not affected", &models.CVEResult{Status: models.CVENotAffected}, 0},
		{"unknown stays quiet", &models.CVEResult{Status: models.CVEUnknown}, 0},
		{"vulnerable low → WARN", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "5.5"}, 1},
		{"vulnerable high CVSS → CRIT", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "9.8"}, 2},
		{"vulnerable + KEV → CRIT", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "5.0", KnownExploited: true}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordCVEResultSeverity(tc.r)
			if pendingExitCode != tc.want {
				t.Errorf("got %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}
