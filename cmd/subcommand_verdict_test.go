package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// GUARD A for the per-subcommand summaries — DD-FOLLOWUPS-1, DEFECT-CLASSES.md
// C1. Each one-collector subcommand (dsd cpu, db, disk, docker, ...) used to
// derive its closing "<X> healthy. Checks passed" line from its own per-section
// counts, so a run whose collector had errored, or whose check came back
// Unverified, still printed healthy. Every renderer below is handed a fixture
// that is locally clean (its own counts are zero — the old code printed healthy
// for exactly this) together with a verdict that must not read healthy: the
// closing line has to say "Not fully verified" and must not claim a pass.
//
// The structural counterpart is TestGuardB_NoSecondVerdictDerivation in
// internal/render, which now covers all of cmd/ and fails if a subcommand spells
// the all-clear wording itself.

type subcommandRenderer struct {
	name   string
	render func(v render.VerdictInfo)
}

func subcommandRenderers() []subcommandRenderer {
	ctx := context.Background()
	plain := output.ModePlain
	return []subcommandRenderer{
		{"cpu", func(v render.VerdictInfo) {
			printCPUReport(ctx, &models.CPUInfo{NumCPU: 4, UsagePct: 10}, nil, nil, nil, plain, 0, v)
		}},
		{"db", func(v render.VerdictInfo) { printDBVerdict(nil, plain, v) }},
		{"disk", func(v render.VerdictInfo) { printDiskReport(&models.DiskInfo{}, nil, plain, 0, false, v) }},
		{"docker", func(v render.VerdictInfo) {
			printDockerReport(&models.DockerInfo{
				Available: true, Runtime: "docker", TotalContainers: 1, RunningCount: 1,
				Containers: []models.ContainerInfo{{Name: "web", State: "running"}},
			}, plain, 0, v)
		}},
		{"gpu", func(v render.VerdictInfo) {
			printGPUReport(&models.GPUInfo{Devices: []models.GPUDevice{{Name: "RTX 3070", TempC: 50, MemTotalMB: 8192}}}, 0, plain, v)
		}},
		{"k8s", func(v render.VerdictInfo) {
			printK8sReport(&models.K8sInfo{Detected: true, APIReachable: true, KubeBin: "kubectl"}, plain, 0, v)
		}},
		{"kvm", func(v render.VerdictInfo) { printKVMReport(&models.KVMInfo{Detected: true}, 0, plain, v) }},
		{"logs", func(v render.VerdictInfo) { printLogsReport(&models.LogsInfo{}, plain, time.Second, time.Hour, v) }},
		{"net", func(v render.VerdictInfo) {
			printNetReport(&models.NetworkInfo{PrimaryInterface: "eth0", Interfaces: []models.InterfaceInfo{
				{Name: "eth0", IP: "10.0.0.5", Up: true},
			}}, plain, 0, platform.ContainerContext{}, v)
		}},
		{"processes", func(v render.VerdictInfo) { printProcessesReport(ctx, &models.ProcessInfo{}, plain, 0, v) }},
		{"pve", func(v render.VerdictInfo) {
			printPVEReport(&models.PVEInfo{IsPVE: true, APIReachable: true}, false, 0, plain, v)
		}},
		{"security", func(v render.VerdictInfo) {
			clean := models.SecurityInfo{AuditRules: -1, SSHStrictModes: true}
			printSecurityReport(&clean, nil, plain, 0, v)
		}},
		{"steamos", func(v render.VerdictInfo) { printSteamOSReport(&models.SteamOSInfo{Detected: true}, 0, plain, v) }},
		{"thermal", func(v render.VerdictInfo) {
			printThermalReport(&models.ThermalInfo{Source: "hwmon", CPUTempC: 55}, plain, 0, v)
		}},
	}
}

func erroredVerdict() render.VerdictInfo {
	return render.Verdict([]runner.Result{{Name: "X", Err: errors.New("collector failed")}}, nil)
}

func unverifiedVerdict() render.VerdictInfo {
	return render.Verdict(nil, []models.Insight{{Level: "INFO", Check: "X", Message: "could not read", Unverified: true}})
}

func TestGuardA_SubcommandsNeverHealthyWhenNotVerified(t *testing.T) {
	verdicts := []struct {
		name string
		v    render.VerdictInfo
	}{
		{"errored collector", erroredVerdict()},
		{"unverified insight", unverifiedVerdict()},
	}
	for _, sc := range subcommandRenderers() {
		// Control: the fixture is clean, so the clean verdict must still read healthy —
		// otherwise the cases below would pass for the wrong reason.
		t.Run(sc.name+"/clean", func(t *testing.T) {
			out := captureStdout(t, func() { sc.render(cleanVerdict()) })
			if !strings.Contains(out, "healthy") {
				t.Fatalf("clean fixture should read healthy, got:\n%s", out)
			}
		})
		for _, vc := range verdicts {
			t.Run(sc.name+"/"+vc.name, func(t *testing.T) {
				out := captureStdout(t, func() { sc.render(vc.v) })
				low := strings.ToLower(out)
				if strings.Contains(low, "checks passed") || strings.Contains(low, " healthy.") {
					t.Errorf("%s printed an all-clear for a run that could not verify itself:\n%s", sc.name, out)
				}
				if !strings.Contains(out, "Not fully verified") {
					t.Errorf("%s must say the run was not fully verified, got:\n%s", sc.name, out)
				}
			})
		}
	}
}

// The exit code follows the same floor: an errored collector or an Unverified
// insight is at least WARN (1), never 0, and never outranks a real CRIT.
func TestRecordResultSeverityFloorsOnErroredCollector(t *testing.T) {
	saved := pendingExitCode
	t.Cleanup(func() { pendingExitCode = saved })

	pendingExitCode = 0
	v := recordResultSeverity([]runner.Result{{Name: "Docker", Data: &models.DockerInfo{Available: true}, Err: errors.New("daemon hiccup")}})
	if v.Clean() {
		t.Fatalf("an errored collector must not yield a clean verdict: %+v", v)
	}
	if pendingExitCode != 1 {
		t.Errorf("errored collector: exit code = %d, want 1 (WARN floor)", pendingExitCode)
	}
}

func TestSubcommandSummaryWording(t *testing.T) {
	if lvl, txt := cleanVerdict().SubcommandSummary("Disk"); lvl != "ok" || txt != "Disk healthy. Checks passed" {
		t.Errorf("clean: got %q %q", lvl, txt)
	}
	lvl, txt := unverifiedVerdict().SubcommandSummary("Disk")
	if lvl != "warn" || !strings.Contains(txt, "Not fully verified: 1 check could not run") || !strings.Contains(txt, "re-run with sudo") {
		t.Errorf("floored: got %q %q", lvl, txt)
	}
	crit := render.Verdict(nil, []models.Insight{{Level: "CRIT", Check: "X"}})
	if lvl, txt := crit.SubcommandSummary("Disk"); lvl != "warn" || strings.Contains(txt, "healthy") {
		t.Errorf("crit: got %q %q", lvl, txt)
	}
}
