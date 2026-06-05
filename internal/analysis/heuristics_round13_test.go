package analysis

import (
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// Round-13: the ApplyThresholds entry point (pre-scan, SELinux injection, error
// path), the remaining checkCPU branches (steal/iowait/run-queue), and the small
// helpers that were at 0% — exercised through their callers.

func TestApplyThresholds(t *testing.T) {
	results := []runner.Result{
		{Name: "CPU", Data: models.CPUInfo{UsagePct: 50, LoadPct: 30}},
		{Name: "Packages", Data: models.PackagesInfo{PackageManager: "dnf", SecurityUpdates: 1, CriticalUpdates: 1}},
		{Name: "KernelSec", Data: models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}},
		// Pointer form so ApplyThresholds can inject SELinuxEnforcing before dispatch.
		{Name: "Systemd", Data: &models.SystemdInfo{Available: true, FailedUnits: []string{"nginx.service"}}},
		{Name: "Broken", Err: errors.New("collector exploded")},
	}
	insights := ApplyThresholds(results, defaultThresh, platform.EnvBareMetal, platform.ContainerContext{})
	if len(insights) == 0 {
		t.Fatal("expected insights")
	}
	if !hasInsightMsg(insights, "INFO", "could not run") {
		t.Errorf("error result should become an INFO insight, got %+v", insights)
	}
	if !hasInsightMsg(insights, "CRIT", "has failed") {
		t.Errorf("systemd failed unit should be CRIT, got %+v", insights)
	}
}

func TestCheckCPU_StealIOwaitRunQueue(t *testing.T) {
	tests := []struct {
		name string
		cpu  models.CPUInfo
		want string
	}{
		{"severe steal is CRIT", models.CPUInfo{StealPct: 25}, "CRIT"},
		{"moderate steal is WARN", models.CPUInfo{StealPct: 15}, "WARN"},
		{"severe iowait is CRIT", models.CPUInfo{IOwaitPct: 45}, "CRIT"},
		{"moderate iowait is WARN", models.CPUInfo{IOwaitPct: 25}, "WARN"},
		{"run-queue 4x saturated is CRIT", models.CPUInfo{NumCPU: 2, RunQueue: 8}, "CRIT"},
		{"run-queue 2x saturated is WARN", models.CPUInfo{NumCPU: 2, RunQueue: 4}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkCPU(tt.cpu, defaultThresh), tt.want)
		})
	}
}

// TestCheckSystemd_SlowBootAndSELinux covers slowBootFix (known offender unit)
// and unitBaseName (the SELinux-enforcing hint on a failed unit).
func TestCheckSystemd_SlowBootAndSELinux(t *testing.T) {
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true, SlowUnits: []models.SlowUnit{{Name: "snapd.service", Duration: 15}}}), "WARN")
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true, FailedUnits: []string{"my-app@1.service"}, SELinuxEnforcing: true}), "CRIT")
}

// TestCheckKernelSecurity_AVCSamples covers extractAVCProcessNames via the AVC
// sample hint path in checkSELinuxDenials.
func TestCheckKernelSecurity_AVCSamples(t *testing.T) {
	mac := models.KernelSecurityInfo{
		SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: 5,
		SELinuxAVCSamples: []string{`type=AVC msg=audit(1): avc: denied { read } comm="httpd" name="x"`},
	}
	assertLevel(t, checkKernelSecurity(mac, defaultThresh), "WARN")
}

// TestCheckSecurity_SELinuxGroups covers the grouped-AVC hint path including
// truncateSELinux on a long fix command.
func TestCheckSecurity_SELinuxGroups(t *testing.T) {
	sec := models.SecurityInfo{
		SSHStrictModes: true, SSHClientAliveInterval: 300,
		SELinuxDenials: 15, SELinuxMode: "enforcing",
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "init_t", Tcontext: "container_t", Tclass: "file", Count: 5, FixCmd: strings.Repeat("x", 120)},
		},
	}
	if !hasInsightMsg(checkSecurity(sec), "WARN", "SELinux denials") {
		t.Errorf("expected SELinux denials WARN with grouped AVC hints")
	}
}

// TestCheckK8sPodHealth_PreviousLogs covers k8sFirstLine via the crash-loop
// previous-log hint.
func TestCheckK8sPodHealth_PreviousLogs(t *testing.T) {
	k := models.K8sInfo{
		Detected: true, CrashLooping: 1,
		Pods: []models.K8sPodInfo{{Status: "CrashLoopBackOff", Namespace: "default", Name: "web", PreviousLogs: "panic: nil deref\ngoroutine 1"}},
	}
	assertLevel(t, checkK8sPodHealth(k), "CRIT")
}

func TestCheckSecurityDrift_Exported(t *testing.T) {
	assertLevel(t, CheckSecurityDrift(nil), "")
	assertLevel(t, CheckSecurityDrift(&baseline.SecurityDiff{NewSUIDs: []string{"/usr/local/bin/x"}}), "CRIT")
}

func TestCheckSRIOV_WithVFs(t *testing.T) {
	// SR-IOV has no failure state — active VFs are healthy (nil), but the device
	// loop should run without panicking.
	assertLevel(t, checkSRIOV(models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 2}}}), "")
	assertLevel(t, checkSRIOV(models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 0}}}), "")
}

// TestCheckDisk_Boot covers the /boot package-manager-specific cleanup hints.
func TestCheckDisk_Boot(t *testing.T) {
	for _, pm := range []string{"dnf", "apt", "zypper", "pacman", ""} {
		th := defaultThresh
		th.PackageManager = pm
		disk := models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/boot", Device: "/dev/sda1", UsedPct: 95}}}
		if !hasLevel(checkDisk(disk, th), "CRIT") {
			t.Errorf("pm=%q: expected /boot CRIT", pm)
		}
	}
}

func TestCheckDiskExtras_ZFS(t *testing.T) {
	assertLevel(t, checkDiskExtras(models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "DEGRADED"}}}), "CRIT")
	assertLevel(t, checkDiskExtras(models.DiskInfo{ZFSPools: []models.ZFSPool{{Name: "tank", State: "ONLINE", ScrubAgeDays: -1}}}), "INFO")
}

func TestCheckDockerContainers_ArchMismatch(t *testing.T) {
	d := models.DockerInfo{
		ArchMismatchCount: 1, HostArch: "amd64",
		Containers: []models.ContainerInfo{{Name: "app", ArchMismatch: true, ImageArch: "arm64"}},
	}
	assertLevel(t, checkDockerContainers(d), "WARN")
}
