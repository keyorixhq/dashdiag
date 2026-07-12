package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the container (Docker/K8s) and drive (NVMe/SATA)
// heuristics — the WARN/CRIT verdicts for the most operationally painful
// failures (crash loops, OOM kills, socket mounts, failing drives). Pure
// functions (models in, []Insight out). Reuses assertLevel/hasLevel from
// heuristics_test.go.

// ── Kubernetes ────────────────────────────────────────────────────────────────

func TestCheckK8s(t *testing.T) {
	tests := []struct {
		name string
		info models.K8sInfo
		want string
	}{
		{"not detected yields nothing", models.K8sInfo{Detected: false, CrashLooping: 5}, ""},
		// Detected but the API never answered — must surface as INFO, not a silent
		// healthy cluster (the false-OK: kubectl present, API down → all counts 0).
		{"detected but API unreachable is INFO", models.K8sInfo{Detected: true, APIReachable: false}, "INFO"},
		{"nodes not ready is CRIT", models.K8sInfo{Detected: true, APIReachable: true, NodesNotReady: 1}, "CRIT"},
		{"crash looping is CRIT", models.K8sInfo{Detected: true, APIReachable: true, CrashLooping: 2}, "CRIT"},
		{"pods not ready is WARN", models.K8sInfo{Detected: true, APIReachable: true, PodsNotReady: 1}, "WARN"},
		{"pending is WARN", models.K8sInfo{Detected: true, APIReachable: true, Pending: 1}, "WARN"},
		{"high restarts is WARN", models.K8sInfo{Detected: true, APIReachable: true, HighRestarts: 1}, "WARN"},
		{"unknown status is WARN", models.K8sInfo{Detected: true, APIReachable: true, UnknownStatus: 1}, "WARN"},
		{
			name: "node pressure condition is CRIT",
			info: models.K8sInfo{Detected: true, APIReachable: true, Nodes: []models.K8sNodeInfo{
				{Name: "n1", Conditions: map[string]string{"DiskPressure": "True"}},
			}},
			want: "CRIT",
		},
		{
			name: "reachable, node Ready=True is fine",
			info: models.K8sInfo{Detected: true, APIReachable: true, Nodes: []models.K8sNodeInfo{
				{Name: "n1", Conditions: map[string]string{"Ready": "True"}},
			}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkK8s(tt.info), tt.want)
		})
	}
}

// TestCheckK8sWiresOSLayer proves checkK8s actually delegates to
// CheckK8sOSLayer when K8sInfo.OSLayer is populated — the table-driven cases
// above never set OSLayer, so that branch (and its downstream insight) was
// otherwise unreached.
func TestCheckK8sWiresOSLayer(t *testing.T) {
	info := models.K8sInfo{
		Detected: true, APIReachable: true,
		OSLayer: &models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: false},
	}
	insights := checkK8s(info)
	if !hasInsightMsg(insights, "CRIT", "IP forwarding disabled") {
		t.Errorf("expected the OS-layer IP-forwarding CRIT to be wired through checkK8s, got %+v", insights)
	}
}

// TestK8sUnknownStatusInsight_StatefulSetHint pins Spec 23f's key distinction: a
// StatefulSet-owned pod stuck Unknown won't be rescheduled until deleted (unlike a
// Deployment/ReplicaSet pod, which the controller replaces elsewhere), so the hint
// text must call that out by name.
func TestK8sUnknownStatusInsight_StatefulSetHint(t *testing.T) {
	info := models.K8sInfo{
		Detected: true, APIReachable: true, UnknownStatus: 1,
		Pods: []models.K8sPodInfo{
			{Namespace: "default", Name: "postgres-0", Status: "Unknown",
				NodeName: "worker-03", OwnerKind: "StatefulSet", OwnerName: "postgres"},
		},
	}
	insights := checkK8s(info)
	var msg string
	var hints []string
	for _, ins := range insights {
		if strings.Contains(ins.Message, "Unknown status") {
			msg = ins.Message
			hints = ins.Hints
		}
	}
	if msg == "" {
		t.Fatalf("no Unknown-status insight found in %+v", insights)
	}
	joined := strings.Join(hints, "\n")
	if !strings.Contains(joined, "StatefulSet/postgres") || !strings.Contains(joined, "will NOT reschedule") {
		t.Errorf("hints missing StatefulSet-not-rescheduled callout: %v", hints)
	}
	if !strings.Contains(joined, "worker-03") {
		t.Errorf("hints missing node name: %v", hints)
	}
}

// ── Docker containers ─────────────────────────────────────────────────────────

func TestCheckDockerContainers(t *testing.T) {
	tests := []struct {
		name string
		info models.DockerInfo
		want string
	}{
		{"empty is clean", models.DockerInfo{}, ""},
		{"crash looping is CRIT", models.DockerInfo{CrashLooping: []string{"web"}}, "CRIT"},
		{"unhealthy is WARN", models.DockerInfo{Unhealthy: []string{"db"}}, "WARN"},
		// Raw stopped count no longer warns — the WARN now counts only failed-exit
		// containers (see TestDockerStoppedCleanExitNotFlagged); clean-exit oneshots
		// are expected. A non-zero-exit container is the real signal.
		{"6 clean-stopped (no exit codes) is fine", models.DockerInfo{Stopped: 6}, ""},
		{"6 failed-exit stopped is WARN", models.DockerInfo{Containers: []models.ContainerInfo{
			{State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1},
			{State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 137},
		}}, "WARN"},
		{"oom events is CRIT", models.DockerInfo{OOMEvents: 1}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerContainers(tt.info), tt.want)
		})
	}
}

// ── Docker security ───────────────────────────────────────────────────────────

func TestCheckDockerSecurity(t *testing.T) {
	tests := []struct {
		name string
		info models.DockerInfo
		want string
	}{
		{"empty is clean", models.DockerInfo{}, ""},
		{"docker.sock mounted is CRIT", models.DockerInfo{SocketMountedCount: 1}, "CRIT"},
		{"running as root is WARN", models.DockerInfo{RunningAsRootCount: 2}, "WARN"},
		{"plaintext secrets is WARN", models.DockerInfo{ContainersWithSecrets: 1}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerSecurity(tt.info), tt.want)
		})
	}
}

// TestCheckDockerSecurityNamesOffendingContainers exercises the name-collection
// loops (SocketMountedCount/ContainersWithSecrets paired with a populated
// Containers slice) — the table-driven cases above set only the summary counts,
// never the per-container flags, so the "for _, c := range d.Containers { if
// c.DockerSocketMounted ... }" / PlaintextSecrets loop bodies were never entered.
func TestCheckDockerSecurityNamesOffendingContainers(t *testing.T) {
	info := models.DockerInfo{
		SocketMountedCount:    1,
		ContainersWithSecrets: 1,
		Containers: []models.ContainerInfo{
			{Name: "safe", State: "running"},
			{Name: "leaky-socket", DockerSocketMounted: true},
			{Name: "leaky-secrets", PlaintextSecrets: []string{"DB_PASSWORD"}},
		},
	}
	insights := checkDockerSecurity(info)
	var socketMsg, secretsMsg string
	for _, ins := range insights {
		switch {
		case strings.Contains(ins.Message, "docker.sock mounted"):
			socketMsg = ins.Message
		case strings.Contains(ins.Message, "plaintext secrets"):
			secretsMsg = ins.Message
		}
	}
	if !strings.Contains(socketMsg, "leaky-socket") {
		t.Errorf("expected docker.sock insight to name leaky-socket, got %q", socketMsg)
	}
	if !strings.Contains(secretsMsg, "leaky-secrets") {
		t.Errorf("expected plaintext-secrets insight to name leaky-secrets, got %q", secretsMsg)
	}
}

// ── NVMe / SATA drive health ──────────────────────────────────────────────────

func TestCheckNVMe(t *testing.T) {
	// These fixtures represent drives whose SMART log was read (they carry real
	// values), so mark them SmartRead — otherwise they trip the new "SMART not
	// read" INFO. The unread case is covered explicitly below.
	nvme := func(d models.NVMeDevice) models.NVMeInfo {
		d.SmartRead = true
		return models.NVMeInfo{Devices: []models.NVMeDevice{d}}
	}
	// SATA fixtures with explicit attributes represent drives whose SMART verdict
	// was read; mark SmartRead so they don't trip the "SMART not read" INFO. The
	// unread case is covered explicitly below.
	sata := func(d models.SATADevice) models.NVMeInfo {
		d.SmartRead = true
		return models.NVMeInfo{SATADevices: []models.SATADevice{d}}
	}
	tests := []struct {
		name string
		info models.NVMeInfo
		want string
	}{
		{"no drives is clean", models.NVMeInfo{}, ""},
		{"healthy nvme is clean", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 10, TempC: 40}), ""},
		{"nvme critical warning is CRIT", nvme(models.NVMeDevice{Name: "nvme0", CriticalWarning: 1}), "CRIT"},
		{"nvme media errors is CRIT", nvme(models.NVMeDevice{Name: "nvme0", MediaErrors: 5}), "CRIT"},
		{"nvme spare below threshold is CRIT", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 5, SpareThresholdPct: 10}), "CRIT"},
		// 0% available spare is the worst reading and must CRIT (the old `> 0`
		// guard silently dropped it). Threshold>0 proves the SMART log was read.
		{"nvme spare exhausted (0%) is CRIT", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 0, SpareThresholdPct: 10}), "CRIT"},
		// Threshold zero → spare not evaluated, stay silent (no false spare CRIT).
		{"nvme spare unread (0/0) is clean", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 0, SpareThresholdPct: 0}), ""},
		// Device detected via sysfs but SMART log never read (no nvme-cli) → INFO,
		// not a confident "healthy". Note: no SmartRead, so not via the nvme() helper.
		{"nvme smart unread is INFO", models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "nvme0"}}}, "INFO"},
		{"nvme spare low is WARN", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 15}), "WARN"},
		{"nvme wear >=90 is WARN", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 95}), "WARN"},
		{"nvme hot is WARN", nvme(models.NVMeDevice{Name: "nvme0", TempC: 75}), "WARN"},
		{"sata smart fail is CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: false}), "CRIT"},
		{"sata uncorrectable is CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, UncorrectableErrors: 1}), "CRIT"},
		{"sata reallocated is WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, ReallocatedSectors: 4}), "WARN"},
		// smartctl errored (e.g. non-root permission) → health UNVERIFIED → INFO,
		// NOT silently dropped. A silent drop let the inline summary count the drive
		// as healthy — the non-root false-OK validated on pve01. Must never CRIT.
		{"sata read error is INFO not silent/CRIT", sata(models.SATADevice{Name: "/dev/sda", SmartOK: false, Error: "permission denied"}), "INFO"},
		// Realistic non-root SATA: smartctl failed, SmartRead false → INFO, never OK.
		{"sata smartctl-failed non-root is INFO", models.NVMeInfo{SATADevices: []models.SATADevice{{Name: "/dev/sda", Type: "sata", SmartRead: false, Error: "smartctl failed"}}}, "INFO"},
		// Detected but SMART never reported (controller/USB bridge/virtual disk) →
		// INFO, NOT a confident "drive may be failing" CRIT. No SmartRead → not via
		// the sata() helper.
		{"sata smart unread is INFO", models.NVMeInfo{SATADevices: []models.SATADevice{{Name: "/dev/sda", Type: "sata", SmartOK: false}}}, "INFO"},
		// Power-on-hours is age, not wear: a healthy long-lived drive must NOT WARN
		// (real endurance is PercentageUsed/spare for NVMe, reallocated sectors for SATA).
		{"nvme high power-on-hours healthy is INFO not WARN", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 10, TempC: 40, PowerOnHours: 40000}), "INFO"},
		{"sata high power-on-hours healthy is INFO not WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, PowerOnHours: 50000}), "INFO"},
		// TRIAGE §L — VMware virtual NVMe returns garbage-but-parseable SMART:
		// the real captured values (temp 11758.85°C, spare 1% vs threshold 100%,
		// counters ~2^63). Before the plausibility guard this fired a false
		// "near end of life" CRIT. It must now be WARN ("implausible … rejected"),
		// NOT CRIT, and the spare/temp gates must not score.
		{"nvme implausible vmware garbage is WARN not CRIT", nvme(models.NVMeDevice{
			Name: "nvme0", TempC: 11758.85, AvailableSparePct: 1, SpareThresholdPct: 100,
			PowerOnHours: 1106804644422573096, PowerCycles: 184467440737095516,
		}), "WARN"},
		// Individual implausibility triggers — each rejects on its own.
		{"nvme impossible temp alone is WARN", nvme(models.NVMeDevice{Name: "nvme0", TempC: 11758}), "WARN"},
		{"nvme spare over 100 is WARN", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 150, SpareThresholdPct: 100}), "WARN"},
		{"nvme overflow counters is WARN", nvme(models.NVMeDevice{Name: "nvme0", PowerOnHours: 1106804644422573096}), "WARN"},
		{"nvme spare threshold over 100 is WARN", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 50, SpareThresholdPct: 150}), "WARN"},
		{"nvme overflow power cycles is WARN", nvme(models.NVMeDevice{Name: "nvme0", PowerCycles: 1106804644422573096}), "WARN"},
		// Plausibility boundaries must NOT reject real drives: a genuinely failing
		// drive (spare below a real threshold, hot but in-range) still CRITs/ WARNs.
		{"nvme real failing drive still CRIT", nvme(models.NVMeDevice{Name: "nvme0", TempC: 45, AvailableSparePct: 5, SpareThresholdPct: 10, PowerOnHours: 40000}), "CRIT"},
		{"nvme high-but-real temp still WARN", nvme(models.NVMeDevice{Name: "nvme0", TempC: 80}), "WARN"},
		// AWS EBS / virtual NVMe: SMART read succeeds but every field is a not-reported
		// sentinel — temp -273°C (0 Kelvin), all else 0. Pre-fix this tripped the
		// implausible-temp gate → a fleet-wide false WARN on every EC2 instance. Must
		// now be INFO ("no real SMART telemetry"), NOT WARN, and NOT a silent healthy.
		// Found live on a Graviton2 t4g.small with EBS volumes.
		{"nvme ebs sentinel (0K temp, all-zero) is INFO not WARN", nvme(models.NVMeDevice{
			Name: "nvme0", TempC: -273, AvailableSparePct: 0, SpareThresholdPct: 0, PercentageUsed: 0,
		}), "INFO"},
		// A real garbage temp (not the 0K sentinel) still rejects as implausible WARN.
		{"nvme garbage cold temp -100 still WARN", nvme(models.NVMeDevice{Name: "nvme0", TempC: -100}), "WARN"},
		// TRIAGE §L §E.3 SATA sibling — garbage-but-parseable SMART on a virtual /
		// USB-bridged SATA controller, or a vendor-encoded raw ATA attribute read
		// as a plain count. Before the SATA plausibility guard, attr 198 raw →
		// UncorrectableErrors fired a false "data loss risk" CRIT. It must now be
		// WARN ("implausible … rejected"), NOT CRIT, and no field may score.
		{"sata implausible garbage is WARN not CRIT", sata(models.SATADevice{
			Name: "/dev/sda", Type: "sata", SmartOK: true, TempC: 11758,
			UncorrectableErrors: 2147483647, ReallocatedSectors: 2147483647, PowerOnHours: 1106804644422573096,
		}), "WARN"},
		// Each SATA implausibility trigger rejects on its own.
		{"sata impossible temp alone is WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, TempC: 9000}), "WARN"},
		{"sata overflow uncorrectable is WARN not CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, UncorrectableErrors: 200000000}), "WARN"},
		{"sata overflow reallocated sectors is WARN not CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, ReallocatedSectors: 200000000}), "WARN"},
		{"sata overflow pending sectors is WARN not CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, PendingSectors: 200000000}), "WARN"},
		{"sata overflow power-on-hours is WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, PowerOnHours: 1106804644422573096}), "WARN"},
		// A drive that *reports* SMART-failed but whose attributes are garbage is
		// treated as health-unverified (WARN), not a confident failure CRIT — the
		// device is an unreliable narrator of its own state.
		{"sata smart-fail with garbage attrs is WARN not CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: false, TempC: 9000}), "WARN"},
		// Boundaries must NOT reject real drives: a genuinely failing SATA drive
		// (real uncorrectable count, hot but in-range) still CRITs / WARNs.
		{"sata real uncorrectable still CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, UncorrectableErrors: 3, TempC: 40}), "CRIT"},
		{"sata high-but-real temp still WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, TempC: 58}), "WARN"},
		{"sata real failing drive (smart fail) still CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: false, TempC: 40}), "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkNVMe(tt.info), tt.want)
		})
	}
}
