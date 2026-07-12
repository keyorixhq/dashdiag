package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintK8sOSLayer guards the deep-only OS-layer section (#684): a clean
// K8sOSLayer must read "No OS-layer issues", and a genuine fault (IP
// forwarding disabled, checked and confirmed off) must render CRIT via the
// shared analysis.CheckK8sOSLayer heuristic, not a hand-duplicated condition.
func TestPrintK8sOSLayer(t *testing.T) {
	clean := captureStdout(t, func() { printK8sOSLayer(models.K8sOSLayer{}, output.ModePlain) })
	if !strings.Contains(clean, "No OS-layer issues") {
		t.Errorf("a clean OS layer should say so, got:\n%s", clean)
	}

	ipForwardOff := captureStdout(t, func() {
		printK8sOSLayer(models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: false}, output.ModePlain)
	})
	if !strings.Contains(ipForwardOff, "CRIT") || !strings.Contains(ipForwardOff, "IP forwarding disabled") {
		t.Errorf("IP forwarding confirmed disabled should render CRIT, got:\n%s", ipForwardOff)
	}

	// WARN branch: firewalld active without masquerade while flannel is in use.
	warnOut := captureStdout(t, func() {
		printK8sOSLayer(models.K8sOSLayer{FirewalldChecked: true, FlannelInUse: true, FirewalldMasquOK: false}, output.ModePlain)
	})
	if !strings.Contains(warnOut, "WARN") || !strings.Contains(warnOut, "masquerade") {
		t.Errorf("firewalld without masquerade should render WARN, got:\n%s", warnOut)
	}

	// INFO (default) branch: OS-layer checks limited by running non-root.
	infoOut := captureStdout(t, func() {
		printK8sOSLayer(models.K8sOSLayer{OSLayerNeedsRoot: true}, output.ModePlain)
	})
	if !strings.Contains(infoOut, "INFO") || !strings.Contains(infoOut, "run as root") {
		t.Errorf("a root-limited check should render INFO, got:\n%s", infoOut)
	}
}

// TestPrintK8sSummary exercises every concern branch individually — each is an
// independent `if info.Field > 0` in printK8sSummary, so a future field that
// stops being wired in would silently vanish from the summary instead of
// failing loudly (the cmd verdict tally drift class, #275). The existing
// printK8sReport tests only exercise the "no concerns" branch (empty info),
// leaving this whole tally untested.
func TestPrintK8sSummary(t *testing.T) {
	cases := []struct {
		name string
		info *models.K8sInfo
		want string
	}{
		{"nodes not ready", &models.K8sInfo{NodesNotReady: 2}, "2 node(s) not ready"},
		{"crash looping", &models.K8sInfo{CrashLooping: 1}, "1 pod(s) crash looping"},
		{"pods not ready", &models.K8sInfo{PodsNotReady: 3}, "3 pod(s) not ready"},
		{"pending", &models.K8sInfo{Pending: 1}, "1 pod(s) pending"},
		{"unknown status", &models.K8sInfo{UnknownStatus: 2}, "2 pod(s) unknown status"},
		{"high restarts", &models.K8sInfo{HighRestarts: 4}, "4 pod(s) high restarts"},
		{"workloads down", &models.K8sInfo{WorkloadsDown: 1}, "1 workload(s) degraded"},
		{"pvcs not bound", &models.K8sInfo{PVCsNotBound: 2}, "2 PVC(s) not bound"},
		{"events", &models.K8sInfo{Events: []models.K8sEvent{{}}}, "1 warning event(s)"},
		{"os-layer issue", &models.K8sInfo{OSLayer: &models.K8sOSLayer{IPForwardChecked: true, IPForwardEnabled: false}}, "OS-layer issue(s)"},
	}
	for _, c := range cases {
		out := captureStdout(t, func() { printK8sSummary(c.info, "", output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printK8sSummary output missing %q, got:\n%s", c.name, c.want, out)
		}
		if strings.Contains(out, "Cluster healthy") {
			t.Errorf("%s: must not read healthy when a concern is present, got:\n%s", c.name, out)
		}
	}

	healthy := captureStdout(t, func() { printK8sSummary(&models.K8sInfo{}, "", output.ModePlain) })
	if !strings.Contains(healthy, "Cluster healthy") {
		t.Errorf("no concerns should read healthy, got:\n%s", healthy)
	}
}

// TestK8sPodNeedsAttention pins the "problem pods" callout logic extracted
// from printK8sReport — each condition is independently tested so a future
// change to one can't silently stop flagging another (the cmd verdict tally
// drift class, #275).
func TestK8sPodNeedsAttention(t *testing.T) {
	cases := []struct {
		name string
		pod  models.K8sPodInfo
		want bool
	}{
		{"healthy running", models.K8sPodInfo{Status: "Running", Ready: "1/1"}, false},
		{"completed job", models.K8sPodInfo{Status: "Completed", Ready: "0/1"}, false},
		{"crash looping", models.K8sPodInfo{Status: "CrashLoopBackOff"}, true},
		{"error status", models.K8sPodInfo{Status: "Error"}, true},
		{"pending", models.K8sPodInfo{Status: "Pending"}, true},
		{"oom killed", models.K8sPodInfo{Status: "OOMKilled"}, true},
		{"high restarts", models.K8sPodInfo{Status: "Running", Ready: "1/1", Restarts: 10}, true},
		{"below restart threshold", models.K8sPodInfo{Status: "Running", Ready: "1/1", Restarts: 9}, false},
		// 0/1 Running = container reports Running but isn't actually ready —
		// the specific false-OK this predicate exists to catch.
		{"running but not ready", models.K8sPodInfo{Status: "Running", Ready: "0/1"}, true},
	}
	for _, c := range cases {
		if got := k8sPodNeedsAttention(c.pod); got != c.want {
			t.Errorf("%s: k8sPodNeedsAttention(%+v) = %v, want %v", c.name, c.pod, got, c.want)
		}
	}
}

// TestPrintK8sNodes covers the node table renderer directly — the OK vs
// not-Ready icon branch.
func TestPrintK8sNodes(t *testing.T) {
	out := captureStdout(t, func() {
		printK8sNodes([]models.K8sNodeInfo{
			{Name: "node-a", Status: "Ready", Roles: "control-plane", Version: "v1.29.0"},
			{Name: "node-b", Status: "NotReady", Roles: "worker", Version: "v1.29.0"},
		}, output.ModePlain)
	})
	if !strings.Contains(out, "node-a") || !strings.Contains(out, "node-b") {
		t.Errorf("both nodes should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "CRIT") {
		t.Errorf("a NotReady node should render the fail icon, got:\n%s", out)
	}
}

// TestPrintK8sPodsOverview covers both the all-healthy summary and the
// problem-pods callout (including the CrashLoop/Error escalation to the fail
// icon vs the plain warn icon for other problem states).
func TestPrintK8sPodsOverview(t *testing.T) {
	healthy := captureStdout(t, func() {
		printK8sPodsOverview([]models.K8sPodInfo{{Status: "Running", Ready: "1/1"}}, output.ModePlain)
	})
	if !strings.Contains(healthy, "All pods healthy") {
		t.Errorf("no problem pods should read healthy, got:\n%s", healthy)
	}

	longName := strings.Repeat("x", 50)
	problems := captureStdout(t, func() {
		printK8sPodsOverview([]models.K8sPodInfo{
			{Name: longName, Namespace: "default", Status: "CrashLoopBackOff", Restarts: 3},
			{Name: "pending-pod", Namespace: "default", Status: "Pending"},
		}, output.ModePlain)
	})
	if !strings.Contains(problems, "2 pod(s) need attention") {
		t.Errorf("both problem pods should be counted, got:\n%s", problems)
	}
	if !strings.Contains(problems, "CRIT") || !strings.Contains(problems, "WARN") {
		t.Errorf("CrashLoop should render fail icon and Pending should render warn icon, got:\n%s", problems)
	}
	if strings.Contains(problems, longName) {
		t.Errorf("a >40-char pod name should be truncated, got:\n%s", problems)
	}
}

// TestPrintK8sAllPodsTable covers the full pod table, including the
// high-restart warning marker.
func TestPrintK8sAllPodsTable(t *testing.T) {
	longName := strings.Repeat("y", 50)
	out := captureStdout(t, func() {
		printK8sAllPodsTable([]models.K8sPodInfo{
			{Namespace: "default", Name: longName, Ready: "1/1", Status: "Running", Restarts: 15, Age: "3d"},
		}, output.ModePlain)
	})
	if strings.Contains(out, longName) {
		t.Errorf("a >40-char pod name should be truncated, got:\n%s", out)
	}
	if !strings.Contains(out, "WARN") {
		t.Errorf("15 restarts (>=10) should show the warn marker, got:\n%s", out)
	}
}

// TestPrintK8sReportDispatch covers printK8sReport's three top-level branches:
// not detected, API unreachable, and the full report (with OS-layer section).
func TestPrintK8sReportDispatch(t *testing.T) {
	notDetected := captureStdout(t, func() {
		printK8sReport(&models.K8sInfo{Detected: false}, output.ModePlain, 0)
	})
	if !strings.Contains(notDetected, "No Kubernetes installation detected") {
		t.Errorf("undetected k8s should say so, got:\n%s", notDetected)
	}

	apiDown := captureStdout(t, func() {
		printK8sReport(&models.K8sInfo{Detected: true, KubeBin: "kubectl", APIReachable: false}, output.ModePlain, 0)
	})
	if !strings.Contains(apiDown, "cluster API unreachable") {
		t.Errorf("an unreachable API should say so, got:\n%s", apiDown)
	}

	full := captureStdout(t, func() {
		printK8sReport(&models.K8sInfo{
			Detected: true, APIReachable: true, KubeBin: "kubectl",
			Nodes:   []models.K8sNodeInfo{{Name: "node-a", Status: "Ready"}},
			Pods:    []models.K8sPodInfo{{Status: "Running", Ready: "1/1"}},
			OSLayer: &models.K8sOSLayer{},
		}, output.ModePlain, 0)
	})
	if !strings.Contains(full, "node-a") || !strings.Contains(full, "OS layer") {
		t.Errorf("a full report should show nodes and the OS-layer section, got:\n%s", full)
	}
}

// TestRunK8s exercises runK8s's real (read-only) collector wiring in --plain
// and --json mode, and with --deep. No kubectl/k3s is expected on this test
// host, so all should render the "not detected" report without error — the
// same real-I/O precedent as cpu_report_test.go / hardware_test.go.
func TestRunK8s(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runK8s(plainCmd, nil); err != nil {
			t.Fatalf("runK8s (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runK8s (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runK8s(jsonCmd, nil); err != nil {
			t.Fatalf("runK8s (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}

	deepCmd := newBareCloudCmd()
	deepCmd.SetContext(context.Background())
	_ = deepCmd.Flags().Set("plain", "true")
	_ = deepCmd.Flags().Set("deep", "true")
	deepOut := captureStdout(t, func() {
		if err := runK8s(deepCmd, nil); err != nil {
			t.Fatalf("runK8s (deep): %v", err)
		}
	})
	if deepOut == "" {
		t.Error("runK8s (deep) produced no output")
	}
}
