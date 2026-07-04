package cmd

import (
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
		{"high restarts", &models.K8sInfo{HighRestarts: 4}, "4 pod(s) high restarts"},
		{"workloads down", &models.K8sInfo{WorkloadsDown: 1}, "1 workload(s) degraded"},
		{"pvcs not bound", &models.K8sInfo{PVCsNotBound: 2}, "2 PVC(s) not bound"},
		{"events", &models.K8sInfo{Events: []models.K8sEvent{{}}}, "1 warning event(s)"},
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
