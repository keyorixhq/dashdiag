package collectors

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Characterization tests for the K8s collector's pure helpers. k8s.go is
// platform-neutral (no build tag), so these run on every OS.

func TestParseK8sNodesRoles(t *testing.T) {
	cases := []struct {
		name      string
		json      string
		wantRole  string
		wantStat  string
		wantNotRd int
	}{
		{
			// k3s single-node control-plane: role lives in a label and the node
			// is UNTAINTED (k3s schedules workloads on it). The old taint-based
			// logic mislabeled this "worker" — the bug found on the VMware k3s rig.
			name: "k3s untainted control-plane (label)",
			json: `{"items":[{"metadata":{"name":"ubuntumin","labels":{
				"node-role.kubernetes.io/control-plane":"true",
				"node-role.kubernetes.io/master":"true",
				"kubernetes.io/hostname":"ubuntumin"}},
				"status":{"nodeInfo":{"kubeletVersion":"v1.35.5+k3s1"},
				"conditions":[{"type":"Ready","status":"True"}]},"spec":{}}]}`,
			wantRole: "control-plane,master",
			wantStat: "Ready",
		},
		{
			name: "plain worker (no role label)",
			json: `{"items":[{"metadata":{"name":"w1","labels":{"kubernetes.io/hostname":"w1"}},
				"status":{"nodeInfo":{"kubeletVersion":"v1.30.0"},
				"conditions":[{"type":"Ready","status":"True"}]},"spec":{}}]}`,
			wantRole: "worker",
			wantStat: "Ready",
		},
		{
			// No labels at all → fall back to taint-derived control-plane.
			name: "taint fallback when labels absent",
			json: `{"items":[{"metadata":{"name":"cp"},
				"status":{"nodeInfo":{"kubeletVersion":"v1.30.0"},
				"conditions":[{"type":"Ready","status":"False"}]},
				"spec":{"taints":[{"key":"node-role.kubernetes.io/control-plane"}]}}]}`,
			wantRole:  "control-plane",
			wantStat:  "NotReady",
			wantNotRd: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, notReady, ok := parseK8sNodes([]byte(tc.json))
			if !ok {
				t.Fatal("parseK8sNodes returned ok=false for valid JSON")
			}
			if len(nodes) != 1 {
				t.Fatalf("got %d nodes, want 1", len(nodes))
			}
			if nodes[0].Roles != tc.wantRole {
				t.Errorf("role = %q, want %q", nodes[0].Roles, tc.wantRole)
			}
			if nodes[0].Status != tc.wantStat {
				t.Errorf("status = %q, want %q", nodes[0].Status, tc.wantStat)
			}
			if notReady != tc.wantNotRd {
				t.Errorf("notReady = %d, want %d", notReady, tc.wantNotRd)
			}
		})
	}
}

func TestK8sTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exact", 5, "exact"},
		{"toolong", 4, "tool…"},
	}
	for _, tt := range tests {
		if got := k8sTruncate(tt.s, tt.n); got != tt.want {
			t.Errorf("k8sTruncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

func TestUpdatePodCounts(t *testing.T) {
	tests := []struct {
		name        string
		pod         models.K8sPodInfo
		maxRestarts int
		fullyReady  bool
		wantField   func(*models.K8sInfo) int
		wantValue   int
		wantCrash   bool // expect an entry in crashNames
	}{
		{
			name:        "crashloop increments CrashLooping",
			pod:         models.K8sPodInfo{Namespace: "ns", Name: "p", Status: "CrashLoopBackOff", Ready: "0/1"},
			maxRestarts: 5,
			wantField:   func(i *models.K8sInfo) int { return i.CrashLooping },
			wantValue:   1,
			wantCrash:   true, // maxRestarts >= 3
		},
		{
			name:        "crashloop under 3 restarts does not record crash name",
			pod:         models.K8sPodInfo{Namespace: "ns", Name: "p", Status: "Error", Ready: "0/1"},
			maxRestarts: 2,
			wantField:   func(i *models.K8sInfo) int { return i.CrashLooping },
			wantValue:   1,
			wantCrash:   false,
		},
		{
			name:        "pending increments Pending",
			pod:         models.K8sPodInfo{Status: "Pending"},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.Pending },
			wantValue:   1,
		},
		{
			name:        "unknown increments UnknownStatus",
			pod:         models.K8sPodInfo{Status: "Unknown"},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.UnknownStatus },
			wantValue:   1,
		},
		{
			name:        "running but 0/N increments PodsNotReady",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "0/2"},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.PodsNotReady },
			wantValue:   1,
		},
		{
			name:        "high restarts but not fully ready increments HighRestarts",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "1/2"},
			maxRestarts: 10,
			fullyReady:  false,
			wantField:   func(i *models.K8sInfo) int { return i.HighRestarts },
			wantValue:   1,
		},
		{
			name:        "high restarts but fully ready (recovered) does not increment HighRestarts",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "1/1"},
			maxRestarts: 10,
			fullyReady:  true,
			wantField:   func(i *models.K8sInfo) int { return i.HighRestarts },
			wantValue:   0,
		},
		{
			name:        "terminating increments Terminating",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "1/1", Terminating: true},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.Terminating },
			wantValue:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &models.K8sInfo{}
			crashNames := map[string]bool{}
			pod := tt.pod
			updatePodCounts(info, &pod, tt.maxRestarts, tt.fullyReady, crashNames)
			if got := tt.wantField(info); got != tt.wantValue {
				t.Errorf("counter = %d, want %d", got, tt.wantValue)
			}
			if gotCrash := len(crashNames) > 0; gotCrash != tt.wantCrash {
				t.Errorf("crashNames recorded = %v, want %v (%v)", gotCrash, tt.wantCrash, crashNames)
			}
		})
	}
}

// TestCollectK8sPodsUnknownStatus pins Spec 23f: a pod in phase Unknown (node
// partitioned/crashed) must carry its node and owner so the analysis layer can
// warn that a StatefulSet-owned pod won't be rescheduled until it's deleted.
func TestCollectK8sPodsUnknownStatus(t *testing.T) {
	const podsJSON = `{"items":[
		{"metadata":{"name":"postgres-0","namespace":"default",
			"creationTimestamp":"2026-01-01T00:00:00Z",
			"ownerReferences":[{"kind":"StatefulSet","name":"postgres"}]},
		 "spec":{"nodeName":"worker-03","containers":[{"image":"postgres:16"}]},
		 "status":{"phase":"Unknown"}},
		{"metadata":{"name":"web-7d4","namespace":"default",
			"creationTimestamp":"2026-01-01T00:00:00Z"},
		 "spec":{"nodeName":"worker-01","containers":[{"image":"nginx"}]},
		 "status":{"phase":"Running","containerStatuses":[{"ready":true}]}}
	]}`
	prev := SetSource(mockExec(func(name string, args []string) (source.Result, error) {
		if name == "kubectl" && len(args) > 0 && args[0] == "get" {
			return source.Result{Stdout: []byte(podsJSON)}, nil
		}
		return source.Result{}, &cmdError{name: name, code: 1}
	}))
	defer SetSource(prev)

	info := &models.K8sInfo{}
	collectK8sPods(context.Background(), "kubectl", info)

	if info.UnknownStatus != 1 {
		t.Fatalf("UnknownStatus = %d, want 1", info.UnknownStatus)
	}
	var unknown *models.K8sPodInfo
	for i := range info.Pods {
		if info.Pods[i].Status == "Unknown" {
			unknown = &info.Pods[i]
		}
	}
	if unknown == nil {
		t.Fatal("no pod parsed with status Unknown")
	}
	if unknown.NodeName != "worker-03" {
		t.Errorf("NodeName = %q, want %q", unknown.NodeName, "worker-03")
	}
	if unknown.OwnerKind != "StatefulSet" || unknown.OwnerName != "postgres" {
		t.Errorf("OwnerKind/OwnerName = %q/%q, want StatefulSet/postgres", unknown.OwnerKind, unknown.OwnerName)
	}
	// The Running pod must NOT get NodeName/Owner populated — those fields are
	// scoped to Unknown pods only (kept out of JSON output otherwise via omitempty).
	for i := range info.Pods {
		p := &info.Pods[i]
		if p.Status == "Running" && (p.NodeName != "" || p.OwnerKind != "") {
			t.Errorf("Running pod %s got NodeName/OwnerKind populated, want empty", p.Name)
		}
	}
}

// TestCNIBinsPresentIn pins the multi-path CNI check (kubeadm /opt/cni/bin vs the
// k3s bundle) — found via live k3s validation: checking only /opt/cni/bin false-CRIT'd
// every k3s node, whose CNI plugins live under /var/lib/rancher/k3s/data/.../bin.
func TestCNIBinsPresentIn(t *testing.T) {
	dir := t.TempDir()
	kubeadm := dir + "/opt-cni-bin" // absent
	k3s := dir + "/k3s-bin"         // populated
	if err := os.MkdirAll(k3s, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k3s+"/flannel", []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// kubeadm path absent, k3s path populated → checked & ok (the k3s regression).
	if checked, ok := cniBinsPresentIn(kubeadm, k3s); !checked || !ok {
		t.Errorf("k3s bundle present: checked=%v ok=%v, want both true", checked, ok)
	}
	// Both absent → checked (we could look) but not ok (genuinely no CNI).
	if checked, ok := cniBinsPresentIn(kubeadm, dir+"/also-absent"); !checked || ok {
		t.Errorf("both absent: checked=%v ok=%v, want checked=true ok=false", checked, ok)
	}
	// A readable-but-empty dir → checked, not ok.
	empty := dir + "/empty"
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if checked, ok := cniBinsPresentIn(empty); !checked || ok {
		t.Errorf("empty dir: checked=%v ok=%v, want checked=true ok=false", checked, ok)
	}
}

// TestPodAge: pod AGE column was blank because the collector never parsed
// metadata.creationTimestamp (found live on k3s-dsd, where kubectl showed "13d").
// podAge renders kubectl's compact short form and blanks on absent/garbage input.
func TestPodAge(t *testing.T) {
	if got := podAge(""); got != "" {
		t.Errorf("empty timestamp should yield empty age, got %q", got)
	}
	if got := podAge("not-a-timestamp"); got != "" {
		t.Errorf("unparseable timestamp should yield empty age, got %q", got)
	}
	now := NowViaSource()
	cases := []struct {
		ago  time.Duration
		want string
	}{
		{90 * time.Second, "1m"},
		{2 * time.Hour, "2h"},
		{49 * time.Hour, "2d"},
		{-time.Hour, "0s"}, // clock skew / future creation clamps to 0s, never negative
	}
	for _, c := range cases {
		ts := now.Add(-c.ago).Format(time.RFC3339)
		if got := podAge(ts); got != c.want {
			t.Errorf("podAge(%s ago) = %q, want %q", c.ago, got, c.want)
		}
	}
}
