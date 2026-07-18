package collectors

import (
	"context"
	"os"
	"strings"
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

// TestCollectK8sPods_InvalidJSON covers k8s.go:256.54,258.3 — the
// json.Unmarshal error early-return when kubectl returns non-JSON output.
func TestCollectK8sPods_InvalidJSON(t *testing.T) {
	prev := SetSource(mockExec(func(name string, args []string) (source.Result, error) {
		if name == "kubectl" {
			return source.Result{Stdout: []byte("not valid json"), ExitCode: 0}, nil
		}
		return source.Result{ExitCode: 1}, nil
	}))
	defer SetSource(prev)

	info := &models.K8sInfo{}
	collectK8sPods(context.Background(), "kubectl", info)
	if info.APIReachable {
		t.Error("APIReachable must remain false when JSON unmarshal fails")
	}
}

// TestCollectK8sPods_WaitingStatusOverride covers k8s.go:281.27,283.4 — the
// statusOverride branch when a container has a non-empty Waiting.Reason.
func TestCollectK8sPods_WaitingStatusOverride(t *testing.T) {
	const podsJSON = `{"items":[
		{"metadata":{"name":"app-0","namespace":"default",
			"creationTimestamp":"2026-01-01T00:00:00Z"},
		 "spec":{"containers":[{"image":"myapp:1.0"}]},
		 "status":{"phase":"Running","containerStatuses":[{
			 "ready":false,"restartCount":0,
			 "state":{"waiting":{"reason":"ImagePullBackOff"}}
		 }]}}
	]}`
	prev := SetSource(mockExec(func(name string, args []string) (source.Result, error) {
		if name == "kubectl" && len(args) > 0 && args[0] == "get" {
			return source.Result{Stdout: []byte(podsJSON), ExitCode: 0}, nil
		}
		return source.Result{ExitCode: 1}, nil
	}))
	defer SetSource(prev)

	info := &models.K8sInfo{}
	collectK8sPods(context.Background(), "kubectl", info)
	if len(info.Pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(info.Pods))
	}
	if info.Pods[0].Status != "ImagePullBackOff" {
		t.Errorf("pod status = %q, want ImagePullBackOff (statusOverride)", info.Pods[0].Status)
	}
}

// TestParseK8sWarningEvents_NameWithoutSlash covers k8s.go:437.9,439.4 —
// the else branch where fields[4] has no "/" separator, so ev.Name = fields[4].
func TestParseK8sWarningEvents_NameWithoutSlash(t *testing.T) {
	t.Parallel()
	// Five fields minimum; fields[4] = "mypod" has no "/" → else branch.
	out := "default  5m  1  Warning  mypod  Back-off pulling image\n"
	evs := parseK8sWarningEvents(out)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Name != "mypod" {
		t.Errorf("Name = %q, want %q", evs[0].Name, "mypod")
	}
}

// TestCollectK8sOSLayer_KubeletErrorsTruncated covers k8s.go:708.35,710.4 —
// the KubeletErrors[:5] cap when journalctl returns more than 5 error lines.
func TestCollectK8sOSLayer_KubeletErrorsTruncated(t *testing.T) {
	sixErrors := strings.Join([]string{
		"Jan 01 00:00:01 host k3s: error syncing pod 0",
		"Jan 01 00:00:02 host k3s: failed to pull image 1",
		"Jan 01 00:00:03 host k3s: error listing pods 2",
		"Jan 01 00:00:04 host k3s: failed to schedule pod 3",
		"Jan 01 00:00:05 host k3s: error updating lease 4",
		"Jan 01 00:00:06 host k3s: failed to connect apiserver 5",
	}, "\n") + "\n"

	prev := SetSource(mockExec(func(name string, args []string) (source.Result, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "is-active" && args[1] == "kubelet" {
			return source.Result{Stdout: []byte("active\n"), ExitCode: 0}, nil
		}
		if name == "journalctl" {
			return source.Result{Stdout: []byte(sixErrors), ExitCode: 0}, nil
		}
		return source.Result{ExitCode: 1}, nil
	}))
	defer SetSource(prev)

	layer := collectK8sOSLayer(context.Background(), "kubectl", "k3s")
	if len(layer.KubeletErrors) != 5 {
		t.Errorf("KubeletErrors = %d, want 5 (truncated from 6)", len(layer.KubeletErrors))
	}
}

// TestCheckCertExpiry_ReadFileFails covers k8s.go:782.17,783.12 — the
// err != nil continue when glob finds a cert path that readFile cannot open.
func TestCheckCertExpiry_ReadFileFails(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/certs/*.crt", []string{"/certs/apiserver.crt"})
	// /certs/apiserver.crt is intentionally NOT seeded → ReadFile returns ErrNotRecorded.
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	var layer models.K8sOSLayer
	checkCertExpiry("/certs", &layer)
	if layer.CertExpirySoon || len(layer.CertExpiredNames) != 0 {
		t.Errorf("expected no cert findings when readFile fails, got CertExpirySoon=%v CertExpiredNames=%v",
			layer.CertExpirySoon, layer.CertExpiredNames)
	}
}

// TestPodAge_SecondsCase covers k8s.go:193.23,194.46 — the "%ds" branch
// when a pod's age is under one minute.
func TestPodAge_SecondsCase(t *testing.T) {
	t.Parallel()
	now := NowViaSource()
	ts := now.Add(-45 * time.Second).Format(time.RFC3339)
	if got := podAge(ts); got != "45s" {
		t.Errorf("podAge(45s ago) = %q, want %q", got, "45s")
	}
}

// TestCollectK8sWorkloads_ReadyFieldNoSlash covers k8s.go:495.28,496.13 —
// the continue when the READY column has no "/" separator (malformed output).
func TestCollectK8sWorkloads_ReadyFieldNoSlash(t *testing.T) {
	// The READY column "1" has no "/" — readyParts len=1 != 2 → continue.
	const workloadsOut = "default  myapp  1  1  1  3d\n"
	prev := SetSource(mockExec(func(name string, args []string) (source.Result, error) {
		if name == "kubectl" && len(args) >= 2 && args[0] == "get" {
			return source.Result{Stdout: []byte(workloadsOut), ExitCode: 0}, nil
		}
		return source.Result{ExitCode: 1}, nil
	}))
	defer SetSource(prev)

	info := &models.K8sInfo{}
	collectK8sWorkloads(context.Background(), "kubectl", info)
	if len(info.Workloads) != 0 {
		t.Errorf("workloads with malformed READY field must be skipped, got %d entries", len(info.Workloads))
	}
}

// TestK8sCollector_DeepBranchPopulatesOSLayer covers k8s.go:77.12,79.3 —
// the `if c.Deep { info.OSLayer = collectK8sOSLayer(...) }` branch.
func TestK8sCollector_DeepBranchPopulatesOSLayer(t *testing.T) {
	// Seed the RKE2 kubectl binary so k8sDetectBin returns non-empty.
	b := source.NewBundle()
	b.PutStat("/var/lib/rancher/rke2/bin/kubectl", source.FileMeta{})
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	c := &K8sCollector{Deep: true}
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	info, ok := result.(*models.K8sInfo)
	if !ok {
		t.Fatal("result is not *models.K8sInfo")
	}
	if info.OSLayer == nil {
		t.Error("OSLayer must be non-nil when Deep=true and a k8s binary is detected")
	}
}
