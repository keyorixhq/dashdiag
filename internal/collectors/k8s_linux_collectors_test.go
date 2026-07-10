//go:build linux

package collectors

import (
	"context"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestK8sCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewK8sCollector()
	if c.Name() != "K8s" {
		t.Errorf("Name() = %q, want K8s", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
	if c.Deep {
		t.Error("NewK8sCollector: expected Deep=false")
	}
	if !NewK8sDeepCollector().Deep {
		t.Error("NewK8sDeepCollector: expected Deep=true")
	}
}

func TestCollectK8sNodes_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "nodes", "-o", "json"},
			`{"items":[{"metadata":{"name":"n1","labels":{"kubernetes.io/hostname":"n1"}},
				"status":{"nodeInfo":{"kubeletVersion":"v1.30.0"},
				"conditions":[{"type":"Ready","status":"False"}]},"spec":{}}]}`, 0)
	})
	info := &models.K8sInfo{}
	collectK8sNodes(context.Background(), "kubectl", info)
	if !info.APIReachable {
		t.Error("expected APIReachable=true")
	}
	if len(info.Nodes) != 1 || info.NodesNotReady != 1 {
		t.Errorf("Nodes = %+v, NodesNotReady = %d", info.Nodes, info.NodesNotReady)
	}
}

func TestCollectK8sNodes_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("kubectl", []string{"get", "nodes", "-o", "json"})
	})
	info := &models.K8sInfo{}
	collectK8sNodes(context.Background(), "kubectl", info)
	if info.APIReachable || len(info.Nodes) != 0 {
		t.Errorf("info = %+v, want untouched", info)
	}
}

func TestCollectK8sNodes_UnparseableJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "nodes", "-o", "json"}, "not json", 0)
	})
	info := &models.K8sInfo{}
	collectK8sNodes(context.Background(), "kubectl", info)
	if info.APIReachable {
		t.Error("expected APIReachable=false on unparseable JSON")
	}
}

func TestCollectK8sEvents_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{
			"get", "events", "-A", "--field-selector", "type=Warning",
			"--sort-by=.lastTimestamp", "--no-headers",
		}, "default   5m   Warning   BackOff   pod/web-1   Back-off restarting\n", 0)
	})
	info := &models.K8sInfo{}
	collectK8sEvents(context.Background(), "kubectl", info)
	if len(info.Events) != 1 || info.Events[0].Reason != "BackOff" {
		t.Errorf("Events = %+v", info.Events)
	}
}

func TestCollectK8sEvents_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("kubectl", []string{
			"get", "events", "-A", "--field-selector", "type=Warning",
			"--sort-by=.lastTimestamp", "--no-headers",
		})
	})
	info := &models.K8sInfo{}
	collectK8sEvents(context.Background(), "kubectl", info)
	if len(info.Events) != 0 {
		t.Errorf("Events = %+v, want empty", info.Events)
	}
}

func TestCollectK8sPVCs_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "pvc", "-A", "--no-headers"},
			"default   data-pg-0   Bound     10Gi\n"+
				"default   data-pg-1   Pending   5Gi\n", 0)
	})
	info := &models.K8sInfo{}
	collectK8sPVCs(context.Background(), "kubectl", info)
	if len(info.PVCs) != 2 || info.PVCsNotBound != 1 {
		t.Errorf("PVCs = %+v, PVCsNotBound = %d", info.PVCs, info.PVCsNotBound)
	}
}

func TestCollectK8sPVCs_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("kubectl", []string{"get", "pvc", "-A", "--no-headers"})
	})
	info := &models.K8sInfo{}
	collectK8sPVCs(context.Background(), "kubectl", info)
	if len(info.PVCs) != 0 {
		t.Errorf("PVCs = %+v, want empty (no PVCs configured is normal)", info.PVCs)
	}
}

func TestCollectK8sWorkloads_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "deploy", "-A", "--no-headers"},
			"default   web   2/3   3   2   10d\n", 0)
		b.PutCmd("kubectl", []string{"get", "statefulset", "-A", "--no-headers"},
			"default   pg    1/1   1   1   10d\n", 0)
	})
	info := &models.K8sInfo{}
	collectK8sWorkloads(context.Background(), "kubectl", info)
	if len(info.Workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(info.Workloads))
	}
	if info.WorkloadsDown != 1 {
		t.Errorf("WorkloadsDown = %d, want 1", info.WorkloadsDown)
	}
	var deploy models.K8sWorkloadInfo
	for _, w := range info.Workloads {
		if w.Name == "web" {
			deploy = w
		}
	}
	if deploy.Kind != "Deploy" || deploy.Ready != 2 || deploy.Desired != 3 {
		t.Errorf("deploy = %+v", deploy)
	}
}

func TestCollectK8sWorkloads_OneKindFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("kubectl", []string{"get", "deploy", "-A", "--no-headers"})
		b.PutCmd("kubectl", []string{"get", "statefulset", "-A", "--no-headers"},
			"default   pg    1/1   1   1   10d\n", 0)
	})
	info := &models.K8sInfo{}
	collectK8sWorkloads(context.Background(), "kubectl", info)
	if len(info.Workloads) != 1 {
		t.Errorf("expected the statefulset kind to still be collected, got %+v", info.Workloads)
	}
}

func TestFlannelCNIConfigured_ByFilename(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/cni/net.d", []string{"10-flannel.conflist"})
	})
	inUse, unreadable := flannelCNIConfigured()
	if !inUse || unreadable {
		t.Errorf("inUse=%v unreadable=%v, want true/false", inUse, unreadable)
	}
}

func TestFlannelCNIConfigured_ByContent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/cni/net.d", []string{"10-cni.conf"})
		b.PutFile("/etc/cni/net.d/10-cni.conf", []byte(`{"type":"flannel"}`))
	})
	inUse, unreadable := flannelCNIConfigured()
	if !inUse || unreadable {
		t.Errorf("inUse=%v unreadable=%v, want true/false", inUse, unreadable)
	}
}

func TestFlannelCNIConfigured_NotConfigured(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/cni/net.d", []string{"10-calico.conflist"})
		b.PutFile("/etc/cni/net.d/10-calico.conflist", []byte(`{"type":"calico"}`))
		b.PutDir("/var/lib/rancher/k3s/agent/etc/cni/net.d", nil)
	})
	inUse, unreadable := flannelCNIConfigured()
	if inUse || unreadable {
		t.Errorf("inUse=%v unreadable=%v, want false/false", inUse, unreadable)
	}
}

func TestFlannelCNIConfigured_Unreadable(t *testing.T) {
	b := source.NewBundle()
	prev := SetSource(&fakePermissionDeniedDirSource{
		Replay: source.NewReplay(b),
		dirs: map[string]bool{
			"/etc/cni/net.d": true,
			"/var/lib/rancher/k3s/agent/etc/cni/net.d": true,
		},
	})
	t.Cleanup(func() { SetSource(prev) })
	inUse, unreadable := flannelCNIConfigured()
	if inUse {
		t.Error("expected inUse=false")
	}
	if !unreadable {
		t.Error("expected unreadable=true when both candidate dirs exist but can't be listed")
	}
}

func TestK8sUnitActive_FirstMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "kubelet"}, "active\n", 0)
	})
	if !k8sUnitActive(context.Background(), "kubelet", "k3s") {
		t.Error("expected true")
	}
}

func TestK8sUnitActive_LaterMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "kubelet"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "k3s"}, "active\n", 0)
	})
	if !k8sUnitActive(context.Background(), "kubelet", "k3s") {
		t.Error("expected true (second unit active)")
	}
}

func TestK8sUnitActive_NoneActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "kubelet"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "k3s"}, "inactive\n", 3)
	})
	if k8sUnitActive(context.Background(), "kubelet", "k3s") {
		t.Error("expected false")
	}
}

func TestCniBinsPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/opt/cni/bin", nil)
		b.PutDir("/var/lib/rancher/k3s/data/current/bin", []string{"flannel", "loopback"})
	})
	checked, ok := cniBinsPresent()
	if !checked || !ok {
		t.Errorf("checked=%v ok=%v, want true/true (k3s bundle populated)", checked, ok)
	}
}

func TestDetectKubeForward_NftKubePresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("nft", []string{"list", "tables"}, "table ip kube-proxy\n", 0)
	})
	checked, present := detectKubeForward(context.Background())
	if !checked || !present {
		t.Errorf("checked=%v present=%v, want true/true", checked, present)
	}
}

func TestDetectKubeForward_IptablesChainPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nft", []string{"list", "tables"})
		b.PutCmd("iptables", []string{"-L", "KUBE-FORWARD", "-n"},
			"Chain KUBE-FORWARD (1 references)\n", 0)
	})
	checked, present := detectKubeForward(context.Background())
	if !checked || !present {
		t.Errorf("checked=%v present=%v, want true/true", checked, present)
	}
}

func TestDetectKubeForward_IptablesNoChain(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nft", []string{"list", "tables"})
		b.PutCmd("iptables", []string{"-L", "KUBE-FORWARD", "-n"}, "No chain/target/match by that name.\n", 1)
	})
	checked, present := detectKubeForward(context.Background())
	if checked || present {
		t.Errorf("checked=%v present=%v, want false/false (iptables exit!=0 counts as unavailable)", checked, present)
	}
}

func TestDetectKubeForward_NeitherToolAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nft", []string{"list", "tables"})
		b.PutCmdNotFound("iptables", []string{"-L", "KUBE-FORWARD", "-n"})
	})
	checked, present := detectKubeForward(context.Background())
	if checked || present {
		t.Errorf("checked=%v present=%v, want false/false", checked, present)
	}
}

// TestDetectKubeForward_NftRanNoKubeTableIptablesUnavailable guards the
// specific "nft ran successfully but found no kube table, AND iptables is
// unavailable" branch — distinct from the neither-tool-available case above:
// here nft DID answer (nftErr == nil), it just found nothing.
func TestDetectKubeForward_NftRanNoKubeTableIptablesUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("nft", []string{"list", "tables"}, "table ip filter\n", 0)
		b.PutCmdNotFound("iptables", []string{"-L", "KUBE-FORWARD", "-n"})
	})
	checked, present := detectKubeForward(context.Background())
	if !checked || present {
		t.Errorf("checked=%v present=%v, want true/false (nft ran, no kube table, iptables unavailable)", checked, present)
	}
}

// TestK8sDetectBin_PathFallback_K0s and _Microk8s guard the two remaining
// lookPath fallback branches in k8sDetectBin not yet exercised elsewhere.
func TestK8sDetectBin_PathFallback_K0s(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"lookpath/k0s": []byte("/usr/bin/k0s")},
	})
	t.Cleanup(func() { SetSource(prev) })
	if got := k8sDetectBin(); got != "k0s kubectl" {
		t.Errorf("k8sDetectBin() = %q, want %q", got, "k0s kubectl")
	}
}

func TestK8sDetectBin_PathFallback_Microk8s(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"lookpath/microk8s": []byte("/usr/bin/microk8s")},
	})
	t.Cleanup(func() { SetSource(prev) })
	if got := k8sDetectBin(); got != "microk8s kubectl" {
		t.Errorf("k8sDetectBin() = %q, want %q", got, "microk8s kubectl")
	}
}

// TestK8sDistribution_Microk8s guards the microk8s marker branch, the only
// k8sDistribution case not already exercised by TestK8sDistribution in
// k8s_distribution_test.go.
func TestK8sDistribution_Microk8s(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/snap/microk8s", source.FileMeta{})
	})
	if got := k8sDistribution(); got != "microk8s" {
		t.Errorf("k8sDistribution() = %q, want microk8s", got)
	}
}

// TestSummarizeContainerStatuses drives every field the tabulation computes:
// max restart count across containers, the last non-empty waiting reason, and
// the last non-empty termination message — none of which the ready/pending
// happy-path fixtures elsewhere exercise.
func TestSummarizeContainerStatuses(t *testing.T) {
	type waiting = struct {
		Reason string `json:"reason"`
	}
	type state = struct {
		Waiting waiting `json:"waiting"`
	}
	type terminated = struct {
		Message string `json:"message"`
	}
	type lastTermination = struct {
		Terminated terminated `json:"terminated"`
	}
	type cs = struct {
		Ready                bool            `json:"ready"`
		RestartCount         int             `json:"restartCount"`
		State                state           `json:"state"`
		LastTerminationState lastTermination `json:"lastState"`
	}

	statuses := []cs{
		{Ready: true, RestartCount: 2},
		{Ready: false, RestartCount: 7, State: state{Waiting: waiting{Reason: "CrashLoopBackOff"}},
			LastTerminationState: lastTermination{Terminated: terminated{Message: "OOMKilled"}}},
		{Ready: false, RestartCount: 3}, // lower than max — must not overwrite maxRestarts
	}
	ready, maxRestarts, statusOverride, terminationMsg := summarizeContainerStatuses(statuses)
	if ready != 1 {
		t.Errorf("ready = %d, want 1", ready)
	}
	if maxRestarts != 7 {
		t.Errorf("maxRestarts = %d, want 7 (the highest RestartCount)", maxRestarts)
	}
	if statusOverride != "CrashLoopBackOff" {
		t.Errorf("statusOverride = %q, want CrashLoopBackOff", statusOverride)
	}
	if terminationMsg != "OOMKilled" {
		t.Errorf("terminationMsg = %q, want OOMKilled", terminationMsg)
	}
}

// TestFetchPreviousLogs_CrashingPodGetsLogs drives the previously-uncovered
// inner body: a pod recorded in crashNames must have `kubectl logs --previous`
// invoked and PreviousLogs populated on success. A second, non-crashing pod
// must be skipped entirely (no logs command for it).
func TestFetchPreviousLogs_CrashingPodGetsLogs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"logs", "--previous", "--tail=10", "-n", "default", "crashy"},
			"panic: oh no\n", 0)
	})
	info := &models.K8sInfo{
		Pods: []models.K8sPodInfo{
			{Namespace: "default", Name: "crashy"},
			{Namespace: "default", Name: "healthy"},
		},
	}
	crashNames := map[string]bool{"default/crashy": true}
	fetchPreviousLogs(context.Background(), "kubectl", info, crashNames)

	if info.Pods[0].PreviousLogs != "panic: oh no\n" {
		t.Errorf("Pods[0].PreviousLogs = %q, want the fetched log line", info.Pods[0].PreviousLogs)
	}
	if info.Pods[1].PreviousLogs != "" {
		t.Errorf("Pods[1].PreviousLogs = %q, want empty (not in crashNames)", info.Pods[1].PreviousLogs)
	}
}

// TestFetchPreviousLogs_CapsAtFive guards the `count >= 5` cutoff: with 6
// crash-looping pods, only the first 5 get a logs fetch attempted.
func TestFetchPreviousLogs_CapsAtFive(t *testing.T) {
	crashNames := map[string]bool{}
	pods := make([]models.K8sPodInfo, 6)
	seedFns := map[string][]string{}
	for i := range pods {
		name := fmt.Sprintf("p%d", i)
		pods[i] = models.K8sPodInfo{Namespace: "default", Name: name}
		crashNames["default/"+name] = true
		seedFns[name] = []string{"logs", "--previous", "--tail=10", "-n", "default", name}
	}
	withFixtureSource(t, func(b *source.Bundle) {
		for _, name := range []string{"p0", "p1", "p2", "p3", "p4", "p5"} {
			b.PutCmd("kubectl", seedFns[name], "log for "+name+"\n", 0)
		}
	})
	info := &models.K8sInfo{Pods: pods}
	fetchPreviousLogs(context.Background(), "kubectl", info, crashNames)

	got := 0
	for _, p := range info.Pods {
		if p.PreviousLogs != "" {
			got++
		}
	}
	if got != 5 {
		t.Errorf("got %d pods with fetched logs, want exactly 5 (the count>=5 cap)", got)
	}
}

// TestFetchPreviousLogs_LogsCommandFails guards the `err == nil && logs != ""`
// guard: a failing `kubectl logs --previous` must leave PreviousLogs empty,
// not panic or record garbage.
func TestFetchPreviousLogs_LogsCommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("kubectl", []string{"logs", "--previous", "--tail=10", "-n", "default", "crashy"})
	})
	info := &models.K8sInfo{
		Pods: []models.K8sPodInfo{{Namespace: "default", Name: "crashy"}},
	}
	fetchPreviousLogs(context.Background(), "kubectl", info, map[string]bool{"default/crashy": true})
	if info.Pods[0].PreviousLogs != "" {
		t.Errorf("PreviousLogs = %q, want empty when the logs command fails", info.Pods[0].PreviousLogs)
	}
}

func TestK8sAvailable_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/local/bin/kubectl", source.FileMeta{})
	})
	if !K8sAvailable() {
		t.Error("expected true")
	}
}

func TestK8sAvailable_False(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
	if K8sAvailable() {
		t.Error("expected false")
	}
}

func TestKubeadmKubeconfigFlag_KubeconfigEnvSet(t *testing.T) {
	// Deterministic regardless of the test runner's euid: a non-empty KUBECONFIG
	// short-circuits kubeadmKubeconfigFlagFor to "" before euid is even consulted.
	t.Setenv("KUBECONFIG", "/home/user/.kube/config")
	if got := kubeadmKubeconfigFlag(); got != "" {
		t.Errorf("got %q, want empty when KUBECONFIG is set", got)
	}
}

// TestK8sDetectBin_PathFallback drives k8sDetectBin's lookPath-based fallback
// branches (no direct-path binary found, resolved via $PATH instead).
func TestK8sDetectBin_PathFallback(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"lookpath/k3s": []byte("/usr/bin/k3s")},
	})
	t.Cleanup(func() { SetSource(prev) })
	if got := k8sDetectBin(); got != "k3s kubectl" {
		t.Errorf("k8sDetectBin() = %q, want %q", got, "k3s kubectl")
	}
}

func TestK8sDetectBin_PathFallback_Kubectl(t *testing.T) {
	t.Setenv("KUBECONFIG", "/home/user/.kube/config") // deterministic: skip the euid==0 admin.conf branch
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"lookpath/kubectl": []byte("/usr/bin/kubectl")},
	})
	t.Cleanup(func() { SetSource(prev) })
	if got := k8sDetectBin(); got != "kubectl" {
		t.Errorf("k8sDetectBin() = %q, want %q", got, "kubectl")
	}
}

func TestK8sDetectBin_NothingFound(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
	if got := k8sDetectBin(); got != "" {
		t.Errorf("k8sDetectBin() = %q, want empty", got)
	}
}

// TestCollectK8sOSLayer drives the full deep-check function against a
// simulated k3s node with a mix of healthy and degraded signals.
func TestCollectK8sOSLayer(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "kubelet"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "k3s"}, "active\n", 0)
		b.PutCmd("journalctl", []string{
			"-u", "kubelet", "-u", "k3s", "-u", "rke2-server", "-u", "k0scontroller",
			"-u", "snap.microk8s.daemon-kubelite", "-n", "30", "--no-pager", "-q",
		}, "level=info msg=\"started\"\nlevel=error msg=\"failed to sync\"\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "containerd"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "snap.microk8s.daemon-containerd"}, "inactive\n", 3)
		b.PutStat("/run/k3s/containerd/containerd.sock", source.FileMeta{})
		b.PutFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"))
		b.PutDir("/etc/cni/net.d", []string{"10-flannel.conflist"})
		b.PutStat("/run/flannel/subnet.env", source.FileMeta{})
		b.PutDir("/opt/cni/bin", []string{"flannel", "loopback"})
		b.PutCmd("nft", []string{"list", "tables"}, "table ip kube-proxy\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "firewalld"}, "active\n", 0)
		b.PutCmd("firewall-cmd", []string{"--query-masquerade"}, "yes\n", 0)
		b.PutGlob("/etc/kubernetes/pki/*.crt", nil)
		b.PutGlob("/var/lib/rancher/k3s/server/tls/*.crt", nil)
	})
	layer := collectK8sOSLayer(context.Background(), "kubectl", "k3s")

	if !layer.KubeletChecked || !layer.KubeletActive {
		t.Errorf("kubelet checked=%v active=%v, want true/true", layer.KubeletChecked, layer.KubeletActive)
	}
	if len(layer.KubeletErrors) != 1 {
		t.Errorf("KubeletErrors = %v, want 1 error line", layer.KubeletErrors)
	}
	if !layer.ContainerdChecked || !layer.ContainerdActive {
		t.Errorf("containerd checked=%v active=%v, want true/true (via bundled sock)", layer.ContainerdChecked, layer.ContainerdActive)
	}
	if !layer.IPForwardChecked || !layer.IPForwardEnabled {
		t.Errorf("IPForward checked=%v enabled=%v, want true/true", layer.IPForwardChecked, layer.IPForwardEnabled)
	}
	if !layer.FlannelInUse || !layer.FlannelSubnetOK {
		t.Errorf("Flannel inUse=%v subnetOK=%v, want true/true", layer.FlannelInUse, layer.FlannelSubnetOK)
	}
	if !layer.CNIChecked || !layer.CNIBinsOK {
		t.Errorf("CNI checked=%v ok=%v, want true/true", layer.CNIChecked, layer.CNIBinsOK)
	}
	if !layer.KubeForwardChecked || !layer.KubeForwardChain {
		t.Errorf("KubeForward checked=%v chain=%v, want true/true", layer.KubeForwardChecked, layer.KubeForwardChain)
	}
	if !layer.KubeServicesChecked || layer.KubeProxyMode != "nft" {
		t.Errorf("KubeServices checked=%v mode=%q, want true/nft", layer.KubeServicesChecked, layer.KubeProxyMode)
	}
	if !layer.FirewalldChecked || !layer.FirewalldMasquOK {
		t.Errorf("Firewalld checked=%v masqOK=%v, want true/true", layer.FirewalldChecked, layer.FirewalldMasquOK)
	}
}

// TestK8sCollector_Collect_FullHappyPath drives Collect() end-to-end,
// including deep mode's OS-layer pass.
func TestK8sCollector_Collect_FullHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/local/bin/kubectl", source.FileMeta{})
		b.PutStat("/etc/kubernetes/manifests", source.FileMeta{})
		b.PutCmd("kubectl", []string{"get", "nodes", "-o", "json"},
			`{"items":[{"metadata":{"name":"n1"},"status":{"nodeInfo":{"kubeletVersion":"v1.30.0"},
				"conditions":[{"type":"Ready","status":"True"}]},"spec":{}}]}`, 0)
		b.PutCmd("kubectl", []string{"get", "pods", "-A", "-o", "json"}, `{"items":[]}`, 0)
		b.PutCmd("kubectl", []string{
			"get", "events", "-A", "--field-selector", "type=Warning",
			"--sort-by=.lastTimestamp", "--no-headers",
		}, "", 0)
		b.PutCmd("kubectl", []string{"get", "pvc", "-A", "--no-headers"}, "", 0)
		b.PutCmd("kubectl", []string{"get", "deploy", "-A", "--no-headers"}, "", 0)
		b.PutCmd("kubectl", []string{"get", "statefulset", "-A", "--no-headers"}, "", 0)
	})
	got, err := NewK8sCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.K8sInfo)
	if !info.Detected || info.KubeBin == "" {
		t.Errorf("info = %+v, want Detected=true with a KubeBin", info)
	}
	if info.Distribution != "kubeadm" {
		t.Errorf("Distribution = %q, want kubeadm", info.Distribution)
	}
	if info.OSLayer != nil {
		t.Error("expected OSLayer=nil in non-deep mode")
	}
}

func TestK8sCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
	got, err := NewK8sCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.K8sInfo)
	if info.Detected {
		t.Error("expected Detected=false")
	}
}

// fakePermissionDeniedDirSource makes ReadDir fail with a permission error for
// the given directories — the Bundle API has no public seam for that (a
// PutDir-recorded directory always replays successfully), needed to exercise
// flannelCNIConfigured's "exists but unreadable" branch.
type fakePermissionDeniedDirSource struct {
	*source.Replay
	dirs map[string]bool
}

func (f *fakePermissionDeniedDirSource) ReadDir(dir string) ([]string, error) {
	if f.dirs[dir] {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrPermission}
	}
	return f.Replay.ReadDir(dir)
}
