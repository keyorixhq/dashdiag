package collectors

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// K8sCollector reads cluster health via kubectl or k3s kubectl.
// No kubeconfig needed when running on the control plane node.
// Uses JSON output for rich pod metadata (Spec 23 + addendums 23a–23g).
type K8sCollector struct {
	Deep bool // set true for OS-layer checks
}

func NewK8sCollector() *K8sCollector     { return &K8sCollector{} }
func NewK8sDeepCollector() *K8sCollector { return &K8sCollector{Deep: true} }

func (c *K8sCollector) Name() string           { return "K8s" }
func (c *K8sCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *K8sCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.K8sInfo{}

	bin := k8sDetectBin()
	if bin == "" {
		return info, nil
	}
	info.Detected = true
	info.KubeBin = bin
	info.Distribution = k8sDistribution()

	// Nodes with conditions
	collectK8sNodes(ctx, bin, info)

	// Pods — single JSON call covers all addendums (23a–23c, 23f)
	collectK8sPods(ctx, bin, info)

	// Warning events
	collectK8sEvents(ctx, bin, info)

	// PVCs
	collectK8sPVCs(ctx, bin, info)

	// Deployments + StatefulSets
	collectK8sWorkloads(ctx, bin, info)

	// OS-layer deep checks (only on k8s nodes, only with --deep)
	if c.Deep {
		info.OSLayer = collectK8sOSLayer(ctx, bin, info.Distribution)
	}

	return info, nil
}

// ── nodes ─────────────────────────────────────────────────────────────────────

func collectK8sNodes(ctx context.Context, bin string, info *models.K8sInfo) {
	data, err := k8sRunJSON(ctx, bin, "get", "nodes", "-o", "json")
	if err != nil {
		return
	}
	nodes, notReady, ok := parseK8sNodes(data)
	if !ok {
		return
	}
	info.APIReachable = true // a `get nodes` that parsed means the API answered
	info.Nodes = append(info.Nodes, nodes...)
	info.NodesNotReady += notReady
}

// parseK8sNodes parses `kubectl get nodes -o json` into node info. Returned
// separately from collectK8sNodes so the role/status logic is unit-testable
// without shelling out. ok is false when the payload doesn't parse.
func parseK8sNodes(data []byte) (nodes []models.K8sNodeInfo, notReady int, ok bool) {
	var result struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
			Spec struct {
				Taints []struct {
					Key string `json:"key"`
				} `json:"taints"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, 0, false
	}
	for _, item := range result.Items {
		node := models.K8sNodeInfo{
			Name:       item.Metadata.Name,
			Version:    item.Status.NodeInfo.KubeletVersion,
			Conditions: map[string]string{},
		}
		// Roles come from node-role.kubernetes.io/<role> labels — the same
		// source kubectl uses for its ROLES column. Taints are NOT a reliable
		// signal: a single-node k3s control-plane is untainted (it schedules
		// workloads by default), which would otherwise mislabel it "worker".
		var roles []string
		for k := range item.Metadata.Labels {
			if r := strings.TrimPrefix(k, "node-role.kubernetes.io/"); r != k && r != "" {
				roles = append(roles, r)
			}
		}
		sort.Strings(roles)
		node.Roles = strings.Join(roles, ",")
		// Fallback: derive control-plane from taints when labels are absent,
		// then default to worker so the field is never empty.
		if node.Roles == "" {
			for _, t := range item.Spec.Taints {
				if strings.Contains(t.Key, "control-plane") || strings.Contains(t.Key, "master") {
					node.Roles = "control-plane"
				}
			}
		}
		if node.Roles == "" {
			node.Roles = "worker"
		}
		for _, c := range item.Status.Conditions {
			node.Conditions[c.Type] = c.Status
			if c.Type == "Ready" {
				if c.Status == "True" {
					node.Status = "Ready"
				} else {
					node.Status = "NotReady"
					notReady++
				}
			}
		}
		nodes = append(nodes, node)
	}
	return nodes, notReady, true
}

// ── pods ──────────────────────────────────────────────────────────────────────

// podAge renders a pod's age from its RFC3339 creationTimestamp in kubectl's
// compact short form (e.g. "24s", "5m", "3h", "13d"). Returns "" if the timestamp
// is absent or unparseable, so the column simply blanks rather than showing junk.
// Uses NowViaSource so the value is stable under capture/replay (capture-time now).
func podAge(creationTimestamp string) string {
	if creationTimestamp == "" {
		return ""
	}
	created, err := time.Parse(time.RFC3339, creationTimestamp)
	if err != nil {
		return ""
	}
	d := NowViaSource().Sub(created)
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	}
}

func collectK8sPods(ctx context.Context, bin string, info *models.K8sInfo) {
	data, err := k8sRunJSON(ctx, bin, "get", "pods", "-A", "-o", "json")
	if err != nil {
		return
	}
	var result struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				DeletionTimestamp string `json:"deletionTimestamp"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
				InitContainers []struct {
					Name string `json:"name"`
				} `json:"initContainers"`
			} `json:"spec"`
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					Ready        bool `json:"ready"`
					RestartCount int  `json:"restartCount"`
					State        struct {
						Waiting struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
					LastTerminationState struct {
						Terminated struct {
							Message string `json:"message"`
						} `json:"terminated"`
					} `json:"lastState"`
				} `json:"containerStatuses"`
				InitContainerStatuses []struct {
					State struct {
						Waiting struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"initContainerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return
	}
	info.APIReachable = true // pods listed (covers restricted-RBAC keys that can't get nodes)

	crashNames := map[string]bool{}
	for _, item := range result.Items {
		pod := models.K8sPodInfo{
			Namespace:   item.Metadata.Namespace,
			Name:        item.Metadata.Name,
			Status:      item.Status.Phase,
			Age:         podAge(item.Metadata.CreationTimestamp),
			Terminating: item.Metadata.DeletionTimestamp != "",
		}
		if len(item.Spec.Containers) > 0 {
			pod.Image = item.Spec.Containers[0].Image
		}
		ready := 0
		maxRestarts := 0
		for _, cs := range item.Status.ContainerStatuses {
			if cs.Ready {
				ready++
			}
			if cs.RestartCount > maxRestarts {
				maxRestarts = cs.RestartCount
			}
			if cs.State.Waiting.Reason != "" {
				pod.Status = cs.State.Waiting.Reason
			}
			if msg := cs.LastTerminationState.Terminated.Message; msg != "" {
				pod.TerminationMsg = msg
			}
		}
		pod.Ready = fmt.Sprintf("%d/%d", ready, len(item.Status.ContainerStatuses))
		pod.Restarts = maxRestarts
		pod.InitError = parseInitError(item.Status.InitContainerStatuses, item.Spec.InitContainers)
		fullyReady := len(item.Status.ContainerStatuses) > 0 && ready == len(item.Status.ContainerStatuses)
		updatePodCounts(info, &pod, maxRestarts, fullyReady, crashNames)
		info.Pods = append(info.Pods, pod)
	}
	fetchPreviousLogs(ctx, bin, info, crashNames)
}

// parseInitError returns the first init container error reason string.
func parseInitError(
	statuses []struct {
		State struct {
			Waiting struct {
				Reason string `json:"reason"`
			} `json:"waiting"`
		} `json:"state"`
	},
	containers []struct {
		Name string `json:"name"`
	},
) string {
	for i, ic := range statuses {
		if r := ic.State.Waiting.Reason; r == "Error" || strings.Contains(r, "CrashLoop") {
			name := ""
			if i < len(containers) {
				name = containers[i].Name
			}
			return name + ":" + r
		}
	}
	return ""
}

// updatePodCounts increments the relevant counters on K8sInfo.
func updatePodCounts(info *models.K8sInfo, pod *models.K8sPodInfo, maxRestarts int, fullyReady bool, crashNames map[string]bool) {
	switch {
	case strings.Contains(pod.Status, "CrashLoop") || pod.Status == "Error":
		info.CrashLooping++
		if maxRestarts >= 3 {
			crashNames[pod.Namespace+"/"+pod.Name] = true
		}
	case pod.Status == "Pending":
		info.Pending++
	case strings.HasPrefix(pod.Ready, "0/") && pod.Status == "Running":
		info.PodsNotReady++
	}
	// restartCount is cumulative over the pod's lifetime; a pod that is currently
	// fully ready has recovered, so its high count is historical, not active
	// instability (live flapping shows up as CrashLoopBackOff / not-ready above).
	if maxRestarts >= 10 && !fullyReady {
		info.HighRestarts++
	}
	if pod.Terminating {
		info.Terminating++
	}
}

// fetchPreviousLogs retrieves the last 10 log lines for crash-looping pods.
func fetchPreviousLogs(ctx context.Context, bin string, info *models.K8sInfo, crashNames map[string]bool) {
	count := 0
	for i := range info.Pods {
		p := &info.Pods[i]
		if !crashNames[p.Namespace+"/"+p.Name] || count >= 5 {
			continue
		}
		logCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		logs, err := k8sRun(logCtx, bin, "logs", "--previous", "--tail=10",
			"-n", p.Namespace, p.Name)
		cancel()
		if err == nil && logs != "" {
			p.PreviousLogs = logs
		}
		count++
	}
}

// ── events ────────────────────────────────────────────────────────────────────

func collectK8sEvents(ctx context.Context, bin string, info *models.K8sInfo) {
	out, err := k8sRun(ctx, bin, "get", "events", "-A",
		"--field-selector", "type=Warning",
		"--sort-by=.lastTimestamp",
		"--no-headers")
	if err != nil {
		return
	}
	info.Events = append(info.Events, parseK8sWarningEvents(out)...)
}

// parseK8sWarningEvents parses `kubectl get events --field-selector type=Warning
// --sort-by=.lastTimestamp --no-headers` and returns the 10 MOST RECENT warning
// events. Two fixes over the original loop:
//   - kubectl sorts ascending (oldest first), so the most recent events are at the
//     END — keep the tail, not the head. Keeping the head showed stale warnings
//     and could miss a recent one (e.g. the flannel subnet.env CRIT hint).
//   - a short/blank line is SKIPPED, not treated as end-of-input. The old
//     `len(fields) < 5 || count >= 10 { break }` aborted all collection on the
//     first malformed line (e.g. a trailing blank line).
func parseK8sWarningEvents(out string) []models.K8sEvent {
	var evs []models.K8sEvent
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ev := models.K8sEvent{
			Namespace: fields[0],
			Age:       fields[1],
			Reason:    fields[3],
		}
		// Name: fields[4] is "type/name" format.
		parts := strings.SplitN(fields[4], "/", 2)
		if len(parts) == 2 {
			ev.Name = parts[1]
		} else {
			ev.Name = fields[4]
		}
		if len(fields) > 5 {
			ev.Message = strings.Join(fields[5:], " ")
		}
		evs = append(evs, ev)
	}
	const maxEvents = 10
	if len(evs) > maxEvents {
		evs = evs[len(evs)-maxEvents:] // most recent (sorted ascending → tail)
	}
	return evs
}

// ── PVCs ──────────────────────────────────────────────────────────────────────

func collectK8sPVCs(ctx context.Context, bin string, info *models.K8sInfo) {
	out, err := k8sRun(ctx, bin, "get", "pvc", "-A", "--no-headers")
	if err != nil {
		return // no PVCs configured is normal
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pvc := models.K8sPVCInfo{
			Namespace: fields[0],
			Name:      fields[1],
			Status:    fields[2],
		}
		if len(fields) > 3 {
			pvc.Capacity = fields[3]
		}
		if pvc.Status != "Bound" {
			info.PVCsNotBound++
		}
		info.PVCs = append(info.PVCs, pvc)
	}
}

// ── workloads ─────────────────────────────────────────────────────────────────

func collectK8sWorkloads(ctx context.Context, bin string, info *models.K8sInfo) {
	for _, kind := range []string{"deploy", "statefulset"} {
		out, err := k8sRun(ctx, bin, "get", kind, "-A", "--no-headers")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// Format: NAMESPACE  NAME  READY  UP-TO-DATE  AVAILABLE  AGE
			// READY is "1/1" format
			readyParts := strings.SplitN(fields[2], "/", 2)
			if len(readyParts) != 2 {
				continue
			}
			ready, _ := strconv.Atoi(readyParts[0])
			desired, _ := strconv.Atoi(readyParts[1])
			w := models.K8sWorkloadInfo{
				Namespace: fields[0],
				Name:      fields[1],
				Kind:      strings.ToTitle(kind[:1]) + kind[1:],
				Ready:     ready,
				Desired:   desired,
			}
			if ready < desired {
				info.WorkloadsDown++
			}
			info.Workloads = append(info.Workloads, w)
		}
	}
}

// ── OS-layer deep checks ──────────────────────────────────────────────────────

// flannelCNIConfigured reports whether flannel is the CNI in use, by looking for a
// flannel CNI config in /etc/cni/net.d (by filename or content). Non-flannel CNIs
// (Calico/Cilium/Weave) drop their own configs there and never create flannel's
// /run/flannel/subnet.env, so its absence is only a problem when flannel is actually
// configured.
func flannelCNIConfigured() bool {
	// kubeadm writes CNI configs to /etc/cni/net.d; k3s keeps them under
	// /var/lib/rancher/k3s/agent/etc/cni/net.d (and only symlinks /etc/cni/net.d
	// on some setups), so check both before deciding flannel isn't in use.
	for _, dir := range []string{"/etc/cni/net.d", "/var/lib/rancher/k3s/agent/etc/cni/net.d"} {
		entries, err := readDirNames(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e), "flannel") {
				return true
			}
			data, err := readFile(filepath.Join(dir, e)) // #nosec G304 -- CNI conf dir
			if err == nil && strings.Contains(strings.ToLower(string(data)), "flannel") {
				return true
			}
		}
	}
	return false
}

// k8sUnitActive reports whether ANY of the named systemd units is active, probing
// each singly (a multi-unit `systemctl is-active a b` exits non-zero unless ALL
// exist and are active, which breaks on k3s where only k3s/k3s-agent exist).
func k8sUnitActive(ctx context.Context, units ...string) bool {
	for _, u := range units {
		if out, err := runCmd(ctx, "systemctl", "is-active", u); err == nil && strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return false
}

// k8sBundledContainerdSockPresent reports whether any k8s distro's bundled containerd
// socket exists — k3s/RKE2 (/run/k3s/containerd/containerd.sock), k0s
// (/run/k0s/containerd.sock), or MicroK8s (/var/snap/microk8s/common/run/containerd.sock).
// These distros run containerd embedded (no host containerd.service), so a healthy node
// would otherwise read as "containerd not active".
func k8sBundledContainerdSockPresent() bool {
	for _, sock := range []string{
		"/run/k3s/containerd/containerd.sock",
		"/run/k0s/containerd.sock",
		"/var/snap/microk8s/common/run/containerd.sock",
	} {
		if fileExists(sock) {
			return true
		}
	}
	return false
}

// cniBinsPresent reports whether CNI plugin binaries are installed and whether the
// check could be made. kubeadm uses /opt/cni/bin; k3s bundles them under
// /var/lib/rancher/k3s/data/current/bin — checking only the former false-CRIT'd
// every k3s node. checked is false only when every candidate was unreadable
// (permission denied), so the verdict treats that as unknown, not "missing".
func cniBinsPresent() (checked, ok bool) {
	return cniBinsPresentIn("/opt/cni/bin", "/var/lib/rancher/k3s/data/current/bin")
}

func cniBinsPresentIn(dirs ...string) (checked, ok bool) {
	for _, d := range dirs {
		entries, err := readDirNames(d)
		switch {
		case err == nil:
			checked = true
			if len(entries) > 0 {
				return true, true // a populated CNI bin dir — done
			}
		case os.IsNotExist(err):
			checked = true // this path is absent, but another may hold the bins
		default:
			// permission denied / other — state unknown for this candidate
		}
	}
	return checked, false
}

// detectKubeForward reports whether the KUBE-FORWARD chain (kube-proxy) is present,
// and whether it could be verified at all. nft is tried first, then iptables. If
// neither tool can run (e.g. k3s, which keeps iptables off the host PATH), checked is
// false so the verdict treats it as unknown rather than a false "present" or "missing".
func detectKubeForward(ctx context.Context) (checked, present bool) {
	nftOut, nftErr := runCmd(ctx, "nft", "list", "tables")
	if nftErr == nil && strings.Contains(nftOut, "kube") {
		return true, true
	}
	if iptOut, iptErr := runCmd(ctx, "iptables", "-L", "KUBE-FORWARD", "-n"); iptErr == nil {
		return true, !strings.Contains(iptOut, "No chain")
	}
	if nftErr == nil {
		return true, false // nft ran (no kube table) and iptables unavailable
	}
	return false, false // neither tool available — unknown
}

func collectK8sOSLayer(ctx context.Context, bin, distribution string) *models.K8sOSLayer {
	layer := &models.K8sOSLayer{}

	// KubeletChecked/ContainerdChecked gate on an on-disk node marker (k8sDistribution,
	// computed by the caller), NOT on live daemon state. A host running `kubectl`
	// against a remote cluster (e.g. a laptop with a cloud kubeconfig) has neither
	// kubelet nor containerd installed at all — that must read as "not applicable",
	// never as a false "kubelet down" CRIT. Only a host actually provisioned as a node
	// (rke2/k3s/k0s/microk8s/kubeadm markers present) gets a real verdict here.
	layer.KubeletChecked = distribution != ""
	layer.ContainerdChecked = distribution != ""

	// kubelet. Most distros embed/wrap the kubelet under a distro-specific unit rather
	// than a standalone kubelet.service: k3s → k3s / k3s-agent; RKE2 → rke2-server /
	// rke2-agent; k0s → k0scontroller / k0sworker; MicroK8s → snap.microk8s.daemon-
	// kubelite. Probing only kubelet/k3s (the old list) false-read every non-k3s
	// embedded-kubelet node as "kubelet inactive" (found on live RKE2/k0s/MicroK8s,
	// 2026-07-01). Probe each known unit singly (k8sUnitActive returns true on the
	// first active one).
	layer.KubeletActive = k8sUnitActive(ctx, "kubelet", "k3s", "k3s-agent",
		"rke2-server", "rke2-agent", "k0scontroller", "k0sworker",
		"snap.microk8s.daemon-kubelite")
	if layer.KubeletActive {
		logOut, _ := runCmd(ctx, "journalctl", "-u", "kubelet", "-u", "k3s",
			"-u", "rke2-server", "-u", "k0scontroller", "-u", "snap.microk8s.daemon-kubelite",
			"-n", "30", "--no-pager", "-q")
		for _, line := range strings.Split(logOut, "\n") {
			if strings.Contains(strings.ToLower(line), "error") ||
				strings.Contains(strings.ToLower(line), "failed") {
				layer.KubeletErrors = append(layer.KubeletErrors, k8sTruncate(line, 120))
			}
		}
		if len(layer.KubeletErrors) > 5 {
			layer.KubeletErrors = layer.KubeletErrors[:5]
		}
	}

	// containerd. Most distros bundle their own containerd rather than the host
	// containerd.service: k3s/RKE2 → /run/k3s/containerd/containerd.sock; k0s →
	// /run/k0s/containerd.sock; MicroK8s → snap.microk8s.daemon-containerd unit +
	// /var/snap/microk8s/common/run/containerd.sock. Recognize all so a healthy node
	// isn't reported "containerd not active".
	layer.ContainerdActive = k8sUnitActive(ctx, "containerd", "snap.microk8s.daemon-containerd")
	if !layer.ContainerdActive {
		layer.ContainerdActive = k8sBundledContainerdSockPresent()
	}

	// IP forwarding — leave IPForwardChecked false when /proc is unreadable so
	// the heuristic treats it as "unknown" rather than a false "disabled" CRIT.
	if data, err := readFile("/proc/sys/net/ipv4/ip_forward"); err == nil { // #nosec G304
		layer.IPForwardChecked = true
		layer.IPForwardEnabled = strings.TrimSpace(string(data)) == "1"
	}

	// Flannel subnet.env — only meaningful when flannel is the configured CNI. On
	// Calico/Cilium/Weave nodes /run/flannel/subnet.env never exists, so flagging its
	// absence as a CRIT was a false alarm on every non-flannel node.
	layer.FlannelInUse = flannelCNIConfigured()
	layer.FlannelSubnetOK = fileExists("/run/flannel/subnet.env")

	// CNI binaries — check both the kubeadm path (/opt/cni/bin) and the k3s bundle
	// (/var/lib/rancher/k3s/data/current/bin); only report "missing" when neither
	// holds plugins, and only when at least one path was actually readable.
	layer.CNIChecked, layer.CNIBinsOK = cniBinsPresent()

	// KUBE-FORWARD chain check (iptables or nft). The old code defaulted to "present"
	// when iptables was absent (`!Contains("", "No chain")` == true) — a false-OK, and
	// it fires nowhere useful on k3s, whose bundled iptables isn't on the host PATH.
	// Track whether a tool actually ran so the verdict can say "unknown" vs "missing".
	layer.KubeForwardChecked, layer.KubeForwardChain = detectKubeForward(ctx)

	// firewalld masquerade (Flannel requirement). Gate on firewalld actually being
	// active first (same pattern as docker.go's collectFirewalldCheck) — most k3s/RKE2
	// nodes never run firewalld at all, and `firewall-cmd --query-masquerade` fails
	// the same way whether firewalld is absent or just off. Without the gate, "absent"
	// and "on but misconfigured" collapse to the same false-negative FirewalldMasquOK.
	if out, err := runCmd(ctx, "systemctl", "is-active", "firewalld"); err == nil && strings.TrimSpace(out) == "active" {
		layer.FirewalldChecked = true
		masqOut, _ := runCmd(ctx, "firewall-cmd", "--query-masquerade")
		layer.FirewalldMasquOK = strings.TrimSpace(masqOut) == "yes"
	}

	// Certificate expiry
	certDirs := []string{
		"/etc/kubernetes/pki",
		"/var/lib/rancher/k3s/server/tls",
	}
	for _, dir := range certDirs {
		checkCertExpiry(dir, layer)
	}

	return layer
}

// checkCertExpiry scans a directory for expiring certificates.
func checkCertExpiry(dir string, layer *models.K8sOSLayer) {
	certs, _ := glob(filepath.Join(dir, "*.crt"))
	now := NowViaSource() // capture-time under replay/certify, so cert-expiry verdicts stay hermetic
	for _, certPath := range certs {
		data, err := readFile(certPath) // #nosec G304
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysLeft < 0 {
			layer.CertExpiredNames = append(layer.CertExpiredNames, filepath.Base(certPath))
		} else if daysLeft < 30 && (!layer.CertExpirySoon || daysLeft < layer.CertExpirySoonDays) {
			// Track via the CertExpirySoon flag, not a magic days value: a cert
			// expiring today (daysLeft==0) must still register. Previously 0 days
			// collided with the zero-value "none", silently reading as OK.
			layer.CertExpirySoon = true
			layer.CertExpirySoonDays = daysLeft
		}
	}
}

// k8sTruncate truncates a string for display.
func k8sTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// K8sAvailable returns true when kubectl or k3s is found on this host.
// Used by cmd/health.go to gate inclusion of the K8s collector.
func K8sAvailable() bool {
	return k8sDetectBin() != ""
}

// k8sDetectBin returns the kubectl binary to use, or "" if none found.
// Checks both PATH and common installation locations since sudo may strip PATH.
func k8sDetectBin() string {
	// RKE2 (Rancher's enterprise K8s, the typical Rancher/SLES substrate) ships its own
	// kubectl under /var/lib/rancher/rke2/bin and its kubeconfig is root-only at
	// /etc/rancher/rke2/rke2.yaml — plain `kubectl` on the host can't find the cluster
	// without it. Detect it explicitly and carry the --kubeconfig so k8sRun reaches the
	// API (k8sRun splits the bin on whitespace, so the flag rides along). Checked before
	// the generic kubectl paths because an RKE2 node often also has a bare /usr/local/bin
	// kubectl that would otherwise be picked WITHOUT the kubeconfig and fail every query.
	if fileExists("/var/lib/rancher/rke2/bin/kubectl") {
		return "/var/lib/rancher/rke2/bin/kubectl --kubeconfig=/etc/rancher/rke2/rke2.yaml"
	}
	// Direct path checks first (sudo safe paths)
	directPaths := []struct{ bin, bin2 string }{
		{"/usr/local/bin/k3s", "k3s"},
		{"/usr/bin/k3s", "k3s"},
		{"/usr/local/bin/k0s", "k0s"},
		{"/usr/bin/k0s", "k0s"},
		{"/usr/local/bin/kubectl", "kubectl"},
		{"/usr/bin/kubectl", "kubectl"},
		{"/snap/bin/microk8s", "microk8s"},
		{"/usr/bin/microk8s", "microk8s"},
	}
	for _, p := range directPaths {
		if fileExists(p.bin) {
			// k3s/k0s/microk8s are single-binary distros with no standalone kubectl —
			// they wrap it as `<bin> kubectl` (which also carries their embedded, often
			// root-only, kubeconfig). A plain kubectl gets the kubeadm admin.conf flag.
			if p.bin2 == "kubectl" {
				return p.bin + kubeadmKubeconfigFlag()
			}
			return p.bin + " kubectl"
		}
	}
	// Fall back to PATH lookup
	if _, err := lookPath("k3s"); err == nil {
		return "k3s kubectl"
	}
	if _, err := lookPath("k0s"); err == nil {
		return "k0s kubectl"
	}
	if _, err := lookPath("microk8s"); err == nil {
		return "microk8s kubectl"
	}
	if _, err := lookPath("kubectl"); err == nil {
		return "kubectl" + kubeadmKubeconfigFlag()
	}
	return ""
}

// kubeadmKubeconfigFlag returns " --kubeconfig=/etc/kubernetes/admin.conf" when a plain
// kubectl on a kubeadm control-plane node would otherwise have no kubeconfig. kubeadm
// writes its admin credential to /etc/kubernetes/admin.conf (root-readable, 0600) but
// — unlike k3s/RKE2 — does NOT place one at /root/.kube/config. So `sudo dsd k8s` /
// `sudo dsd health` ran bare kubectl, which falls back to localhost:8080 and reports
// the API "unreachable" on a perfectly healthy cluster (found live on a kubeadm node,
// 2026-07-01; the operator's own non-root run via ~/.kube/config worked fine). Gated to
// root (admin.conf is root-only) and skipped when root already has its own kubeconfig,
// so the non-root path is untouched. kubectl reads admin.conf to authenticate; its
// content is never captured (we record kubectl's output, not the credential).
func kubeadmKubeconfigFlag() string {
	return kubeadmKubeconfigFlagFor(os.Geteuid(), os.Getenv("KUBECONFIG"),
		fileExists("/root/.kube/config"), fileExists("/etc/kubernetes/admin.conf"))
}

// kubeadmKubeconfigFlagFor is the pure decision behind kubeadmKubeconfigFlag. Returns
// the admin.conf flag only as root (admin.conf is root-only), only when root has no
// kubeconfig of its own (KUBECONFIG env or /root/.kube/config), and only when admin.conf
// actually exists.
func kubeadmKubeconfigFlagFor(euid int, kubeconfigEnv string, rootKubeExists, adminConfExists bool) string {
	if euid != 0 || kubeconfigEnv != "" || rootKubeExists || !adminConfExists {
		return ""
	}
	return " --kubeconfig=/etc/kubernetes/admin.conf"
}

// k8sDistribution returns the Kubernetes distribution in use ("rke2", "k3s", "k0s",
// "microk8s", "kubeadm") from on-disk markers, or "" when undetermined. Order matters:
// RKE2 also lays down /var/lib/rancher, so check its rke2-specific path before the k3s
// one; k0s runs its own kubelet (creating /var/lib/kubelet/config.yaml), so check its
// /var/lib/k0s marker before the kubeadm one or it would misdetect as kubeadm.
func k8sDistribution() string {
	switch {
	case fileExists("/var/lib/rancher/rke2") || fileExists("/etc/rancher/rke2/rke2.yaml"):
		return "rke2"
	case fileExists("/var/lib/rancher/k3s") || fileExists("/etc/rancher/k3s/k3s.yaml"):
		return "k3s"
	case fileExists("/var/lib/k0s") || fileExists("/etc/k0s"):
		return "k0s"
	case fileExists("/var/snap/microk8s") || fileExists("/snap/bin/microk8s"):
		return "microk8s"
	case fileExists("/etc/kubernetes/manifests") || fileExists("/var/lib/kubelet/config.yaml"):
		return "kubeadm"
	}
	return ""
}

// k8sRun runs a kubectl command and returns stdout.
func k8sRun(ctx context.Context, bin string, args ...string) (string, error) {
	parts := strings.Fields(bin)
	parts = append(parts, args...)
	return runCmd(ctx, parts[0], parts[1:]...)
}

// k8sRunJSON runs a kubectl command with JSON output and returns the raw bytes.
func k8sRunJSON(ctx context.Context, bin string, args ...string) ([]byte, error) {
	out, err := k8sRun(ctx, bin, args...)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}
