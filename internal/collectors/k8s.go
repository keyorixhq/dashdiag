package collectors

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		info.OSLayer = collectK8sOSLayer(ctx, bin)
	}

	return info, nil
}

// ── nodes ─────────────────────────────────────────────────────────────────────

func collectK8sNodes(ctx context.Context, bin string, info *models.K8sInfo) {
	data, err := k8sRunJSON(ctx, bin, "get", "nodes", "-o", "json")
	if err != nil {
		return
	}
	var result struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
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
		return
	}
	for _, item := range result.Items {
		node := models.K8sNodeInfo{
			Name:       item.Metadata.Name,
			Version:    item.Status.NodeInfo.KubeletVersion,
			Conditions: map[string]string{},
		}
		// Roles from taints
		for _, t := range item.Spec.Taints {
			if strings.Contains(t.Key, "control-plane") || strings.Contains(t.Key, "master") {
				node.Roles = "control-plane"
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
					info.NodesNotReady++
				}
			}
		}
		info.Nodes = append(info.Nodes, node)
	}
}

// ── pods ──────────────────────────────────────────────────────────────────────

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

	crashNames := map[string]bool{}
	for _, item := range result.Items {
		pod := models.K8sPodInfo{
			Namespace:   item.Metadata.Namespace,
			Name:        item.Metadata.Name,
			Status:      item.Status.Phase,
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
		updatePodCounts(info, &pod, maxRestarts, crashNames)
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
func updatePodCounts(info *models.K8sInfo, pod *models.K8sPodInfo, maxRestarts int, crashNames map[string]bool) {
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
	if maxRestarts >= 10 {
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
	count := 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || count >= 10 {
			break
		}
		ev := models.K8sEvent{
			Namespace: fields[0],
			Age:       fields[1],
			Reason:    fields[3],
		}
		// Name: fields[4] (type/name format)
		parts := strings.SplitN(fields[4], "/", 2)
		if len(parts) == 2 {
			ev.Name = parts[1]
		} else {
			ev.Name = fields[4]
		}
		if len(fields) > 5 {
			ev.Message = strings.Join(fields[5:], " ")
		}
		info.Events = append(info.Events, ev)
		count++
	}
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

func collectK8sOSLayer(ctx context.Context, bin string) *models.K8sOSLayer {
	layer := &models.K8sOSLayer{}

	// kubelet
	out, err := runCmd(ctx, "systemctl", "is-active", "kubelet", "k3s")
	if err == nil {
		layer.KubeletActive = strings.Contains(out, "active")
	}
	if layer.KubeletActive {
		logOut, _ := runCmd(ctx, "journalctl", "-u", "kubelet", "-u", "k3s",
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

	// containerd
	_, err = runCmd(ctx, "systemctl", "is-active", "containerd")
	layer.ContainerdActive = err == nil

	// IP forwarding — leave IPForwardChecked false when /proc is unreadable so
	// the heuristic treats it as "unknown" rather than a false "disabled" CRIT.
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil { // #nosec G304
		layer.IPForwardChecked = true
		layer.IPForwardEnabled = strings.TrimSpace(string(data)) == "1"
	}

	// Flannel subnet.env
	_, err = os.Stat("/run/flannel/subnet.env")
	layer.FlannelSubnetOK = err == nil

	// CNI binaries
	entries, _ := os.ReadDir("/opt/cni/bin")
	layer.CNIBinsOK = len(entries) > 0

	// KUBE-FORWARD chain check (iptables or nft)
	nftOut, _ := runCmd(ctx, "nft", "list", "tables")
	if strings.Contains(nftOut, "kube") {
		layer.KubeForwardChain = true
	} else {
		iptOut, _ := runCmd(ctx, "iptables", "-L", "KUBE-FORWARD", "-n")
		layer.KubeForwardChain = !strings.Contains(iptOut, "No chain")
	}

	// firewalld masquerade (Flannel requirement)
	masqOut, _ := runCmd(ctx, "firewall-cmd", "--query-masquerade")
	layer.FirewalldMasquOK = strings.TrimSpace(masqOut) == "yes"

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
	certs, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
	now := time.Now()
	for _, certPath := range certs {
		data, err := os.ReadFile(certPath) // #nosec G304
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
		} else if daysLeft < 30 && (layer.CertExpirySoonDays == 0 || daysLeft < layer.CertExpirySoonDays) {
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
	// Direct path checks first (sudo safe paths)
	directPaths := []struct{ bin, bin2 string }{
		{"/usr/local/bin/k3s", "k3s"},
		{"/usr/bin/k3s", "k3s"},
		{"/usr/local/bin/kubectl", "kubectl"},
		{"/usr/bin/kubectl", "kubectl"},
		{"/snap/bin/microk8s", "microk8s"},
		{"/usr/bin/microk8s", "microk8s"},
	}
	for _, p := range directPaths {
		if _, err := os.Stat(p.bin); err == nil {
			if p.bin2 == "k3s" {
				return p.bin + " kubectl"
			}
			if p.bin2 == "microk8s" {
				return p.bin + " kubectl"
			}
			return p.bin
		}
	}
	// Fall back to PATH lookup
	if _, err := exec.LookPath("k3s"); err == nil {
		return "k3s kubectl"
	}
	if _, err := exec.LookPath("microk8s"); err == nil {
		return "microk8s kubectl"
	}
	if _, err := exec.LookPath("kubectl"); err == nil {
		return "kubectl"
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
