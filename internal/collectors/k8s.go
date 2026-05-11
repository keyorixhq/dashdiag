package collectors

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// K8sCollector reads cluster health via kubectl or k3s kubectl.
// No kubeconfig needed when running on the control plane node.
type K8sCollector struct{}

func NewK8sCollector() *K8sCollector { return &K8sCollector{} }

func (c *K8sCollector) Name() string           { return "K8s" }
func (c *K8sCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *K8sCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.K8sInfo{}

	// Detect kubectl binary: prefer k3s kubectl, fall back to kubectl
	bin := k8sDetectBin()
	if bin == "" {
		return info, nil // no k8s on this host
	}
	info.Detected = true
	info.KubeBin = bin

	// Nodes
	nodeOut, err := k8sRun(ctx, bin, "get", "nodes", "--no-headers")
	if err == nil {
		info.Nodes = parseK8sNodes(nodeOut)
		for _, n := range info.Nodes {
			if n.Status != "Ready" {
				info.NodesNotReady++
			}
		}
	}

	// Pods (all namespaces)
	podOut, err := k8sRun(ctx, bin, "get", "pods", "-A", "--no-headers")
	if err == nil {
		info.Pods = parseK8sPods(podOut)
		for _, p := range info.Pods {
			switch {
			case strings.Contains(p.Status, "CrashLoop") || strings.Contains(p.Status, "Error"):
				info.CrashLooping++
			case p.Status == "Pending":
				info.Pending++
			case strings.HasPrefix(p.Ready, "0/") && p.Status == "Running":
				info.PodsNotReady++ // container not ready (e.g. metrics-server 0/1)
			}
			if p.Restarts >= 10 {
				info.HighRestarts++
			}
		}
	}

	return info, nil
}

// k8sDetectBin returns the kubectl binary to use, or "" if none found.
func k8sDetectBin() string {
	// k3s kubectl — most common on single-node clusters
	if path, err := exec.LookPath("k3s"); err == nil {
		_ = path
		return "k3s kubectl"
	}
	// Standard kubectl
	if _, err := exec.LookPath("kubectl"); err == nil {
		return "kubectl"
	}
	return ""
}

// k8sRun runs a kubectl command and returns stdout.
func k8sRun(ctx context.Context, bin string, args ...string) (string, error) {
	// bin may be "k3s kubectl" — split it
	parts := strings.Fields(bin)
	parts = append(parts, args...)
	return runCmd(ctx, parts[0], parts[1:]...)
}

// parseK8sNodes parses `kubectl get nodes --no-headers` output.
// Format: NAME  STATUS  ROLES  AGE  VERSION
func parseK8sNodes(out string) []models.K8sNodeInfo {
	var nodes []models.K8sNodeInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		nodes = append(nodes, models.K8sNodeInfo{
			Name:    fields[0],
			Status:  fields[1],
			Roles:   fields[2],
			Age:     fields[3],
			Version: fields[4],
		})
	}
	return nodes
}

// parseK8sPods parses `kubectl get pods -A --no-headers` output.
// Format: NAMESPACE  NAME  READY  STATUS  RESTARTS  AGE
// Restarts field may be "9 (16m ago)" — last field is always age.
func parseK8sPods(out string) []models.K8sPodInfo {
	var pods []models.K8sPodInfo
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Age is always last field. Restarts may be "9" or "9 (16m ago)" = 2 tokens
		age := fields[len(fields)-1]
		// Restarts is the token before age (or before "(Xm ago) age")
		restartIdx := len(fields) - 2
		if restartIdx > 0 && strings.HasSuffix(fields[restartIdx], ")") {
			// "(16m ago)" → skip back one more
			restartIdx--
		}
		restarts, _ := strconv.Atoi(fields[restartIdx])

		pods = append(pods, models.K8sPodInfo{
			Namespace: fields[0],
			Name:      fields[1],
			Ready:     fields[2],
			Status:    fields[3],
			Restarts:  restarts,
			Age:       age,
		})
	}
	return pods
}
