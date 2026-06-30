package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RancherCollector reports Rancher (SUSE's Kubernetes management platform) health on a
// cluster where it's installed. Gated on a usable kubectl; the real "is Rancher here"
// test is the cattle-system namespace, queried in Collect, so it's silent on every
// non-Rancher cluster.
type RancherCollector struct{}

func NewRancherCollector() *RancherCollector       { return &RancherCollector{} }
func (c *RancherCollector) Name() string           { return "Rancher" }
func (c *RancherCollector) Timeout() time.Duration { return 12 * time.Second }

// RancherAvailable gates inclusion on a usable kubectl (any k8s node). The
// cattle-system check that actually decides "Rancher present" needs a cluster query.
func RancherAvailable() bool { return K8sAvailable() }

func (c *RancherCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.RancherInfo{}
	bin := k8sDetectBin()
	if bin == "" {
		return info, nil
	}
	// cattle-system namespace == Rancher is installed here. A failed query (non-root /
	// no kubeconfig / API down) leaves Available=false and the check silent — like the
	// k8s collector's APIReachable, dsd does not invent a verdict it couldn't measure.
	out, err := k8sRun(ctx, bin, "get", "namespace", "cattle-system", "-o", "name")
	if err != nil || !strings.Contains(out, "cattle-system") {
		return info, nil
	}
	info.Available = true
	info.ServerReady, info.ServerDesired = rancherDeployReady(ctx, bin, "rancher", "cattle-system")
	info.WebhookReady, info.WebhookDesired = rancherDeployReady(ctx, bin, "rancher-webhook", "cattle-system")
	return info, nil
}

// rancherDeployReady parses the READY column ("ready/desired") of `kubectl get deploy
// <name> -n <ns> --no-headers`. Returns (0,0) when the deployment is absent or
// unreadable — a missing webhook is simply not flagged, not a false WARN.
func rancherDeployReady(ctx context.Context, bin, name, ns string) (ready, desired int) {
	out, err := k8sRun(ctx, bin, "get", "deploy", name, "-n", ns, "--no-headers")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return 0, 0
	}
	rd := strings.SplitN(fields[1], "/", 2)
	if len(rd) != 2 {
		return 0, 0
	}
	ready, _ = strconv.Atoi(rd[0])
	desired, _ = strconv.Atoi(rd[1])
	return ready, desired
}
