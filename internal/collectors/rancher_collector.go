package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const rancherNamespace = "cattle-system"

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

func (c *RancherCollector) Collect(ctx context.Context) (any, error) {
	info := &models.RancherInfo{}
	bin := k8sDetectBin()
	if bin == "" {
		return info, nil
	}
	// cattle-system namespace == Rancher is installed here. A failed query (non-root /
	// no kubeconfig / API down) leaves Available=false and the check silent — like the
	// k8s collector's APIReachable, dsd does not invent a verdict it couldn't measure.
	out, err := k8sRun(ctx, bin, "get", "namespace", rancherNamespace, "-o", "name")
	if err != nil || !strings.Contains(out, rancherNamespace) {
		return info, nil //nolint:nilerr // namespace query failed or absent: Available stays false; cluster reachability is K8sCollector's APIReachable, not duplicated here
	}
	info.Available = true
	var serverOK, webhookOK bool
	info.ServerReady, info.ServerDesired, serverOK = rancherDeployReady(ctx, bin, "rancher", rancherNamespace)
	info.WebhookReady, info.WebhookDesired, webhookOK = rancherDeployReady(ctx, bin, "rancher-webhook", rancherNamespace)
	info.ServerUnreadable = !serverOK
	info.WebhookUnreadable = !webhookOK
	return info, nil
}

// rancherDeployReady parses the READY column ("ready/desired") of `kubectl get deploy
// <name> -n <ns> --no-headers`. Returns (0,0,true) when the deployment is genuinely
// absent (kubectl "NotFound") — a missing webhook is simply not flagged, not a false
// WARN — and (0,0,false) when the query failed or its output could not be parsed
// (forbidden, timeout), which the caller reports as unreadable.
func rancherDeployReady(ctx context.Context, bin, name, ns string) (ready, desired int, readable bool) {
	parts := append(strings.Fields(bin), "get", "deploy", name, "-n", ns, "--no-headers")
	// Combined output: kubectl's NotFound/Forbidden verdict is on stderr, which
	// runCmd drops.
	out, err := runCmdCombined(ctx, parts[0], parts[1:]...)
	if err != nil {
		return 0, 0, strings.Contains(out, "NotFound")
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return 0, 0, false
	}
	rd := strings.SplitN(fields[1], "/", 2)
	if len(rd) != 2 {
		return 0, 0, false
	}
	ready, _ = strconv.Atoi(rd[0])
	desired, _ = strconv.Atoi(rd[1])
	return ready, desired, true
}
