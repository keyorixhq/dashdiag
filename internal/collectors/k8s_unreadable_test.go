package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func withK8sBundle(t *testing.T, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	seed(b)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })
}

// DD-COLLECTOR-GAPS-1 High #2: events/PVCs/workloads fail independently of the
// APIReachable gate. A forbidden `kubectl get` must set its own sentinel instead
// of leaving a clean-looking zero count.
func TestCollectK8s_ForbiddenQueriesSetOwnSentinels(t *testing.T) {
	withK8sBundle(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "events", "-A", "--field-selector", "type=Warning", "--sort-by=.lastTimestamp", "--no-headers"}, "", 1)
		b.PutCmd("kubectl", []string{"get", "pvc", "-A", "--no-headers"}, "", 1)
		b.PutCmd("kubectl", []string{"get", "deploy", "-A", "--no-headers"}, "", 1)
		b.PutCmd("kubectl", []string{"get", "statefulset", "-A", "--no-headers"}, "", 1)
	})
	info := &models.K8sInfo{APIReachable: true}
	collectK8sEvents(context.Background(), "kubectl", info)
	collectK8sPVCs(context.Background(), "kubectl", info)
	collectK8sWorkloads(context.Background(), "kubectl", info)
	if !info.EventsUnreadable || !info.PVCsUnreadable || !info.WorkloadsUnreadable {
		t.Fatalf("sentinels = events:%v pvcs:%v workloads:%v, want all true", info.EventsUnreadable, info.PVCsUnreadable, info.WorkloadsUnreadable)
	}
}

// Positive control: "No resources found" (exit 0) is a genuine empty result, not
// a sentinel.
func TestCollectK8s_EmptySuccessfulQueriesAreClean(t *testing.T) {
	withK8sBundle(t, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "pvc", "-A", "--no-headers"}, "", 0)
		b.PutCmd("kubectl", []string{"get", "deploy", "-A", "--no-headers"}, "", 0)
		b.PutCmd("kubectl", []string{"get", "statefulset", "-A", "--no-headers"}, "", 0)
	})
	info := &models.K8sInfo{APIReachable: true}
	collectK8sPVCs(context.Background(), "kubectl", info)
	collectK8sWorkloads(context.Background(), "kubectl", info)
	if info.PVCsUnreadable || info.WorkloadsUnreadable {
		t.Fatalf("clean empty result set a sentinel: %+v", info)
	}
}
