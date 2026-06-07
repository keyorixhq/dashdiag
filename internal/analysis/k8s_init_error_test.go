package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Pods stuck in Init:Error (failing init container) were uncounted: the
// crash-loop count keys off pod.Status ("Init:CrashLoopBackOff" matches, but
// "Init:Error" doesn't), and InitError was parsed but never surfaced.
func TestCheckK8sPodHealth_InitError(t *testing.T) {
	// A pod in Init:Error -> WARN naming it; not double-counted as crash loop.
	got := checkK8sPodHealth(models.K8sInfo{
		Pods: []models.K8sPodInfo{
			{Namespace: "prod", Name: "web", Status: "Init:Error", InitError: "Error"},
		},
	})
	if !hasLevel(got, "WARN") {
		t.Fatalf("Init:Error pod should WARN, got %+v", got)
	}
	found := false
	for _, ins := range got {
		if strings.Contains(ins.Message, "init errors") && strings.Contains(ins.Message, "prod/web") {
			found = true
		}
	}
	if !found {
		t.Errorf("want an init-errors message naming prod/web, got %+v", got)
	}

	// Init:CrashLoopBackOff is handled by the crash-loop count — must NOT also
	// produce the init-errors WARN (no double-warn).
	noDouble := checkK8sPodHealth(models.K8sInfo{
		CrashLooping: 1,
		Pods: []models.K8sPodInfo{
			{Namespace: "prod", Name: "api", Status: "Init:CrashLoopBackOff", InitError: "CrashLoopBackOff"},
		},
	})
	for _, ins := range noDouble {
		if strings.Contains(ins.Message, "init errors") {
			t.Errorf("Init:CrashLoopBackOff must not produce the init-errors WARN, got %+v", ins)
		}
	}

	// Healthy pods -> no init-error insight.
	for _, ins := range checkK8sPodHealth(models.K8sInfo{Pods: []models.K8sPodInfo{{Name: "ok", Status: "Running"}}}) {
		if strings.Contains(ins.Message, "init errors") {
			t.Errorf("healthy pod must not warn init errors, got %+v", ins)
		}
	}
}
