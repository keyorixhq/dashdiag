package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestK8sPodNeedsAttention pins the "problem pods" callout logic extracted
// from printK8sReport — each condition is independently tested so a future
// change to one can't silently stop flagging another (the cmd verdict tally
// drift class, #275).
func TestK8sPodNeedsAttention(t *testing.T) {
	cases := []struct {
		name string
		pod  models.K8sPodInfo
		want bool
	}{
		{"healthy running", models.K8sPodInfo{Status: "Running", Ready: "1/1"}, false},
		{"completed job", models.K8sPodInfo{Status: "Completed", Ready: "0/1"}, false},
		{"crash looping", models.K8sPodInfo{Status: "CrashLoopBackOff"}, true},
		{"error status", models.K8sPodInfo{Status: "Error"}, true},
		{"pending", models.K8sPodInfo{Status: "Pending"}, true},
		{"oom killed", models.K8sPodInfo{Status: "OOMKilled"}, true},
		{"high restarts", models.K8sPodInfo{Status: "Running", Ready: "1/1", Restarts: 10}, true},
		{"below restart threshold", models.K8sPodInfo{Status: "Running", Ready: "1/1", Restarts: 9}, false},
		// 0/1 Running = container reports Running but isn't actually ready —
		// the specific false-OK this predicate exists to catch.
		{"running but not ready", models.K8sPodInfo{Status: "Running", Ready: "0/1"}, true},
	}
	for _, c := range cases {
		if got := k8sPodNeedsAttention(c.pod); got != c.want {
			t.Errorf("%s: k8sPodNeedsAttention(%+v) = %v, want %v", c.name, c.pod, got, c.want)
		}
	}
}
