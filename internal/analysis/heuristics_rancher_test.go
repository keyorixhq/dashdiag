package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckRancher(t *testing.T) {
	if got := checkRancher(models.RancherInfo{Available: false}); got != nil {
		t.Error("absent Rancher must be nil (silent on non-Rancher clusters)")
	}
	if got := checkRancher(models.RancherInfo{Available: true, ServerReady: 1, ServerDesired: 1}); len(got) != 0 {
		t.Errorf("fully-ready Rancher must be silent, got %+v", got)
	}
	if !hasInsightMsg(checkRancher(models.RancherInfo{Available: true, ServerReady: 0, ServerDesired: 1}), "WARN", "management plane is degraded") {
		t.Error("Rancher server 0/1 must WARN (degraded mgmt plane)")
	}
	if !hasInsightMsg(checkRancher(models.RancherInfo{Available: true, ServerReady: 1, ServerDesired: 1, WebhookReady: 0, WebhookDesired: 2}), "WARN", "rancher-webhook") {
		t.Error("degraded rancher-webhook must WARN")
	}
}
