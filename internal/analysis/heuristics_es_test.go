package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckElasticsearch(t *testing.T) {
	if got := checkElasticsearch(models.ElasticsearchInfo{Detected: false}); got != nil {
		t.Errorf("undetected ES should be silent, got %+v", got)
	}
	if got := checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: false}); !insightWithMsg(got, "INFO", "could not be read") {
		t.Errorf("no health read should be INFO, got %+v", got)
	}
	if got := checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: true, Status: "green"}); len(got) != 0 {
		t.Errorf("green cluster should be silent, got %+v", got)
	}
	red := checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: true, Status: "red", UnassignedShards: 3, ActiveShardsPct: 60})
	if !insightWithMsg(red, "CRIT", "cluster is RED") {
		t.Errorf("red cluster should CRIT, got %+v", red)
	}
	yellow := checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: true, Status: "yellow", UnassignedShards: 2, Distribution: "opensearch"})
	if !insightWithMsg(yellow, "WARN", "cluster is YELLOW") {
		t.Errorf("yellow cluster should WARN, got %+v", yellow)
	}
}

// TestCheckElasticsearch_UnrecognizedStatus is a regression guard for
// internal-analysis-04-01: the switch on e.Status had no default case, so any
// value other than "red"/"yellow" fell through as if it were the genuinely
// healthy "green" case — including a garbled or spoofed status from a
// non-Elasticsearch service answering the same port. HealthRead only confirms
// the JSON parsed and status was non-empty, not that it's a real ES/OpenSearch
// enum value, so this must never render as silently clean.
func TestCheckElasticsearch_UnrecognizedStatus(t *testing.T) {
	got := checkElasticsearch(models.ElasticsearchInfo{
		Detected: true, HealthRead: true, Status: "anything-not-red-or-yellow",
	})
	if !insightWithMsg(got, "INFO", "not a recognized state") {
		t.Errorf("an unrecognized status must disclose it could not confirm health, not read as clean, got %+v", got)
	}
}

// TestCheckElasticsearch_IdentityUnverified is the regression test for
// internal-collectors-11-04: a spoofed-green response (a fake ES process
// answering with cluster status "green") previously produced zero insights —
// identical to a real, confirmed-healthy cluster. IdentityUnverified must
// disclose the reduced confidence even when the reported status is green.
func TestCheckElasticsearch_IdentityUnverified(t *testing.T) {
	green := checkElasticsearch(models.ElasticsearchInfo{
		Detected: true, HealthRead: true, Status: "green", IdentityUnverified: true,
	})
	if !insightWithMsg(green, "INFO", "identity could not be confirmed") {
		t.Errorf("a spoofed-green result must disclose unverified identity, not read as silently clean, got %+v", green)
	}

	// Must be additive, not a replacement: a real RED finding must still CRIT
	// even when identity is also unverified.
	red := checkElasticsearch(models.ElasticsearchInfo{
		Detected: true, HealthRead: true, Status: "red", IdentityUnverified: true,
	})
	if !insightWithMsg(red, "CRIT", "cluster is RED") {
		t.Errorf("expected the real RED CRIT to survive alongside the disclosure, got %+v", red)
	}
	if !insightWithMsg(red, "INFO", "identity could not be confirmed") {
		t.Errorf("expected the identity disclosure alongside the RED CRIT, got %+v", red)
	}
}

// TestCheckElasticsearch_IdentityVerified_NoExtraNoise confirms the fix adds
// no disclosure when identity IS confirmed — must not introduce noise for
// the common, legitimately-verified case.
func TestCheckElasticsearch_IdentityVerified_NoExtraNoise(t *testing.T) {
	got := checkElasticsearch(models.ElasticsearchInfo{
		Detected: true, HealthRead: true, Status: "green", IdentityUnverified: false,
	})
	if len(got) != 0 {
		t.Errorf("expected no insights for a verified-healthy cluster, got %+v", got)
	}
}
