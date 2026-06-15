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
