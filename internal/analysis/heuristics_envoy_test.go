package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckEnvoy(t *testing.T) {
	if got := checkEnvoy(models.EnvoyInfo{Detected: false}); got != nil {
		t.Errorf("undetected envoy should be silent, got %+v", got)
	}

	// Up but stats unreadable → INFO, never a silent OK.
	noStats := checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: false})
	if !insightWithMsg(noStats, "INFO", "cluster stats could not be read") {
		t.Errorf("unreadable stats should be INFO, got %+v", noStats)
	}

	// Stats endpoint answered but no cluster membership was parsed out of it
	// (garbled/empty/filtered response) → INFO, not a silent green.
	noMembers := checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: true, ClustersTotal: 0})
	if !insightWithMsg(noMembers, "INFO", "no upstream cluster membership data was found") {
		t.Errorf("stats-read but zero clusters should be INFO, got %+v", noMembers)
	}

	// All upstreams healthy → silent.
	healthy := checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: true, ClustersTotal: 3, UpstreamsTotal: 9, UpstreamsHealthy: 9})
	if len(healthy) != 0 {
		t.Errorf("all-healthy envoy should be silent, got %+v", healthy)
	}

	// Some upstreams unhealthy (no fully-down cluster) → WARN.
	partial := checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: true, ClustersTotal: 2, UpstreamsTotal: 6,
		UpstreamsHealthy: 4, DegradedSample: `cluster "svc_a": 1/3 hosts healthy`})
	if !insightWithMsg(partial, "WARN", "2 of 6 upstream host(s) are unhealthy") {
		t.Fatalf("partial unhealthy should WARN, got %+v", partial)
	}
	if insightWithMsg(partial, "CRIT", "ZERO") {
		t.Errorf("partial unhealthy must not CRIT, got %+v", partial)
	}

	// A fully-down cluster → CRIT (takes precedence over the WARN).
	down := checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: true, ClustersTotal: 2, UpstreamsTotal: 4,
		UpstreamsHealthy: 2, FullyDownClusters: 1, DegradedSample: `cluster "svc_b": 0/2 hosts healthy`})
	if !insightWithMsg(down, "CRIT", "ZERO healthy hosts") {
		t.Fatalf("fully-down cluster should CRIT, got %+v", down)
	}
	if !insightWithMsg(down, "CRIT", "svc_b") {
		t.Errorf("CRIT should carry the degraded sample, got %+v", down)
	}
}
