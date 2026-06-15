package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckMemcached(t *testing.T) {
	if got := checkMemcached(models.MemcachedInfo{Detected: false}); got != nil {
		t.Errorf("undetected memcached should be silent, got %+v", got)
	}
	if got := checkMemcached(models.MemcachedInfo{Detected: true, MetricsRead: false}); !insightWithMsg(got, "INFO", "stats could not be read") {
		t.Errorf("unreadable stats should be INFO, got %+v", got)
	}
	// healthy (not evicting now; cumulative evictions alone must NOT alarm) → silent
	if got := checkMemcached(models.MemcachedInfo{Detected: true, MetricsRead: true, Evictions: 5, MaxConnections: 1024, CurrConnections: 5}); len(got) != 0 {
		t.Errorf("healthy memcached should be silent, got %+v", got)
	}
	// actively evicting → WARN
	if got := checkMemcached(models.MemcachedInfo{Detected: true, MetricsRead: true, EvictingNow: true}); !insightWithMsg(got, "WARN", "actively evicting") {
		t.Errorf("active eviction should WARN, got %+v", got)
	}
	// connection saturation → WARN
	if got := checkMemcached(models.MemcachedInfo{Detected: true, MetricsRead: true, MaxConnections: 100, CurrConnections: 95}); !insightWithMsg(got, "WARN", "approaching maxconns") {
		t.Errorf("conn saturation should WARN, got %+v", got)
	}
}
