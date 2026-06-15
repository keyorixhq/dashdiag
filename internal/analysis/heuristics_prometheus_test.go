package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckPrometheus(t *testing.T) {
	if got := checkPrometheus(models.PrometheusInfo{Detected: false}); got != nil {
		t.Errorf("undetected prometheus should be silent, got %+v", got)
	}

	// Up but API unreadable → INFO, never a silent OK.
	noAPI := checkPrometheus(models.PrometheusInfo{Detected: true, MetricsRead: false})
	if !insightWithMsg(noAPI, "INFO", "API could not be read") {
		t.Errorf("unreadable API should be INFO, got %+v", noAPI)
	}

	// Healthy (all targets up, reload ok) → silent.
	healthy := checkPrometheus(models.PrometheusInfo{
		Detected: true, MetricsRead: true, TargetsTotal: 5, TargetsDown: 0,
		ConfigReloadRead: true, ConfigReloadOK: true,
	})
	if len(healthy) != 0 {
		t.Errorf("healthy prometheus should be silent, got %+v", healthy)
	}

	// Some targets down → WARN, not CRIT.
	some := checkPrometheus(models.PrometheusInfo{Detected: true, MetricsRead: true,
		TargetsTotal: 5, TargetsDown: 2, DownSample: "http://node1:9100/metrics (connection refused)"})
	if !insightWithMsg(some, "WARN", "2 of 5 scrape target(s) are DOWN") {
		t.Fatalf("some targets down should WARN, got %+v", some)
	}
	if insightWithMsg(some, "CRIT", "DOWN") {
		t.Errorf("some-down must not CRIT, got %+v", some)
	}
	// The sample down target is carried as a hint, not in the message.
	sampleSeen := false
	for _, in := range some {
		for _, h := range in.Hints {
			if strings.Contains(h, "node1") {
				sampleSeen = true
			}
		}
	}
	if !sampleSeen {
		t.Errorf("WARN should carry the sample down target in its hints, got %+v", some)
	}

	// All targets down → CRIT (monitoring blind).
	all := checkPrometheus(models.PrometheusInfo{Detected: true, MetricsRead: true, TargetsTotal: 4, TargetsDown: 4})
	if !insightWithMsg(all, "CRIT", "ALL 4 scrape target(s) are DOWN") {
		t.Errorf("all targets down should CRIT, got %+v", all)
	}

	// Failed config reload → WARN (stale config).
	reload := checkPrometheus(models.PrometheusInfo{Detected: true, MetricsRead: true,
		TargetsTotal: 3, TargetsDown: 0, ConfigReloadRead: true, ConfigReloadOK: false})
	if !insightWithMsg(reload, "WARN", "configuration reload FAILED") {
		t.Errorf("failed reload should WARN, got %+v", reload)
	}
}
