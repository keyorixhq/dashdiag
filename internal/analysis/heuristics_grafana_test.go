package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckGrafana(t *testing.T) {
	if got := checkGrafana(models.GrafanaInfo{Detected: false}); got != nil {
		t.Errorf("undetected grafana should be silent, got %+v", got)
	}

	// Up but health endpoint unreadable → INFO, never a silent OK.
	noHealth := checkGrafana(models.GrafanaInfo{Detected: true, HealthRead: false})
	if !insightWithMsg(noHealth, "INFO", "health endpoint could not be read") {
		t.Errorf("unreadable health should be INFO, got %+v", noHealth)
	}

	// Database ok → silent.
	healthy := checkGrafana(models.GrafanaInfo{Detected: true, HealthRead: true, DatabaseOK: true, DatabaseStatus: "ok", Version: "11.1.0"})
	if len(healthy) != 0 {
		t.Errorf("healthy grafana should be silent, got %+v", healthy)
	}

	// Database not ok → CRIT (instance effectively down).
	down := checkGrafana(models.GrafanaInfo{Detected: true, HealthRead: true, DatabaseOK: false, DatabaseStatus: "failing"})
	if !insightWithMsg(down, "CRIT", "backend database is not OK") {
		t.Fatalf("bad database should CRIT, got %+v", down)
	}
	if !insightWithMsg(down, "CRIT", "failing") {
		t.Errorf("CRIT should name the database status, got %+v", down)
	}

	// Database status empty but flagged not-ok → CRIT with "unknown".
	unknown := checkGrafana(models.GrafanaInfo{Detected: true, HealthRead: true, DatabaseOK: false})
	if !insightWithMsg(unknown, "CRIT", "unknown") {
		t.Errorf("empty status should CRIT as unknown, got %+v", unknown)
	}
}
