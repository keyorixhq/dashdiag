package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckAlertmanager(t *testing.T) {
	if got := checkAlertmanager(models.AlertmanagerInfo{Detected: false}); got != nil {
		t.Errorf("undetected alertmanager should be silent, got %+v", got)
	}

	// Up but status unreadable → INFO, never a silent OK.
	noStatus := checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: false})
	if !insightWithMsg(noStatus, "INFO", "status API could not be read") {
		t.Errorf("unreadable status should be INFO, got %+v", noStatus)
	}

	// Single node (cluster disabled, reload ok) → silent.
	single := checkAlertmanager(models.AlertmanagerInfo{
		Detected: true, StatusRead: true, ClusterStatus: "disabled",
		ConfigReloadRead: true, ConfigReloadOK: true,
	})
	if len(single) != 0 {
		t.Errorf("healthy single-node alertmanager should be silent, got %+v", single)
	}

	// Clustered + ready → silent.
	ready := checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: true, ClusterStatus: "ready", ClusterPeers: 3})
	if len(ready) != 0 {
		t.Errorf("ready cluster should be silent, got %+v", ready)
	}

	// "settling" is a transient startup state (verified live: resolves to "ready"
	// in seconds) — it must NOT warn, or every restart false-alarms.
	settling := checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: true, ClusterStatus: "settling", ClusterPeers: 1,
		ConfigReloadRead: true, ConfigReloadOK: true})
	if len(settling) != 0 {
		t.Errorf("settling cluster must be silent (transient), got %+v", settling)
	}

	// Failed config reload → WARN (stale routing/receiver config), even mid-settle.
	reload := checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: true,
		ClusterStatus: "settling", ConfigReloadRead: true, ConfigReloadOK: false})
	if !insightWithMsg(reload, "WARN", "configuration reload FAILED") {
		t.Errorf("failed reload should WARN, got %+v", reload)
	}
}
