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

	// Clustered + ready, with a verified reload → silent.
	ready := checkAlertmanager(models.AlertmanagerInfo{
		Detected: true, StatusRead: true, ClusterStatus: "ready", ClusterPeers: 3,
		ConfigReloadRead: true, ConfigReloadOK: true,
	})
	if len(ready) != 0 {
		t.Errorf("ready cluster should be silent, got %+v", ready)
	}

	// Status API reachable but the /metrics scrape carrying the config-reload
	// gauge is not (proxy/auth blocks it, or Alertmanager only partially up) →
	// INFO, never a silent OK — this is the one signal the check exists for.
	noReload := checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: true, ClusterStatus: "ready"})
	if !insightWithMsg(noReload, "INFO", "config-reload status could not be read") {
		t.Errorf("unreadable config-reload status should be INFO, got %+v", noReload)
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
