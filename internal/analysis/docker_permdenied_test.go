package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A permission-denied container socket is a non-root MEASUREMENT GAP, not a
// fault. It must degrade to INFO ("couldn't measure"), never WARN — otherwise an
// unprivileged operator gets a false alarm about a runtime they simply couldn't
// read. Regression for the SLES16/arm64 podman false-WARN (the WARN also named
// the wrong runtime: "systemctl status docker" for a podman socket).
func TestDockerSocketPermDeniedIsInfoNotWarn(t *testing.T) {
	permDenied := models.DockerInfo{
		Available:        false,
		SocketPermDenied: true,
		Status:           "unavailable",
		StatusReason:     "podman socket found at /run/podman/podman.sock but user not in socket group — run: sudo usermod -aG podman $USER then log out and reconnect",
	}
	got := checkDocker(permDenied)
	assertLevel(t, got, "INFO")
	for _, ins := range got {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			t.Errorf("perm-denied socket must not alarm, got %s: %s", ins.Level, ins.Message)
		}
		for _, h := range ins.Hints {
			if h == "to inspect: systemctl status docker" {
				t.Errorf("perm-denied podman socket must not emit the docker-named hint %q", h)
			}
		}
	}

	// Genuine daemon-down (installed but not running) is still a real WARN.
	daemonDown := models.DockerInfo{
		Available:    false,
		StatusReason: "Docker installed but daemon not running",
	}
	if got := checkDocker(daemonDown); !hasInsightMsg(got, "WARN", "daemon not running") {
		t.Errorf("daemon-down must stay WARN, got %+v", got)
	}

	// Genuinely absent, no reason → stay silent (no regression).
	if got := checkDocker(models.DockerInfo{Available: false}); len(got) != 0 {
		t.Errorf("no reason → stay silent, got %+v", got)
	}
}

// TestDockerEnumerationErrorFallsBackToDefaultReason covers the Status=="error"
// path (daemon reachable but container listing failed) when StatusReason is
// empty — the code must fall back to its own generic explanation rather than
// emitting a blank-message insight.
func TestDockerEnumerationErrorFallsBackToDefaultReason(t *testing.T) {
	enumFailed := models.DockerInfo{Available: true, Status: "error"}
	got := checkDocker(enumFailed)
	if !hasInsightMsg(got, "WARN", "health not verified") {
		t.Errorf("expected default enumeration-failed reason, got %+v", got)
	}

	// With an explicit reason, that reason is used verbatim instead.
	withReason := models.DockerInfo{Available: true, Status: "error", StatusReason: "docker ps timed out after 5s"}
	if got := checkDocker(withReason); !hasInsightMsg(got, "WARN", "docker ps timed out after 5s") {
		t.Errorf("expected the explicit StatusReason to be used, got %+v", got)
	}
}
