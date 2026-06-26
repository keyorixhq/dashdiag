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
