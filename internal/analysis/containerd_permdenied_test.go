package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A permission-denied containerd socket is a non-root MEASUREMENT GAP, not a
// fault — containerd IS installed and likely running, dsd just lacks access.
// It must degrade to INFO ("couldn't measure"), never WARN, mirroring
// checkDocker's identical SocketPermDenied handling. Before this, a
// permission-denied socket collapsed into the same !Available WARN as a
// genuinely-absent one ("containerd socket not found — not installed or not
// running"), which is simply false when the socket is right there.
func TestContainerdSocketPermDeniedIsInfoNotWarn(t *testing.T) {
	permDenied := models.ContainerdInfo{
		Available:        false,
		SocketPermDenied: true,
		Status:           "unavailable",
		StatusReason:     "containerd socket found at /run/containerd/containerd.sock but user not in socket group — run: sudo usermod -aG containerd $USER then log out and reconnect",
	}
	got := checkContainerd(permDenied)
	assertLevel(t, got, "INFO")
	for _, ins := range got {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			t.Errorf("perm-denied socket must not alarm, got %s: %s", ins.Level, ins.Message)
		}
	}

	// Genuinely absent socket is still a real WARN.
	absent := models.ContainerdInfo{
		Available:    false,
		StatusReason: "containerd socket not found",
	}
	if got := checkContainerd(absent); !hasInsightMsg(got, "WARN", "socket not found") {
		t.Errorf("genuinely-absent socket must stay WARN, got %+v", got)
	}
}
