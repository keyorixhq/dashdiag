package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// hasIPForwardCRIT reports whether the IP-forwarding-disabled CRIT is present.
func hasIPForwardCRIT(insights []models.Insight) bool {
	for _, in := range insights {
		if in.Level == "CRIT" && strings.Contains(in.Message, "IP forwarding disabled") {
			return true
		}
	}
	return false
}

// On macOS / a proc-less container the /proc/sys/net/ipv4/ip_forward read fails,
// leaving IPForwardChecked false. State is unknown, not disabled — no CRIT.
// Regression test for the false-positive `dsd docker` exit-2 on a Mac with OrbStack.
func TestIPForwardUncheckedNoFalseCRIT(t *testing.T) {
	d := models.DockerInfo{
		Available:        true,
		IPForwardChecked: false,
		IPForwardEnabled: false,
	}
	if hasIPForwardCRIT(checkDockerResources(d)) {
		t.Error("unchecked IP forwarding must NOT fire the disabled CRIT (state unknown)")
	}
}

// A genuine Linux read of ip_forward=0 still fires the CRIT.
func TestIPForwardCheckedDisabledFiresCRIT(t *testing.T) {
	d := models.DockerInfo{
		Available:        true,
		IPForwardChecked: true,
		IPForwardEnabled: false,
	}
	if !hasIPForwardCRIT(checkDockerResources(d)) {
		t.Error("checked + disabled IP forwarding must fire the CRIT")
	}
}

// ip_forward=1 — healthy, no CRIT.
func TestIPForwardCheckedEnabledNoCRIT(t *testing.T) {
	d := models.DockerInfo{
		Available:        true,
		IPForwardChecked: true,
		IPForwardEnabled: true,
	}
	if hasIPForwardCRIT(checkDockerResources(d)) {
		t.Error("enabled IP forwarding must not fire the CRIT")
	}
}
