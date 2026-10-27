package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DD-COLLECTOR-GAPS-1 Low items: each "could not look" sentinel produces an
// Unverified insight, never silence. hasUnverified lives in medium_gaps_unverified_test.go.

func TestCheckKdump_StateUnverified(t *testing.T) {
	t.Parallel()
	got := checkKdump(models.KdumpInfo{Available: true, StateUnverified: true})
	if !hasUnverified(got, "enabled/active state could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
	if len(checkKdump(models.KdumpInfo{Available: true})) != 0 {
		t.Error("a deliberately-disabled kdump must stay silent")
	}
}

func TestCheckTuned_StateUnverified(t *testing.T) {
	t.Parallel()
	got := checkTuned(models.TunedInfo{Available: true, StateUnverified: true})
	if !hasUnverified(got, "state or profile could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
}

func TestCheckThermal_SensorUnreadable(t *testing.T) {
	t.Parallel()
	got := checkThermal(models.ThermalInfo{Available: true, Source: "coretemp", SensorUnreadable: true}, Thresholds{})
	if !hasUnverified(got, "could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
}

func TestCheckContainerd_UnreadableNamespacesAndCounts(t *testing.T) {
	t.Parallel()
	got := checkContainerd(models.ContainerdInfo{Available: true, ServiceState: "active", CtrBinaryFound: true, NamespacesUnreadable: true, ContainerCountsUnreadable: true})
	if !hasUnverified(got, "namespaces list") || !hasUnverified(got, "lower bound") {
		t.Errorf("missing Unverified insights: %+v", got)
	}
}
