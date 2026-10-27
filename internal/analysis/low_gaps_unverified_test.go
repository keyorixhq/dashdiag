package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
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

func TestCheckKVMGuest_StealUnreadable(t *testing.T) {
	t.Parallel()
	got := checkKVMGuest(models.KVMGuestInfo{IsGuest: true, StealUnreadable: true})
	if !hasUnverified(got, "CPU steal since boot could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
}

func TestCheckSwap_UnreadableIsUnverified(t *testing.T) {
	t.Parallel()
	got := checkSwap(models.SwapInfo{SwapsUnreadable: true, ZramUnreadable: true}, DefaultThresholds(platform.EnvBareMetal))
	if !hasUnverified(got, "/proc/swaps could not be read") || !hasUnverified(got, "zram") {
		t.Errorf("missing Unverified insights: %+v", got)
	}
}

func TestCheckNFS_StatsUnreadable(t *testing.T) {
	t.Parallel()
	got := checkNFS(models.NFSInfo{StatsUnreadable: true, RpcbindActive: true})
	if !hasUnverified(got, "/proc/net/rpc/nfs could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
}

func TestCheckHealthDeep_MemDetailUnreadable(t *testing.T) {
	t.Parallel()
	got := checkHealthDeep(models.HealthDeepInfo{MemDetailUnreadable: true})
	if !hasUnverified(got, "/proc/meminfo could not be read") {
		t.Errorf("no Unverified insight: %+v", got)
	}
}

func TestCheckPressure_UnreadableMetrics(t *testing.T) {
	t.Parallel()
	got := checkPressure(models.PressureInfo{Available: true, UnreadableMetrics: []string{"memory", "io"}})
	if !hasUnverified(got, "memory, io") {
		t.Errorf("no Unverified insight naming the unread PSI files: %+v", got)
	}
}
