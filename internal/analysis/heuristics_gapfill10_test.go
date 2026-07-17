package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckSysctl_ElasticsearchSwappiness covers the VMSwappiness > 1 branch in the
// "elasticsearch" workload case of checkSysctl — ES recommends swappiness=1, so
// anything higher must WARN.
func TestCheckSysctl_ElasticsearchSwappiness(t *testing.T) {
	t.Parallel()
	got := checkSysctl(models.SysctlInfo{Workload: "elasticsearch", VMSwappiness: 30})
	if !hasInsightMsg(got, "WARN", "Elasticsearch recommends") {
		t.Errorf("elasticsearch with high swappiness must WARN, got %+v", got)
	}
}

// TestCheckSysctl_K8sMaxMapCount covers the VMMaxMapCount < 262144 branch in the
// "k8s" workload case of checkSysctl — k8s/Elasticsearch commonly colocates with
// the same map-count requirement.
func TestCheckSysctl_K8sMaxMapCount(t *testing.T) {
	t.Parallel()
	got := checkSysctl(models.SysctlInfo{Workload: "k8s", VMMaxMapCount: 1000})
	if !hasInsightMsg(got, "WARN", "vm.max_map_count") {
		t.Errorf("k8s workload with low VMMaxMapCount must WARN, got %+v", got)
	}
}

// TestK8sUnknownStatusInsight_SkipsNonUnknownPod covers the
// `if p.Status != "Unknown" { continue }` branch — a non-Unknown pod in the
// pod list must be silently skipped without affecting the insight.
func TestK8sUnknownStatusInsight_SkipsNonUnknownPod(t *testing.T) {
	t.Parallel()
	info := models.K8sInfo{
		UnknownStatus: 1,
		Pods: []models.K8sPodInfo{
			{Namespace: "kube-system", Name: "coredns-0", Status: "Running"}, // → continue
			{Namespace: "default", Name: "app-0", Status: "Unknown"},         // → process
		},
	}
	ins := k8sUnknownStatusInsight(info)
	if ins.Level != "WARN" {
		t.Errorf("expected WARN, got %q", ins.Level)
	}
	found := false
	for _, h := range ins.Hints {
		if strings.Contains(h, "app-0") {
			found = true
		}
	}
	if !found {
		t.Errorf("Unknown pod must appear in hints, got %v", ins.Hints)
	}
}

// TestParseK8sEventAge_UnitWithoutLeadingDigit covers the `if !sawDigit { return 0, false }`
// branch inside the unit-character case of parseK8sEventAgeSeconds — a unit letter
// appearing before any digit must return ok=false.
func TestParseK8sEventAge_UnitWithoutLeadingDigit(t *testing.T) {
	t.Parallel()
	got, ok := parseK8sEventAgeSeconds("h5")
	if ok || got != 0 {
		t.Errorf("unit before digit must return (0, false), got (%d, %v)", got, ok)
	}
	got, ok = parseK8sEventAgeSeconds("s")
	if ok || got != 0 {
		t.Errorf("bare unit must return (0, false), got (%d, %v)", got, ok)
	}
}

// TestCheckSteamOSDeep_FlatpakLarge covers the FlatpakDataGB > 20 WARN branch in
// checkSteamOSDeep — an oversized flatpak data directory should surface as a WARN.
func TestCheckSteamOSDeep_FlatpakLarge(t *testing.T) {
	t.Parallel()
	got := checkSteamOSDeep(models.SteamOSInfo{FlatpakDataGB: 25.0})
	if !hasInsightMsg(got, "WARN", "flatpak data is") {
		t.Errorf("FlatpakDataGB > 20 must WARN, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_WritableRootfsCritPrefix verifies the "steamos-readonly is DISABLED"
// prefix in the CRIT message for a known-writable rootfs.
func TestCheckSteamOSUpdate_WritableRootfsCritPrefix(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: false})
	if !hasInsightMsg(got, "CRIT", "steamos-readonly is DISABLED") {
		t.Errorf("writable rootfs must CRIT with 'steamos-readonly is DISABLED', got %+v", got)
	}
}

// TestCheckSteamOSUpdate_BetaChannelLabel covers the Channel != "stable" INFO branch
// with a "beta" channel value — the channel name must appear in the INFO message.
func TestCheckSteamOSUpdate_BetaChannelLabel(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{Channel: "beta"})
	if !hasInsightMsg(got, "INFO", "update channel is 'beta'") {
		t.Errorf("beta channel must produce INFO with channel name, got %+v", got)
	}
}
