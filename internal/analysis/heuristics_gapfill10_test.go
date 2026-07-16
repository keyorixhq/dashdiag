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
			{Namespace: "default", Name: "app-0", Status: "Unknown"},          // → process
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

// TestCheckSteamOSUpdate_ReadonlyDisabled covers the ReadonlyKnown && !ReadonlyEnabled
// CRIT branch — a writable rootfs on SteamOS must be flagged CRIT to prevent
// the next update from overwriting manual changes.
func TestCheckSteamOSUpdate_ReadonlyDisabled(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: false})
	if !hasInsightMsg(got, "CRIT", "steamos-readonly is DISABLED") {
		t.Errorf("writable rootfs must CRIT, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_ChannelConfigMissing covers the ChannelConfigMissing WARN
// branch — a missing updater config must warn so the operator knows the channel is
// unconfigured.
func TestCheckSteamOSUpdate_ChannelConfigMissing(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{ChannelConfigMissing: true})
	if !hasInsightMsg(got, "WARN", "client.conf is missing") {
		t.Errorf("missing channel config must WARN, got %+v", got)
	}
}

// TestCheckSteamOSUpdate_NonStableChannel covers the Channel != "stable" INFO branch
// — a dev/beta update channel must produce an informational notice.
func TestCheckSteamOSUpdate_NonStableChannel(t *testing.T) {
	t.Parallel()
	got := checkSteamOSUpdate(models.SteamOSInfo{Channel: "beta"})
	if !hasInsightMsg(got, "INFO", "update channel is 'beta'") {
		t.Errorf("non-stable channel must INFO, got %+v", got)
	}
}
