package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// corrByName returns the correlation with the given Name, or nil.
func corrByName(corrs []Correlation, name string) *Correlation {
	for i := range corrs {
		if corrs[i].Name == name {
			return &corrs[i]
		}
	}
	return nil
}

func TestRuleDiskFullServiceFailure(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "Disk", "/ at 100%"),
		ins("CRIT", "Systemd", "unit nginx.service has failed"),
	})
	c := corrByName(fires, "Disk-Full Service Failure")
	if c == nil || c.Level != "CRIT" {
		t.Fatalf("expected Disk-Full Service Failure CRIT, got %+v", fires)
	}
	// Disk full alone (no service/log failure) must not fire this rule.
	if corrByName(Correlate([]models.Insight{ins("CRIT", "Disk", "/ at 100%")}), "Disk-Full Service Failure") != nil {
		t.Error("should not fire on a full disk with no downstream failure")
	}
	// Logs CRIT alone (no Systemd failure) still fires — exercises the
	// logsCrit-only branch of the (!systemdCrit && !logsCrit) gate and the
	// separate "Logs" append to Checks.
	logsOnly := Correlate([]models.Insight{
		ins("CRIT", "Disk", "/ at 100%"),
		ins("CRIT", "Logs", "write errors: no space left on device"),
	})
	c = corrByName(logsOnly, "Disk-Full Service Failure")
	if c == nil || c.Level != "CRIT" {
		t.Fatalf("expected Disk-Full Service Failure CRIT via Logs alone, got %+v", logsOnly)
	}
	foundLogs := false
	for _, chk := range c.Checks {
		if chk == "Logs" {
			foundLogs = true
		}
	}
	if !foundLogs {
		t.Errorf("expected Checks to include Logs, got %v", c.Checks)
	}
}

func TestRuleNFSStaleProcessHang(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "NFS", "stale mount /data"),
		ins("CRIT", "Processes", "3 hung processes"),
	})
	if corrByName(fires, "NFS Stall Process Hang") == nil {
		t.Fatalf("expected NFS Stall Process Hang, got %+v", fires)
	}
	if corrByName(Correlate([]models.Insight{ins("CRIT", "NFS", "stale mount")}), "NFS Stall Process Hang") != nil {
		t.Error("should not fire without hung processes")
	}
}

func TestRuleClockSkewTLSAuth(t *testing.T) {
	viaTLS := Correlate([]models.Insight{
		ins("CRIT", "Clock", "NTP not synchronized, offset 4200ms"),
		ins("CRIT", "TLS", "certificate expired"),
	})
	if corrByName(viaTLS, "Clock Skew Breaking TLS/Auth") == nil {
		t.Fatalf("expected clock-skew via TLS, got %+v", viaTLS)
	}
	viaAuth := Correlate([]models.Insight{
		ins("CRIT", "Clock", "large offset"),
		ins("WARN", "Auth", "repeated auth failures"),
	})
	if corrByName(viaAuth, "Clock Skew Breaking TLS/Auth") == nil {
		t.Fatalf("expected clock-skew via Auth, got %+v", viaAuth)
	}
	// Clock fine → no correlation even with TLS failing.
	if corrByName(Correlate([]models.Insight{ins("CRIT", "TLS", "expired")}), "Clock Skew Breaking TLS/Auth") != nil {
		t.Error("should not fire without clock skew")
	}
}

func TestRuleContainerCgroupOOM(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "Docker", "container app OOM-killed"),
		ins("CRIT", "Cgroup", "memory.events oom_kill in app.slice"),
		ins("OK", "Memory", "RAM at 40%"), // host memory confirmed clear
	})
	if corrByName(fires, "Container Memory-Limit OOM") == nil {
		t.Fatalf("expected Container Memory-Limit OOM, got %+v", fires)
	}
	// When host memory is ALSO critical it's a host-OOM, not a container-limit issue.
	hostOOM := Correlate([]models.Insight{
		ins("CRIT", "Docker", "container OOM-killed"),
		ins("CRIT", "Cgroup", "oom_kill"),
		ins("CRIT", "Memory", "RAM at 99%"),
	})
	if corrByName(hostOOM, "Container Memory-Limit OOM") != nil {
		t.Error("should not fire when host memory is also critical")
	}
}

// TestRuleContainerCgroupOOMDoesNotFireWithUnmeasuredMemory is the regression
// test for internal-analysis-01-03: without a Memory insight at all (never
// measured, not confirmed clear), the rule must not claim "the host still
// has RAM" — that claim is unverified, not merely unconfirmed-critical.
func TestRuleContainerCgroupOOMDoesNotFireWithUnmeasuredMemory(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "Docker", "container app OOM-killed"),
		ins("CRIT", "Cgroup", "memory.events oom_kill in app.slice"),
	})
	if corrByName(fires, "Container Memory-Limit OOM") != nil {
		t.Error("should not fire when host memory was never measured")
	}
}

func TestRuleThermalThrottleUnderLoad(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "CPU Thermal", "package 98C — throttling"),
		ins("WARN", "CPU Load/IOWait", "load high"),
	})
	c := corrByName(fires, "Thermal Throttling Under Load")
	if c == nil || c.Level != "CRIT" {
		t.Fatalf("expected Thermal Throttling Under Load CRIT, got %+v", fires)
	}
	// Hot but idle → not throttling under load.
	if corrByName(Correlate([]models.Insight{ins("WARN", "CPU Thermal", "warm")}), "Thermal Throttling Under Load") != nil {
		t.Error("should not fire when the box is idle")
	}
}

func TestRuleDNSResolverNotConnectivity(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "DNS", "resolution failing for all queries"),
		ins("OK", "Network", "gateway reachable"), // network confirmed up
	})
	if corrByName(fires, "DNS Resolver Failure (network is up)") == nil {
		t.Fatalf("expected DNS resolver correlation, got %+v", fires)
	}
	// If the network is also CRIT, it's likely connectivity — don't claim resolver-only.
	withNet := Correlate([]models.Insight{
		ins("CRIT", "DNS", "resolution failing"),
		ins("CRIT", "Network", "gateway unreachable"),
	})
	if corrByName(withNet, "DNS Resolver Failure (network is up)") != nil {
		t.Error("should not fire when the network is also down")
	}
}

// TestRuleDNSResolverNotConnectivityDoesNotFireWithUnmeasuredNetwork is the
// regression test for internal-analysis-01-03: without a Network insight at
// all, the rule must not claim "the network link is healthy" — that's an
// unverified claim, not a confirmed one.
func TestRuleDNSResolverNotConnectivityDoesNotFireWithUnmeasuredNetwork(t *testing.T) {
	fires := Correlate([]models.Insight{
		ins("CRIT", "DNS", "resolution failing for all queries"),
	})
	if corrByName(fires, "DNS Resolver Failure (network is up)") != nil {
		t.Error("should not fire when the network was never measured")
	}
}
