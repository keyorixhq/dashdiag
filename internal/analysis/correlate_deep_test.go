package analysis

import (
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func hasCorr(corrs []Correlation, name string) *Correlation {
	for i := range corrs {
		if corrs[i].Name == name {
			return &corrs[i]
		}
	}
	return nil
}

func TestRuleIOSingleDeviceDegradation(t *testing.T) {
	io := func(devs ...models.IODeviceInfo) *models.IOInfo { return &models.IOInfo{Devices: devs} }
	deg := models.IODeviceInfo{Name: "sda", AwaitMs: 50, UtilPct: 95}
	healthy := models.IODeviceInfo{Name: "sdb", AwaitMs: 1, UtilPct: 10}

	if c, ok := ruleIOSingleDeviceDegradation(io(deg, healthy)); !ok || c.Level != "CRIT" {
		t.Errorf("one degraded + one healthy should fire CRIT, got %v %+v", ok, c)
	}
	// One device only — can't distinguish single-drive fault from subsystem load.
	if _, ok := ruleIOSingleDeviceDegradation(io(deg)); ok {
		t.Error("single device should not fire")
	}
	// Two degraded — subsystem overload, not a single drive.
	if _, ok := ruleIOSingleDeviceDegradation(io(deg, deg)); ok {
		t.Error("two degraded devices should not fire")
	}
	// Degraded but no clearly-healthy peer.
	mid := models.IODeviceInfo{Name: "sdc", AwaitMs: 10, UtilPct: 70}
	if _, ok := ruleIOSingleDeviceDegradation(io(deg, mid)); ok {
		t.Error("no healthy peer should not fire")
	}
	if _, ok := ruleIOSingleDeviceDegradation(nil); ok {
		t.Error("nil IOInfo should not fire")
	}
}

func TestRuleServiceMemoryLeak(t *testing.T) {
	leak := &models.OOMInfo{
		Available: true, EventsLast24h: 3,
		RecentEvents: []models.OOMEvent{{Process: "java"}, {Process: "java"}, {Process: "nginx"}},
	}
	if c, ok := ruleServiceMemoryLeak(leak); !ok || c.Level != "WARN" {
		t.Errorf("repeated same-process kill should fire WARN, got %v %+v", ok, c)
	}
	// Different processes each time — general pressure, not a leak.
	spread := &models.OOMInfo{
		Available: true, EventsLast24h: 2,
		RecentEvents: []models.OOMEvent{{Process: "a"}, {Process: "b"}},
	}
	if _, ok := ruleServiceMemoryLeak(spread); ok {
		t.Error("distinct victims should not fire the leak rule")
	}
	if _, ok := ruleServiceMemoryLeak(nil); ok {
		t.Error("nil OOMInfo should not fire")
	}
}

func TestRuleDockerOOMCascade(t *testing.T) {
	ts := time.Date(2026, 6, 6, 20, 0, 0, 0, time.UTC)
	oom := &models.OOMInfo{Available: true, EventsLast24h: 1, RecentEvents: []models.OOMEvent{{Process: "x", Timestamp: ts}}}

	// Timed path: a docker oom event within 5 min of the kernel OOM → names the actor.
	dockerTimed := &models.DockerInfo{
		Available: true, OOMEvents: 1,
		RecentEvents: []models.DockerEvent{{Action: "oom", Actor: "web", TimeUnix: ts.Add(2 * time.Minute).Unix()}},
	}
	c := ruleDockerOOMCascadeOrNil(t, oom, dockerTimed)
	if c == nil || c.Level != "CRIT" {
		t.Fatalf("timed cascade should fire CRIT, got %+v", c)
	}

	// Fallback path: counts present but no timestamped docker events.
	dockerFallback := &models.DockerInfo{Available: true, OOMEvents: 2}
	if c := ruleDockerOOMCascadeOrNil(t, oom, dockerFallback); c == nil || c.Level != "CRIT" {
		t.Errorf("fallback cascade should fire CRIT, got %+v", c)
	}

	// No co-occurrence: docker has no OOM events.
	if _, ok := ruleDockerOOMCascade(oom, &models.DockerInfo{Available: true, OOMEvents: 0}); ok {
		t.Error("no docker OOM events should not fire")
	}
}

func ruleDockerOOMCascadeOrNil(t *testing.T, oom *models.OOMInfo, d *models.DockerInfo) *Correlation {
	t.Helper()
	c, ok := ruleDockerOOMCascade(oom, d)
	if !ok {
		return nil
	}
	return &c
}

func TestRuleSysctlNotPersisted(t *testing.T) {
	warn := []models.Insight{ins("WARN", "Sysctl", "vm.swappiness high")}

	// Rebooted recently + a tuned-away (non-default) value → fires.
	out := CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 600, VMSwappiness: 30})
	if hasCorr(out, "Sysctl Parameter Not Persisted") == nil {
		t.Errorf("expected Sysctl-not-persisted correlation, got %+v", out)
	}

	// Same recent reboot but values still at kernel stock default → suppressed.
	out = CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 600, VMSwappiness: 60})
	if hasCorr(out, "Sysctl Parameter Not Persisted") != nil {
		t.Error("stock-default values after a fresh boot should suppress the correlation")
	}

	// Long uptime → not a recent-reboot scenario → suppressed.
	out = CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 100000, VMSwappiness: 30})
	if hasCorr(out, "Sysctl Parameter Not Persisted") != nil {
		t.Error("long uptime should not fire the not-persisted correlation")
	}
}
