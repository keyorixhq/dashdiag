package analysis

import (
	"strings"
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
	// High await on an essentially-idle device is measurement noise, not a failing
	// drive — must NOT fire (regression: 24ms await @ 4% util false-CRIT on an LXC).
	idleSlow := models.IODeviceInfo{Name: "sdb", AwaitMs: 24, UtilPct: 4}
	if _, ok := ruleIOSingleDeviceDegradation(io(idleSlow, healthy)); ok {
		t.Error("high await at idle util should not fire (await is noise below the active floor)")
	}
	// High await WITH meaningful utilization still fires (a busy, slow drive).
	busySlow := models.IODeviceInfo{Name: "sdb", AwaitMs: 24, UtilPct: 35}
	if _, ok := ruleIOSingleDeviceDegradation(io(busySlow, healthy)); !ok {
		t.Error("high await at active util should still fire (real degraded drive)")
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
	// Determinism (TRIAGE §I): when two processes tie for most-killed, the named
	// leaker must be stable (lexicographically smallest), not map-iteration-order
	// dependent. "apache" and "redis" each die twice → must always name "apache".
	tie := &models.OOMInfo{
		Available: true, EventsLast24h: 4,
		RecentEvents: []models.OOMEvent{
			{Process: "redis"}, {Process: "apache"}, {Process: "redis"}, {Process: "apache"},
		},
	}
	for range 50 {
		c, ok := ruleServiceMemoryLeak(tie)
		if !ok || !strings.Contains(c.Summary, "apache") {
			t.Fatalf("tie must stably name 'apache', got ok=%v summary=%q", ok, c.Summary)
		}
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

func TestFindTimedDockerOOMSkipsNonOOMDieActions(t *testing.T) {
	ts := time.Date(2026, 6, 6, 20, 0, 0, 0, time.UTC)
	oom := &models.OOMInfo{RecentEvents: []models.OOMEvent{{Process: "x", Timestamp: ts}}}
	// "start"/"stop" events must be skipped (continue at the action-filter check)
	// before ever reaching an "oom"/"die" event that would match.
	docker := &models.DockerInfo{RecentEvents: []models.DockerEvent{
		{Action: "start", Actor: "web", TimeUnix: ts.Unix()},
		{Action: "stop", Actor: "web", TimeUnix: ts.Unix()},
		{Action: "die", Actor: "web", TimeUnix: ts.Add(time.Minute).Unix()},
	}}
	actor, found := findTimedDockerOOM(oom, docker)
	if !found || actor != "web" {
		t.Fatalf("expected the die event to match after skipping start/stop, got actor=%q found=%v", actor, found)
	}
}

func TestFindTimedDockerOOMSkipsZeroTimestampKernelEvents(t *testing.T) {
	// A kernel OOM event with a zero Timestamp (unparseable) must be skipped —
	// exercises the ke.Timestamp.IsZero() continue branch — while a later,
	// properly-timestamped kernel event still matches.
	ts := time.Date(2026, 6, 6, 20, 0, 0, 0, time.UTC)
	oom := &models.OOMInfo{RecentEvents: []models.OOMEvent{
		{Process: "unparsed"},         // zero Timestamp
		{Process: "x", Timestamp: ts}, // valid
	}}
	docker := &models.DockerInfo{RecentEvents: []models.DockerEvent{
		{Action: "oom", Actor: "web", TimeUnix: ts.Add(time.Minute).Unix()},
	}}
	actor, found := findTimedDockerOOM(oom, docker)
	if !found || actor != "web" {
		t.Fatalf("expected match against the valid-timestamp kernel event, got actor=%q found=%v", actor, found)
	}
}

func TestFindTimedDockerOOMMatchesWhenKernelEventIsLater(t *testing.T) {
	// Docker event BEFORE the kernel OOM event — diff is negative before the
	// abs() normalization. Exercises the `diff < 0` branch.
	ts := time.Date(2026, 6, 6, 20, 0, 0, 0, time.UTC)
	oom := &models.OOMInfo{RecentEvents: []models.OOMEvent{{Process: "x", Timestamp: ts.Add(2 * time.Minute)}}}
	docker := &models.DockerInfo{RecentEvents: []models.DockerEvent{
		{Action: "oom", Actor: "web", TimeUnix: ts.Unix()},
	}}
	actor, found := findTimedDockerOOM(oom, docker)
	if !found || actor != "web" {
		t.Fatalf("expected match when the kernel event follows the docker event, got actor=%q found=%v", actor, found)
	}
}

func TestFindTimedDockerOOMNoMatchOutsideWindow(t *testing.T) {
	ts := time.Date(2026, 6, 6, 20, 0, 0, 0, time.UTC)
	oom := &models.OOMInfo{RecentEvents: []models.OOMEvent{{Process: "x", Timestamp: ts}}}
	docker := &models.DockerInfo{RecentEvents: []models.DockerEvent{
		{Action: "oom", Actor: "web", TimeUnix: ts.Add(time.Hour).Unix()},
	}}
	if _, found := findTimedDockerOOM(oom, docker); found {
		t.Error("events an hour apart should not match the 5-minute window")
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
	out := CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 600, VMSwappiness: 30}, nil, nil)
	if hasCorr(out, "Sysctl Parameter Not Persisted") == nil {
		t.Errorf("expected Sysctl-not-persisted correlation, got %+v", out)
	}

	// Same recent reboot but values still at kernel stock default → suppressed.
	out = CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 600, VMSwappiness: 60}, nil, nil)
	if hasCorr(out, "Sysctl Parameter Not Persisted") != nil {
		t.Error("stock-default values after a fresh boot should suppress the correlation")
	}

	// Long uptime → not a recent-reboot scenario → suppressed.
	out = CorrelateDeep(warn, nil, nil, nil, &models.SysctlInfo{UptimeSeconds: 100000, VMSwappiness: 30}, nil, nil)
	if hasCorr(out, "Sysctl Parameter Not Persisted") != nil {
		t.Error("long uptime should not fire the not-persisted correlation")
	}
}

func TestRuleIOWaitCulprit(t *testing.T) {
	io := &models.IOInfo{Devices: []models.IODeviceInfo{
		{Name: "sda", AwaitMs: 3},
		{Name: "nvme0n1", AwaitMs: 12},
	}}
	deep := &models.HealthDeepInfo{TopIOProcs: []models.ProcessIOStat{
		{PID: 1204, Name: "postgres", ReadBps: 900, WriteBps: 100},
		{PID: 42, Name: "kworker", ReadBps: 10, WriteBps: 0},
	}}

	c, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, io, deep)
	if !ok {
		t.Fatal("expected the culprit rule to fire at 12% iowait with device+process data present")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN below the 40%% CRIT band, got %q", c.Level)
	}
	want := "iowait 12% ← nvme0n1 (12ms await) ← postgres (PID 1204)"
	if c.Summary != want {
		t.Errorf("summary = %q, want %q", c.Summary, want)
	}

	if c, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 45}, io, deep); !ok || c.Level != "CRIT" {
		t.Errorf("expected CRIT at 45%% iowait, got %v %+v", ok, c)
	}

	if _, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 4}, io, deep); ok {
		t.Error("below the 5% gate should not fire")
	}
	if _, ok := ruleIOWaitCulprit(nil, io, deep); ok {
		t.Error("nil CPUInfo should not fire")
	}
	if _, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, nil, deep); ok {
		t.Error("nil IOInfo should not fire")
	}
	if _, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, &models.IOInfo{}, deep); ok {
		t.Error("no devices should not fire")
	}
	if _, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, io, nil); ok {
		t.Error("nil HealthDeepInfo should not fire")
	}
	if _, ok := ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, io, &models.HealthDeepInfo{}); ok {
		t.Error("no sampled top processes should not fire")
	}

	needsRoot := &models.HealthDeepInfo{
		TopIOProcs:          deep.TopIOProcs,
		TopIOProcsNeedsRoot: true,
	}
	c, ok = ruleIOWaitCulprit(&models.CPUInfo{IOwaitPct: 12}, io, needsRoot)
	if !ok || !strings.Contains(c.Summary, "partial process visibility") {
		t.Errorf("expected a partial-visibility caveat in the summary, got %+v", c)
	}
}

// TestCorrelateDeepWiresAllDeepRules exercises CorrelateDeep's own call sites
// (not just the underlying rule functions in isolation) so that each
// `if c, ok := ruleX(...); ok { out = append(out, c) }` append branch inside
// CorrelateDeep itself is actually taken — ruleIOSingleDeviceDegradation,
// ruleServiceMemoryLeak, and ruleIOWaitCulprit are otherwise only ever called
// directly by their own unit tests above, never through CorrelateDeep with
// data that makes them fire.
func TestCorrelateDeepWiresAllDeepRules(t *testing.T) {
	io := &models.IOInfo{Devices: []models.IODeviceInfo{
		{Name: "sda", AwaitMs: 50, UtilPct: 95},
		{Name: "sdb", AwaitMs: 1, UtilPct: 10},
	}}
	oom := &models.OOMInfo{
		Available: true, EventsLast24h: 3,
		RecentEvents: []models.OOMEvent{{Process: "java"}, {Process: "java"}},
	}
	cpu := &models.CPUInfo{IOwaitPct: 45}
	deep := &models.HealthDeepInfo{TopIOProcs: []models.ProcessIOStat{
		{PID: 1204, Name: "postgres", ReadBps: 900, WriteBps: 100},
	}}

	out := CorrelateDeep(nil, oom, nil, io, nil, cpu, deep)

	if hasCorr(out, "Single Device IO Degradation") == nil {
		t.Errorf("expected Single Device IO Degradation via CorrelateDeep, got %+v", out)
	}
	if hasCorr(out, "Repeated OOM Kill — Possible Memory Leak") == nil {
		t.Errorf("expected Repeated OOM Kill correlation via CorrelateDeep, got %+v", out)
	}
	if hasCorr(out, "IO Wait Culprit") == nil {
		t.Errorf("expected IO Wait Culprit via CorrelateDeep, got %+v", out)
	}
}
