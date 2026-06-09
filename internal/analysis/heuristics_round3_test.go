package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-3 characterization tests: clustered-storage data integrity (DRBD,
// multipath, Ceph), kernel-stability log signals, and DNS resolution. Pure
// functions; reuses assertLevel.

// ── DRBD replication state ────────────────────────────────────────────────────

func TestCheckDRBDResource(t *testing.T) {
	tests := []struct {
		name string
		res  models.DRBDResource
		want string
	}{
		{"connected/uptodate is clean", models.DRBDResource{ConnState: "Connected", LocalDisk: "UpToDate"}, ""},
		{"split-brain is CRIT", models.DRBDResource{ConnState: "SplitBrain"}, "CRIT"},
		{"standalone is CRIT", models.DRBDResource{ConnState: "StandAlone"}, "CRIT"},
		{"waiting for peer is WARN", models.DRBDResource{ConnState: "WFConnection"}, "WARN"},
		{"syncing is INFO", models.DRBDResource{ConnState: "SyncTarget", SyncPct: 42}, "INFO"},
		{"local disk failed is CRIT", models.DRBDResource{ConnState: "Connected", LocalDisk: "Failed"}, "CRIT"},
		{"inconsistent not syncing is CRIT", models.DRBDResource{ConnState: "Connected", LocalDisk: "Inconsistent"}, "CRIT"},
		{"outdated is WARN", models.DRBDResource{ConnState: "Connected", LocalDisk: "Outdated"}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDRBDResource(tt.res), tt.want)
		})
	}
}

// ── multipath ─────────────────────────────────────────────────────────────────

func TestCheckMultipath(t *testing.T) {
	mp := func(active, failed, total int) models.MultipathInfo {
		return models.MultipathInfo{Available: true, Devices: []models.MultipathDevice{
			{Name: "mpatha", DM: "dm-0", ActivePaths: active, FailedPaths: failed, TotalPaths: total},
		}}
	}
	assertLevel(t, checkMultipath(models.MultipathInfo{Available: false}), "") // unavailable
	assertLevel(t, checkMultipath(mp(2, 0, 2)), "")                            // all paths healthy
	assertLevel(t, checkMultipath(mp(1, 1, 2)), "WARN")                        // degraded
	assertLevel(t, checkMultipath(mp(0, 2, 2)), "CRIT")                        // all paths failed
}

// ── Ceph cluster health ───────────────────────────────────────────────────────

func TestCheckCeph(t *testing.T) {
	tests := []struct {
		name string
		c    models.CephInfo
		want string
	}{
		{"unavailable + not configured is silent (client binary only)", models.CephInfo{Available: false}, ""},
		{"unavailable + configured is CRIT (cluster unreachable)", models.CephInfo{Available: false, Configured: true}, "CRIT"},
		{"healthy is clean", models.CephInfo{Available: true, Health: "HEALTH_OK", OSDTotal: 3, OSDUp: 3}, ""},
		{"health err is CRIT", models.CephInfo{Available: true, Health: "HEALTH_ERR"}, "CRIT"},
		{"health warn is WARN", models.CephInfo{Available: true, Health: "HEALTH_WARN"}, "WARN"},
		{"osd down is WARN", models.CephInfo{Available: true, Health: "HEALTH_OK", OSDTotal: 5, OSDUp: 4}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkCeph(tt.c), tt.want)
		})
	}
}

// ── log signals (kernel stability, OOM) ───────────────────────────────────────

func TestCheckLogs(t *testing.T) {
	tests := []struct {
		name string
		logs models.LogsInfo
		want string
	}{
		{"clean is empty", models.LogsInfo{}, ""},
		{"needs root is INFO", models.LogsInfo{NeedsRoot: true}, "INFO"},
		{"oom kills is CRIT", models.LogsInfo{OOMKills: 1, OOMProcesses: []string{"java"}}, "CRIT"},
		{"segfaults is WARN", models.LogsInfo{Segfaults: 1, SegfaultProcs: []string{"app"}}, "WARN"},
		{"soft lockup is CRIT", models.LogsInfo{SoftLockups: 1}, "CRIT"},
		{"hard lockup is CRIT", models.LogsInfo{HardLockups: 1}, "CRIT"},
		{"kernel panic is CRIT", models.LogsInfo{KernelPanics: 1}, "CRIT"},
		{"nvme timeout is WARN", models.LogsInfo{NVMeTimeouts: 1}, "WARN"},
		{"crash loop is CRIT", models.LogsInfo{CrashLoops: []string{"x.service"}}, "CRIT"},
		{"large journal is WARN", models.LogsInfo{JournalSizeGB: defaultThresh.JournalSizeWarnGB}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkLogs(tt.logs, defaultThresh), tt.want)
		})
	}
}

// ── DNS resolution ────────────────────────────────────────────────────────────

func TestCheckDNS(t *testing.T) {
	tests := []struct {
		name string
		d    models.DNSResolverInfo
		want string
	}{
		{"healthy is clean", models.DNSResolverInfo{ExternalResolvesOK: true, Manager: "static", ExternalLatencyMs: 50}, ""},
		{"resolution failing is CRIT", models.DNSResolverInfo{ExternalResolvesOK: false, Manager: "systemd-resolved"}, "CRIT"},
		{"failing with no manager is silent", models.DNSResolverInfo{ExternalResolvesOK: false, Manager: "none"}, ""},
		{"slow resolution is WARN", models.DNSResolverInfo{ExternalResolvesOK: true, ExternalLatencyMs: 600}, "WARN"},
		{"public fallback is INFO", models.DNSResolverInfo{ExternalResolvesOK: true, PublicFallback: true, ExternalLatencyMs: 50}, "INFO"},
		{
			name: "too many nameservers is WARN",
			d:    models.DNSResolverInfo{ExternalResolvesOK: true, TooManyNameservers: true, Nameservers: []string{"1", "2", "3", "4"}},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDNS(tt.d), tt.want)
		})
	}
}
