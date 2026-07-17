//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeStatfsOverrideSource wraps a Bundle-backed Replay but overrides Statfs
// for one path — the Bundle API has no public seam for statfs results.
type fakeStatfsOverrideSource struct {
	*source.Replay
	path string
	info source.StatfsInfo
}

func (f fakeStatfsOverrideSource) Statfs(path string) (source.StatfsInfo, error) {
	if path == f.path {
		return f.info, nil
	}
	return f.Replay.Statfs(path)
}

// ── construction / trivial methods ───────────────────────────────────────────

func TestNewLogsCollector(t *testing.T) {
	c := NewLogsCollector()
	if c.Lookback != time.Hour {
		t.Errorf("expected default Lookback=1h, got %v", c.Lookback)
	}
	if c.Name() != "Logs" || c.Timeout() != 10*time.Second {
		t.Errorf("unexpected Name/Timeout: %q/%v", c.Name(), c.Timeout())
	}
}

func TestNewLogsCollectorWithLookback(t *testing.T) {
	c := NewLogsCollectorWithLookback(30 * time.Minute)
	if c.Lookback != 30*time.Minute {
		t.Errorf("expected Lookback=30m, got %v", c.Lookback)
	}
}

func TestNewLogsCollectorWithProfile(t *testing.T) {
	c := NewLogsCollectorWithProfile(platform.Profile{Distro: "nixos"})
	if c.Lookback != time.Hour || c.profile.Distro != "nixos" {
		t.Errorf("expected default lookback + carried profile, got %+v", c)
	}
}

// ── detectVirtualized ─────────────────────────────────────────────────────────

func TestDetectVirtualized_VMType(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-detect-virt", []string{"-v"}, "kvm\n", 0)
	})
	if !detectVirtualized(context.Background()) {
		t.Error("expected detectVirtualized=true for systemd-detect-virt kvm")
	}
}

func TestDetectVirtualized_BareMetal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemd-detect-virt", []string{"-v"}, "none\n", 1)
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Dell Inc.\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("PowerEdge R750\n"))
	})
	if detectVirtualized(context.Background()) {
		t.Error("expected detectVirtualized=false for bare metal (systemd-detect-virt none, no VMware DMI)")
	}
}

func TestDetectVirtualized_NoSystemdFallsBackToVMwareDMI(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemd-detect-virt", []string{"-v"})
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("VMware, Inc.\n"))
		b.PutFile("/sys/class/dmi/id/product_name", []byte("VMware Virtual Platform\n"))
	})
	if !detectVirtualized(context.Background()) {
		t.Error("expected the VMware DMI fallback to fire when systemd-detect-virt is absent")
	}
}

// ── kmsg / parseKmsg ─────────────────────────────────────────────────────────

func TestParseKmsg_DetectsOOMAndSegfault(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	// timestamps are microseconds since boot; nowUsec = 100000e6. Both records at
	// 99999e6 (1s before "now") — well within a 1h lookback.
	kmsg := "6,100,99999000000,-;Out of memory: Kill process 1234 (nginx) score 900\n" +
		"3,101,99999000000,-;nginx[5678]: segfault at 0 ip 0 sp 0 error 4\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 1 || len(info.OOMProcesses) != 1 || info.OOMProcesses[0] != "nginx" {
		t.Errorf("expected 1 OOM kill (nginx), got %+v", info)
	}
	if info.Segfaults != 1 || len(info.SegfaultProcs) != 1 || info.SegfaultProcs[0] != "nginx" {
		t.Errorf("expected 1 segfault (nginx), got %+v", info)
	}
}

func TestParseKmsg_LockupsPanicsNVMe(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	kmsg := "2,1,99999000000,-;BUG: soft lockup - CPU#0 stuck for 22s!\n" +
		"1,2,99999000000,-;BUG: hard lockup on CPU 1\n" +
		"0,3,99999000000,-;Kernel panic - not syncing: VFS\n" +
		"3,4,99999000000,-;nvme nvme0: I/O 1 QID 3 timeout, aborting\n" +
		"3,5,99999000000,-;nvme nvme0: controller is down; will reset: CSTS=0xffffffff\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.SoftLockups != 1 || info.HardLockups != 1 || info.KernelPanics != 1 {
		t.Errorf("expected 1 each of soft/hard lockup/panic, got %+v", info)
	}
	if info.NVMeTimeouts != 1 || info.NVMeResets != 1 {
		t.Errorf("expected 1 NVMe timeout + 1 reset, got %+v", info)
	}
}

func TestParseKmsg_OutsideLookbackIgnored(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	// 2 hours before "now" (nowUsec=100000e6), lookback is 1h -> excluded.
	kmsg := "3,1,92800000000,-;Out of memory: Kill process 1 (old) score 1\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 0 {
		t.Errorf("expected the 2h-old record to fall outside a 1h lookback, got %+v", info)
	}
}

// TestParseKmsg_UptimeUnreadable covers the "readFile(/proc/uptime) errors ->
// return" branch: kmsg has content, but /proc/uptime can't be read, so
// parseKmsg must bail out without touching info at all.
func TestParseKmsg_UptimeUnreadable(t *testing.T) {
	b := source.NewBundle()
	// No /proc/uptime seeded -> readFile fails.
	kmsg := "6,100,99999000000,-;Out of memory: Kill process 1234 (nginx) score 900\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 0 {
		t.Errorf("expected no-op when /proc/uptime is unreadable, got %+v", info)
	}
}

// TestParseKmsg_UptimeEmptyFields covers the "len(fields) == 0 -> return"
// branch: /proc/uptime is readable but contains only whitespace, so
// strings.Fields yields zero fields.
func TestParseKmsg_UptimeEmptyFields(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("   \n"))
	kmsg := "6,100,99999000000,-;Out of memory: Kill process 1234 (nginx) score 900\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 0 {
		t.Errorf("expected no-op when /proc/uptime has no whitespace-separated fields, got %+v", info)
	}
}

// TestParseKmsg_UptimeUnparseable covers the "strconv.ParseFloat(uptime)
// errors -> return" branch: /proc/uptime is readable but its first field
// isn't a valid float (corrupt/truncated read).
func TestParseKmsg_UptimeUnparseable(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("not-a-number 90000.00\n"))
	kmsg := "6,100,99999000000,-;Out of memory: Kill process 1234 (nginx) score 900\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 0 {
		t.Errorf("expected no-op when /proc/uptime's first field is unparseable, got %+v", info)
	}
}

func TestKmsgRecords_Empty(t *testing.T) {
	b := source.NewBundle()
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte("")}})
	t.Cleanup(func() { SetSource(prev) })
	if got := kmsgRecords(context.Background()); got != nil {
		t.Errorf("expected nil for empty kmsg, got %v", got)
	}
}

// liveCachedKmsgSource mirrors source.Live's Cached semantics (always invoke
// produce) — needed to exercise kmsgRecords' closure body (the readKmsgLive
// call itself), which a plain fakeCombinedSource-with-cached fixture never
// reaches because its Cached short-circuits without invoking produce.
// /dev/kmsg does not exist in the CI/test container, so os.OpenFile fails
// immediately and readKmsgLive returns "" deterministically — no real kernel
// ring buffer is ever read.
type liveCachedKmsgSource struct {
	*source.Replay
}

func (liveCachedKmsgSource) Cached(_ string, produce func() ([]byte, error)) ([]byte, error) {
	return produce()
}

func TestKmsgRecords_LiveClosureUnavailable(t *testing.T) {
	prev := SetSource(liveCachedKmsgSource{Replay: source.NewReplay(source.NewBundle())})
	t.Cleanup(func() { SetSource(prev) })
	if got := kmsgRecords(context.Background()); got != nil {
		t.Errorf("expected nil when /dev/kmsg is unavailable, got %v", got)
	}
}

// ── journal disk usage ───────────────────────────────────────────────────────

func TestJournalDiskUsage(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir(journalRunPath, []string{})
		b.PutDir(journalVarPath, []string{"machine-id-dir"})
		b.PutDir(journalVarPath+"/machine-id-dir", []string{"system.journal"})
		b.PutStat(journalVarPath+"/machine-id-dir/system.journal", source.FileMeta{Size: 2 * 1024 * 1024 * 1024})
	})
	gb := journalDiskUsage()
	if gb < 1.9 || gb > 2.1 {
		t.Errorf("expected ~2GB journal usage, got %v", gb)
	}
}

func TestJournalDiskUsage_MissingDirs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := journalDiskUsage(); got != 0 {
		t.Errorf("expected 0 when neither journal dir exists, got %v", got)
	}
}

// ── crash loop detection ─────────────────────────────────────────────────────

func TestDetectCrashLoops_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"myapp.service    loaded failed failed My App\n", 0)
		recentTS := time.Now().UTC().Format("Mon 2006-01-02 15:04:05 MST")
		b.PutCmd("systemctl", []string{"show", "myapp.service", "--property=NRestarts", "--property=InactiveEnterTimestamp"},
			"NRestarts=7\nInactiveEnterTimestamp="+recentTS+"\n", 0)
	})
	loops := detectCrashLoops(context.Background())
	if len(loops) != 1 {
		t.Fatalf("expected 1 crash loop, got %v", loops)
	}
	if loops[0] != "myapp.service (restarted 7 times)" {
		t.Errorf("unexpected loop entry: %q", loops[0])
	}
}

func TestDetectCrashLoops_BelowThreshold(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"myapp.service    loaded failed failed My App\n", 0)
		b.PutCmd("systemctl", []string{"show", "myapp.service", "--property=NRestarts", "--property=InactiveEnterTimestamp"},
			"NRestarts=2\nInactiveEnterTimestamp=\n", 0)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected no crash loop below the restart threshold, got %v", loops)
	}
}

func TestDetectCrashLoops_NoFailedUnits(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 0)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil on a clean host, got %v", loops)
	}
}

// TestDetectCrashLoops_ListUnitsFails covers the "runCmd(list-units) errors ->
// nil" branch.
func TestDetectCrashLoops_ListUnitsFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 1)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil when list-units fails, got %v", loops)
	}
}

// TestDetectCrashLoops_UnitWithoutDotSkipped covers the "!strings.Contains(unit,
// \".\") -> continue" branch: a malformed/non-unit token in the list-units
// output (no unit-type suffix) must be skipped rather than probed further.
func TestDetectCrashLoops_UnitWithoutDotSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"nodotunit    loaded failed failed No Dot\n", 0)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil for a unit token without a '.', got %v", loops)
	}
}

// TestDetectCrashLoops_NoiseUnitSkipped covers the "cloudInitOrNoiseUnit ->
// continue" branch: cloud-init.service is unconditionally suppressed from the
// crash-loop filter.
func TestDetectCrashLoops_NoiseUnitSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"cloud-init.service    loaded failed failed Cloud Init\n", 0)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil for a noise unit (cloud-init.service), got %v", loops)
	}
}

// TestDetectCrashLoops_ShowFails covers the "runCmd(systemctl show) errors ->
// continue" branch: the unit can't be probed for NRestarts/timestamp, so it
// must be skipped rather than reported (or panicking on empty showOut).
func TestDetectCrashLoops_ShowFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"myapp.service    loaded failed failed My App\n", 0)
		b.PutCmd("systemctl", []string{"show", "myapp.service", "--property=NRestarts", "--property=InactiveEnterTimestamp"},
			"", 1)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil when systemctl show fails, got %v", loops)
	}
}

// TestDetectCrashLoops_StaleLoopSkipped covers the "!crashLoopRecent ->
// continue" branch: a unit above the restart threshold but whose last state
// change is well outside the recency window must not be reported as an
// active crash loop.
func TestDetectCrashLoops_StaleLoopSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"myapp.service    loaded failed failed My App\n", 0)
		staleTS := time.Now().Add(-30 * 24 * time.Hour).UTC().Format("Mon 2006-01-02 15:04:05 MST")
		b.PutCmd("systemctl", []string{"show", "myapp.service", "--property=NRestarts", "--property=InactiveEnterTimestamp"},
			"NRestarts=7\nInactiveEnterTimestamp="+staleTS+"\n", 0)
	})
	if loops := detectCrashLoops(context.Background()); loops != nil {
		t.Errorf("expected nil for a stale (30-day-old) crash loop, got %v", loops)
	}
}

// ── pstore panics ────────────────────────────────────────────────────────────

func TestCountPstorePanics(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/fs/pstore", []string{"dmesg-efi-123456", "dmesg-efi-old", "unrelated.txt"})
		b.PutStat("/sys/fs/pstore/dmesg-efi-123456", source.FileMeta{ModTime: time.Now().Add(-2 * 24 * time.Hour)})
		b.PutStat("/sys/fs/pstore/dmesg-efi-old", source.FileMeta{ModTime: time.Now().Add(-90 * 24 * time.Hour)})
	})
	if got := countPstorePanics(); got != 1 {
		t.Errorf("expected 1 recent panic record (stale one excluded, non-dmesg file ignored), got %d", got)
	}
}

func TestCountPstorePanics_NotMounted(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := countPstorePanics(); got != 0 {
		t.Errorf("expected 0 when pstore isn't mounted, got %d", got)
	}
}

// ── journal health sub-checks ────────────────────────────────────────────────

func TestDetectUnboundedJournal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("SystemMaxUse=500M\n"))
	})
	if detectUnboundedJournal(2.0) {
		t.Error("expected bounded (SystemMaxUse set) to report false")
	}
}

func TestDetectUnboundedJournal_NoCapConfigured(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !detectUnboundedJournal(2.0) {
		t.Error("expected unbounded=true when no SystemMaxUse is set and the journal is already > 1GB")
	}
}

func TestDetectUnboundedJournal_SmallJournalNeverFlags(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if detectUnboundedJournal(0.1) {
		t.Error("expected a small journal to never flag unbounded regardless of config")
	}
}

func TestDetectSyncRisk(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("SyncIntervalSec=5min\n"))
	})
	if !detectSyncRisk(false) {
		t.Error("expected SyncIntervalSec=5min (300s) to flag a risk on a non-volatile journal")
	}
}

func TestDetectSyncRisk_Volatile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("SyncIntervalSec=5min\n"))
	})
	if detectSyncRisk(true) {
		t.Error("expected a volatile journal to never flag sync risk (it already loses logs on reboot)")
	}
}

func TestDetectSyncRisk_DefaultUnset(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !detectSyncRisk(false) {
		t.Error("expected the default (5min, unset) to flag a risk")
	}
}

func TestDetectVolatileJournal_PersistDirPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat(journalVarPath, source.FileMeta{IsDir: true})
	})
	if detectVolatileJournal() {
		t.Error("expected non-volatile when /var/log/journal exists")
	}
}

func TestDetectVolatileJournal_ExplicitPersistentConfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("Storage=persistent\n"))
	})
	if detectVolatileJournal() {
		t.Error("expected non-volatile when Storage=persistent even without the directory present yet")
	}
}

// TestDetectVolatileJournal_ExplicitVolatileConfig covers the "volatile"/"none"
// case branch directly (distinct from the "auto"/unset default branch, which
// also returns true but through the `default:` arm).
func TestDetectVolatileJournal_ExplicitVolatileConfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("Storage=volatile\n"))
	})
	if !detectVolatileJournal() {
		t.Error("expected volatile=true for an explicit Storage=volatile config")
	}
}

func TestDetectVolatileJournal_DefaultAutoIsVolatile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !detectVolatileJournal() {
		t.Error("expected volatile=true when /var/log/journal is missing and Storage is unset (auto default)")
	}
}

func TestDetectJournalRateLimit(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("RateLimitBurst=50\n"))
	})
	if !detectJournalRateLimit() {
		t.Error("expected RateLimitBurst=50 (< 100) to flag rate limiting")
	}
}

func TestDetectJournalRateLimit_DefaultIsFine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if detectJournalRateLimit() {
		t.Error("expected the default (unset) RateLimitBurst to not flag")
	}
}

// TestDetectJournalRateLimit_NonNumericValue covers the "strconv.Atoi errors
// -> false" branch: a malformed RateLimitBurst config value must not flag.
func TestDetectJournalRateLimit_NonNumericValue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("RateLimitBurst=notanumber\n"))
	})
	if detectJournalRateLimit() {
		t.Error("expected a non-numeric RateLimitBurst value to not flag")
	}
}

func TestDetectNoTextFallback_NixOS(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !detectNoTextFallback(platform.Profile{Distro: "nixos"}) {
		t.Error("expected NixOS to always report no text fallback")
	}
}

func TestDetectNoTextFallback_SyslogPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/syslog", source.FileMeta{})
	})
	if detectNoTextFallback(platform.Profile{}) {
		t.Error("expected a fallback when /var/log/syslog exists")
	}
}

func TestDetectNoTextFallback_RsyslogServiceActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "rsyslog"}, "active\n", 0)
	})
	if detectNoTextFallback(platform.Profile{}) {
		t.Error("expected a fallback when rsyslog.service is active even without a text file yet")
	}
}

func TestDetectNoTextFallback_NoneFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !detectNoTextFallback(platform.Profile{}) {
		t.Error("expected no-fallback=true when neither a text file nor a syslog service is found")
	}
}

func TestReadJournaldConfig_DropInOverrides(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("SystemMaxUse=500M\n"))
		b.PutDir("/etc/systemd/journald.conf.d", []string{"override.conf"})
		b.PutFile("/etc/systemd/journald.conf.d/override.conf", []byte("SystemMaxUse=2G\n"))
	})
	if got := readJournaldConfig("SystemMaxUse"); got != "2G" {
		t.Errorf("expected the drop-in to override the base config, got %q", got)
	}
}

func TestReadJournaldConfig_CommentedOutIgnored(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/systemd/journald.conf", []byte("#SystemMaxUse=500M\n"))
	})
	if got := readJournaldConfig("SystemMaxUse"); got != "" {
		t.Errorf("expected a commented-out key to be ignored, got %q", got)
	}
}

func TestIsServiceActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "rsyslog"}, "active\n", 0)
	})
	if !isServiceActive("rsyslog") {
		t.Error("expected isServiceActive=true when systemctl reports active")
	}
}

func TestIsServiceActive_Inactive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "rsyslog"}, "inactive\n", 3)
	})
	if isServiceActive("rsyslog") {
		t.Error("expected isServiceActive=false when systemctl reports inactive")
	}
}

// ── log disk usage ───────────────────────────────────────────────────────────

func TestLogDiskUsage(t *testing.T) {
	b := source.NewBundle()
	b.PutStat(journalVarPath, source.FileMeta{IsDir: true})
	b.PutFile("/proc/self/mountinfo", []byte("25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"+
		"26 25 8:2 / /var/log rw,relatime shared:2 - ext4 /dev/sda2 rw\n"))
	prev := SetSource(fakeStatfsOverrideSource{
		Replay: source.NewReplay(b),
		path:   journalVarPath,
		info:   source.StatfsInfo{Bsize: 4096, Blocks: 1000, Bfree: 100}, // 90% used
	})
	t.Cleanup(func() { SetSource(prev) })

	mount, pct := logDiskUsage()
	if mount != "/var/log" {
		t.Errorf("expected mount=/var/log (the seeded mountinfo entry), got %q", mount)
	}
	if pct < 89 || pct > 91 {
		t.Errorf("expected ~90%% used, got %v", pct)
	}
}

func TestLogDiskUsage_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	mount, pct := logDiskUsage()
	if mount != "" || pct != 0 {
		t.Errorf("expected empty/zero when statfs fails on both targets, got mount=%q pct=%v", mount, pct)
	}
}

// ── checkJournalHealth (end-to-end) ──────────────────────────────────────────

func TestCheckJournalHealth_NoSystemd(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.LogsInfo{}
	checkJournalHealth(context.Background(), info, platform.Profile{})
	if info.JournalVolatile || info.JournalRateLimited || info.JournalUnbounded {
		t.Errorf("expected all journal-health fields to stay zero when systemd isn't present, got %+v", info)
	}
}

func TestCheckJournalHealth_FullPath(t *testing.T) {
	b := source.NewBundle()
	b.PutStat("/run/systemd/private", source.FileMeta{}) // systemdPresentViaSource gate
	b.PutFile("/etc/systemd/journald.conf", []byte("RateLimitBurst=50\n"))
	b.PutFile("/proc/self/mountinfo", []byte("25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"))
	prev := SetSource(fakeStatfsOverrideSource{
		Replay: source.NewReplay(b),
		path:   "/var/log",
		info:   source.StatfsInfo{Bsize: 4096, Blocks: 1000, Bfree: 500},
	})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{JournalSizeGB: 2.0}
	checkJournalHealth(context.Background(), info, platform.Profile{})

	if !info.JournalVolatile {
		t.Error("expected JournalVolatile=true (no /var/log/journal dir, Storage unset)")
	}
	if !info.JournalRateLimited {
		t.Error("expected JournalRateLimited=true (RateLimitBurst=50)")
	}
	if !info.JournalUnbounded {
		t.Error("expected JournalUnbounded=true (no SystemMaxUse cap, journal already 2GB)")
	}
	if info.JournalSyncRisk {
		t.Error("expected JournalSyncRisk=false — a volatile journal is excluded from sync risk")
	}
	if info.LogDiskMount == "" {
		t.Error("expected LogDiskMount to be populated from the statfs fallback to /var/log")
	}
}

// TestCheckJournalHealth_CorruptArchived covers the "fileExists(journalVarPath)
// && hasCorruptArchived -> JournalCorrupt=true" branch, which
// TestCheckJournalHealth_FullPath above never reaches (it seeds no
// /var/log/journal directory at all).
func TestCheckJournalHealth_CorruptArchived(t *testing.T) {
	b := source.NewBundle()
	b.PutStat("/run/systemd/private", source.FileMeta{}) // systemdPresentViaSource gate
	b.PutStat(journalVarPath, source.FileMeta{IsDir: true})
	b.PutDir(journalVarPath, []string{"system.journal~"})
	b.PutCmd("journalctl", []string{"--verify", "--file=" + journalVarPath + "/system.journal~"},
		"FAIL: /var/log/journal/system.journal~ (Bad message)\n", 1)
	b.PutFile("/proc/self/mountinfo", []byte("25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"))
	prev := SetSource(fakeStatfsOverrideSource{
		Replay: source.NewReplay(b),
		path:   "/var/log",
		info:   source.StatfsInfo{Bsize: 4096, Blocks: 1000, Bfree: 500},
	})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	checkJournalHealth(context.Background(), info, platform.Profile{})
	if !info.JournalCorrupt {
		t.Error("expected JournalCorrupt=true when journalctl --verify reports FAIL on an archived journal")
	}
}

// ── collectSeveritySummary ───────────────────────────────────────────────────

func TestCollectSeveritySummary_CountsErrorsAndWarnings(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"},
			"2026-06-03T09:00:00+00:00 host myapp[100]: database connection refused\n"+
				"2026-06-03T09:05:00+00:00 host myapp[100]: database connection refused\n", 0)
		b.PutCmd("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"},
			"Jun 03 09:00:00 host myapp[100]: database connection refused\n"+
				"Jun 03 09:10:00 host myapp[100]: disk usage climbing\n", 0)
	})
	info := &models.LogsInfo{}
	collectSeveritySummary(context.Background(), info, time.Hour)
	if info.ErrorCount != 2 {
		t.Errorf("expected 2 errors, got %d", info.ErrorCount)
	}
	if info.ErrorScanFailed {
		t.Error("expected ErrorScanFailed=false on a successful query")
	}
	if len(info.TopErrors) == 0 || len(info.TopCritical) == 0 {
		t.Error("expected TopErrors/TopCritical populated")
	}
	// journalctl -p warning includes <= warning, so ErrorCount is subtracted:
	// 2 warning-level lines - 2 errors = 0.
	if info.WarningCount != 0 {
		t.Errorf("expected WarningCount=0 after subtracting errors, got %d", info.WarningCount)
	}
}

func TestCollectSeveritySummary_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"})
		b.PutCmdNotFound("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"})
	})
	info := &models.LogsInfo{}
	collectSeveritySummary(context.Background(), info, time.Hour)
	if !info.ErrorScanFailed {
		t.Error("expected ErrorScanFailed=true when the journalctl query fails")
	}
	if info.ErrorCount != 0 {
		t.Errorf("expected ErrorCount=0 on a failed scan, got %d", info.ErrorCount)
	}
}

// TestCollectSeveritySummary_BenignKernelErrSkipped covers line 804-805: a line
// from the error journal that matches a known benign kernel pattern (e.g.
// "of_root node is null") is skipped rather than counted as a real error.
func TestCollectSeveritySummary_BenignKernelErrSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"},
			"2026-06-03T09:00:00+00:00 host kernel: of_root node is null, cannot create root phandle\n"+
				"2026-06-03T09:05:00+00:00 host myapp[100]: real error here\n", 0)
		b.PutCmdNotFound("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"})
	})
	info := &models.LogsInfo{}
	collectSeveritySummary(context.Background(), info, time.Hour)
	if info.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1 (benign kernel err must be skipped)", info.ErrorCount)
	}
}

// TestCollectSeveritySummary_WarningCountClampedToZero covers line 833-835:
// when ErrorCount exceeds the WarningCount computed from warnOut, the subtraction
// goes negative and must be clamped to 0.
func TestCollectSeveritySummary_WarningCountClampedToZero(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"},
			"2026-06-03T09:00:00+00:00 host myapp[100]: error one\n"+
				"2026-06-03T09:05:00+00:00 host myapp[100]: error two\n", 0)
		// warnOut is empty → WarningCount stays 0 before subtraction; 0 - 2 = -2 → clamped to 0.
		b.PutCmd("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"},
			"", 0)
	})
	info := &models.LogsInfo{}
	collectSeveritySummary(context.Background(), info, time.Hour)
	if info.WarningCount != 0 {
		t.Errorf("WarningCount = %d, want 0 (negative result must be clamped to zero)", info.WarningCount)
	}
	if info.ErrorCount != 2 {
		t.Errorf("ErrorCount = %d, want 2", info.ErrorCount)
	}
}

// ── collectCrashFiles ─────────────────────────────────────────────────────────

func TestCollectCrashFiles(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/var/crash", []string{"core.1234"})
		b.PutStat("/var/crash/core.1234", source.FileMeta{Size: 1024 * 1024, ModTime: time.Now().Add(-3 * 24 * time.Hour)})
		b.PutDir("/var/lib/systemd/coredump", []string{})
		b.PutDir("/sys/fs/pstore", []string{"dmesg-efi-1"})
		b.PutStat("/sys/fs/pstore/dmesg-efi-1", source.FileMeta{Size: 4096, ModTime: time.Now().Add(-1 * 24 * time.Hour)})
	})
	info := &models.LogsInfo{}
	collectCrashFiles(info)
	if info.CoreDumpCount != 2 || len(info.CrashFiles) != 2 {
		t.Errorf("expected 2 crash files (1 core dump + 1 pstore panic), got %+v", info)
	}
}

func TestCollectCrashFiles_None(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.LogsInfo{}
	collectCrashFiles(info)
	if info.CoreDumpCount != 0 || len(info.CrashFiles) != 0 {
		t.Errorf("expected no crash files on a clean host, got %+v", info)
	}
}

// ── detectLogSource ───────────────────────────────────────────────────────────

func TestDetectLogSource_JournaldOnly(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/journal/socket", source.FileMeta{})
	})
	if got := detectLogSource(platform.Profile{}); got != "journald" {
		t.Errorf("expected journald, got %q", got)
	}
}

func TestDetectLogSource_JournaldPlusSyslog(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/journal/socket", source.FileMeta{})
		b.PutStat("/var/log/syslog", source.FileMeta{Size: 100})
	})
	if got := detectLogSource(platform.Profile{}); got != "journald+syslog" {
		t.Errorf("expected journald+syslog, got %q", got)
	}
}

func TestDetectLogSource_SyslogOnly(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/messages", source.FileMeta{Size: 100})
	})
	if got := detectLogSource(platform.Profile{}); got != "syslog" {
		t.Errorf("expected syslog, got %q", got)
	}
}

func TestDetectLogSource_Unknown(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := detectLogSource(platform.Profile{}); got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

func TestDetectLogSource_NixOSJournaldOnlyProfile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/syslog", source.FileMeta{Size: 100}) // must be ignored on NixOS
	})
	if got := detectLogSource(platform.Profile{Distro: "nixos"}); got != "unknown" {
		t.Errorf("expected unknown (no journald socket, syslog probe skipped), got %q", got)
	}
}

// ── collectVarLogErrors (thin production wrapper) ────────────────────────────

func TestCollectVarLogErrors_UsesRealCandidatePaths(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/log/syslog", source.FileMeta{Size: 100})
		b.PutFile("/var/log/syslog", []byte("Jun  3 10:00:00 host app[1]: error: disk failing\n"))
	})
	info := &models.LogsInfo{}
	collectVarLogErrors(info)
	if info.LogSource != "syslog" || info.ErrorCount != 1 {
		t.Errorf("expected the real /var/log/syslog candidate to be consulted, got %+v", info)
	}
}

// ── lookbackToSince ───────────────────────────────────────────────────────────

func TestLookbackToSince(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{48 * time.Hour, "2 days ago"},
		{3 * time.Hour, "3 hours ago"},
		{30 * time.Minute, "30 minutes ago"},
	}
	for _, tc := range cases {
		if got := lookbackToSince(tc.d); got != tc.want {
			t.Errorf("lookbackToSince(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ── Collect (end-to-end) ─────────────────────────────────────────────────────

func TestLogsCollector_Collect_Smoke(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("systemd-detect-virt", []string{"-v"}, "none\n", 1)
	b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Dell Inc.\n"))
	b.PutFile("/sys/class/dmi/id/product_name", []byte("PowerEdge R750\n"))
	b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 0)
	b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"}, "", 0)
	b.PutCmd("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"}, "", 0)
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte("")}})
	t.Cleanup(func() { SetSource(prev) })

	c := NewLogsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.LogsInfo)
	if !info.Available {
		t.Error("expected Available=true")
	}
	if info.Virtualized {
		t.Error("expected Virtualized=false for the bare-metal fixture")
	}
	if info.LogSource != "unknown" {
		t.Errorf("expected LogSource=unknown (no journald socket / syslog file seeded), got %q", info.LogSource)
	}
}

// TestLogsCollector_Collect_VarLogFallback covers the shouldReadVarLogFallback
// TRUE branch inside Collect: no journald socket + a real /var/log/syslog
// present makes detectLogSource return "syslog", and journalctl's (seeded)
// zero-error scan means ErrorCount stays 0 going into the fallback check — so
// Collect must consult /var/log/syslog and flip ErrorCount/LogSource/TopErrors
// from that file rather than reporting a false "0 errors, nothing to fall
// back to".
func TestLogsCollector_Collect_VarLogFallback(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("systemd-detect-virt", []string{"-v"}, "none\n", 1)
	b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Dell Inc.\n"))
	b.PutFile("/sys/class/dmi/id/product_name", []byte("PowerEdge R750\n"))
	b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 0)
	b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"}, "", 0)
	b.PutCmd("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"}, "", 0)
	b.PutStat("/var/log/syslog", source.FileMeta{Size: 100})
	b.PutFile("/var/log/syslog", []byte("Jun  3 10:00:00 host app[1]: error: disk failing\n"))
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte("")}})
	t.Cleanup(func() { SetSource(prev) })

	c := NewLogsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.LogsInfo)
	if info.LogSource != "syslog" {
		t.Errorf("LogSource = %q, want syslog (no journald socket, /var/log/syslog present)", info.LogSource)
	}
	if info.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1 (from the /var/log/syslog fallback line)", info.ErrorCount)
	}
	if info.ErrorCountUnverified {
		t.Error("expected ErrorCountUnverified=false: the /var/log fallback covered the scan")
	}
}

// TestLogsCollector_Collect_ErrorScanFailedUnverified covers the
// "ErrorScanFailed && !fellBack" branch: the journalctl error-priority scan
// itself fails (non-zero exit) AND there is no /var/log fallback to cover for
// it (LogSource stays "unknown" — no journald socket, no syslog file), so
// Collect must flag ErrorCountUnverified rather than silently reporting a
// trustworthy-looking ErrorCount=0.
func TestLogsCollector_Collect_ErrorScanFailedUnverified(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("systemd-detect-virt", []string{"-v"}, "none\n", 1)
	b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Dell Inc.\n"))
	b.PutFile("/sys/class/dmi/id/product_name", []byte("PowerEdge R750\n"))
	b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 0)
	// journalctl error scan fails outright (e.g. journald not running/reachable).
	b.PutCmd("journalctl", []string{"-p", "err", "--since", "1 hours ago", "--no-pager", "-q", "--output=short-iso"}, "", 1)
	b.PutCmd("journalctl", []string{"-p", "warning", "--since", "1 hours ago", "--no-pager", "-q", "--output=short"}, "", 1)
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte("")}})
	t.Cleanup(func() { SetSource(prev) })

	c := NewLogsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info := raw.(*models.LogsInfo)
	if info.LogSource != "unknown" {
		t.Fatalf("LogSource = %q, want unknown (no journald socket / syslog file seeded)", info.LogSource)
	}
	if !info.ErrorCountUnverified {
		t.Error("expected ErrorCountUnverified=true: journalctl scan failed and no /var/log fallback covered it")
	}
}

// TestParseKmsg_ContextCancelledMidLoop covers line 225-226: ctx.Done() fires
// during the per-line loop → parseKmsg returns early.
func TestParseKmsg_ContextCancelledMidLoop(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	kmsg := "6,100,99999000000,-;Out of memory: Kill process 1234 (nginx) score 900\n" +
		"3,101,99999000000,-;nginx[5678]: segfault at 0 ip 0 sp 0 error 4\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the very first select case fires
	info := &models.LogsInfo{}
	parseKmsg(ctx, info, time.Hour)
	// With a pre-cancelled context the loop exits before processing either line.
	if info.OOMKills != 0 || info.Segfaults != 0 {
		t.Errorf("expected no events processed with cancelled context, got %+v", info)
	}
}

// TestParseKmsg_LineWithoutSemicolon covers line 232-233: a kmsg line that
// contains no ';' has semi<0 and is skipped.
func TestParseKmsg_LineWithoutSemicolon(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	kmsg := "malformed line no semicolon here\n" +
		"6,200,99999000000,-;Out of memory: Kill process 9 (bad) score 1\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 1 {
		t.Errorf("expected 1 OOM kill (malformed line skipped, valid line parsed), got %+v", info)
	}
}

// TestParseKmsg_MetaFewFields covers line 239-240: the meta part before ';'
// splits into fewer than 3 comma-separated fields → line is skipped.
func TestParseKmsg_MetaFewFields(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	// "6,100" has only 2 comma-separated fields (need ≥3 for index [2]=timestamp)
	kmsg := "6,100;Out of memory: Kill process 9 (bad) score 1\n" +
		"6,200,99999000000,-;Out of memory: Kill process 7 (good) score 1\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 1 {
		t.Errorf("expected 1 OOM kill (short-meta line skipped, valid line parsed), got %+v", info)
	}
}

// TestParseKmsg_NonNumericTimestamp covers line 243-244: the timestamp field
// in the meta part is not a valid float → line is skipped.
func TestParseKmsg_NonNumericTimestamp(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/proc/uptime", []byte("100000.00 90000.00\n"))
	// meta part has 3+ fields but field[2] is "notanumber"
	kmsg := "6,100,notanumber,-;Out of memory: Kill process 9 (bad) score 1\n" +
		"6,200,99999000000,-;Out of memory: Kill process 7 (good) score 1\n"
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: map[string][]byte{"kmsg": []byte(kmsg)}})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.LogsInfo{}
	parseKmsg(context.Background(), info, time.Hour)
	if info.OOMKills != 1 {
		t.Errorf("expected 1 OOM kill (non-numeric timestamp skipped, valid line parsed), got %+v", info)
	}
}
