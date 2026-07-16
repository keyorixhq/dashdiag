//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── logs_linux.go ─────────────────────────────────────────────────────────────

// NOTE: TestIsVMVirtType, TestExtractParenthesized, TestCrashLoopRecent,
// TestCrashFileTooOld, TestLookbackToSince, TestParseSystemdTime, and
// TestShouldReadVarLogFallback already exist elsewhere in this package
// (logs_linux_test.go, parsers_round3_test.go, logs_linux_collectors_test.go)
// — omitted here to avoid func redeclarations.

// TestExtractBracketProc covers the bracket-process extractor.
// NOTE: also already covered in parsers_round3_test.go — omitted to avoid redeclaration.

// TestScanVarLog_Empty covers the zero-errors early return.
func TestScanVarLog_Empty(t *testing.T) {
	t.Parallel()
	count, top, crit := scanVarLog("this line has nothing bad in it\n", time.Now())
	if count != 0 || top != nil || crit != nil {
		t.Errorf("expected zero results, got count=%d top=%v crit=%v", count, top, crit)
	}
}

// TestDetectLogSource_NixOSJournald covers the nixos shortcut: journald socket
// present → "journald" (no syslog probe on journald-only distros).
func TestDetectLogSource_NixOSJournald(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/systemd/journal/socket", source.FileMeta{})
	})
	got := detectLogSource(platform.Profile{Distro: "nixos"})
	if got != "journald" {
		t.Errorf("detectLogSource(nixos, socket present) = %q, want journald", got)
	}
}

// TestDetectLogSource_NixOSNoSocket covers nixos without a journald socket → "unknown".
func TestDetectLogSource_NixOSNoSocket(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	got := detectLogSource(platform.Profile{Distro: "nixos"})
	if got != "unknown" {
		t.Errorf("detectLogSource(nixos, no socket) = %q, want unknown", got)
	}
}

// TestLogsCollectorIdentity covers Name/Timeout methods.
func TestLogsCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewLogsCollector()
	if c.Name() != "Logs" {
		t.Errorf("Name() = %q, want Logs", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

// TestTopMessages covers the frequency-sort and deduplication.
func TestTopMessages(t *testing.T) {
	t.Parallel()
	counts := map[string]int{
		"a": 5,
		"b": 3,
		"c": 5, // tie with "a" — deterministic by key: "a" < "c"
		"d": 1,
	}
	got := topMessages(counts, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 results, got %d", len(got))
	}
	// Both "a" and "c" have count 5; key sort makes "a" first
	if !strings.HasPrefix(got[0], "×5 a") {
		t.Errorf("got[0] = %q, want starts with ×5 a", got[0])
	}
}

// ── kernel_security.go ────────────────────────────────────────────────────────

// NOTE: TestIsSafePolicyToken and TestExtractAVCProcesses already exist in
// misc_parsers_test.go — omitted here to avoid func redeclarations.

// NOTE: isRecentAVCDenial is already covered by TestIsRecentAVCDenial in
// kernel_security_test.go (recent/old/permissive/granted/non-AVC/missing-
// timestamp branches) — omitted here to avoid a func redeclaration.

// NOTE: TestValidateSELinuxPolicyType_RelabelPending for the /.autorelabel
// branch already exists in kernel_security_linux_test.go — omitted here to
// avoid a func redeclaration.

// TestKernelSecurityCollectorIdentity covers Name/Timeout.
func TestKernelSecurityCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewKernelSecurityCollector()
	if c.Name() != "KernelSec" {
		t.Errorf("Name() = %q, want KernelSec", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// ── security_linux.go ─────────────────────────────────────────────────────────

// TestParseSSHFileContent_EmptyAndComments covers the no-op branches: empty
// lines, comment lines, and lines with fewer than 2 fields are all skipped.
func TestParseSSHFileContent_EmptyAndComments(t *testing.T) {
	t.Parallel()
	info := &models.SecurityInfo{
		SSHPubkeyAuth:   true,
		SSHStrictModes:  true,
		SSHIgnoreRhosts: true,
	}
	parseSSHFileContent("# comment\n\nOnlyOneField\n", info)
	if !info.SSHPubkeyAuth || !info.SSHStrictModes || !info.SSHIgnoreRhosts {
		t.Error("defaults changed by comment/empty/single-field content")
	}
}

// TestParseSSHFileContent_MatchBlock covers the inMatch suppression: directives
// inside a Match block must not be read as the global policy.
func TestParseSSHFileContent_MatchBlock(t *testing.T) {
	t.Parallel()
	info := &models.SecurityInfo{SSHPubkeyAuth: true}
	content := "Match Address 10.0.0.0/8\nPasswordAuthentication yes\nMatch all\nPasswordAuthentication no\n"
	parseSSHFileContent(content, info)
	if info.SSHPasswordAuth {
		t.Error("Match-block PasswordAuthentication yes must not set global SSHPasswordAuth")
	}
}

// TestParseSSHFileContent_AllKeys covers every switch case in parseSSHFileContent.
func TestParseSSHFileContent_AllKeys(t *testing.T) {
	t.Parallel()
	content := `PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
Port 2222
Protocol 1
MaxAuthTries 3
LoginGraceTime 1m
AllowUsers alice bob
AllowGroups admins
X11Forwarding yes
AllowAgentForwarding yes
PermitEmptyPasswords yes
StrictModes no
ClientAliveInterval 60
IgnoreRhosts no
HostbasedAuthentication yes
PermitUserEnvironment yes
AllowTcpForwarding yes
LogLevel DEBUG
Banner /etc/ssh/banner
MaxSessions 5
MaxStartups 10:30:60
Ciphers aes128-ctr
MACs hmac-sha2-256
KexAlgorithms curve25519-sha256
`
	info := &models.SecurityInfo{}
	parseSSHFileContent(content, info)

	if !info.SSHRootLogin {
		t.Error("expected SSHRootLogin=true")
	}
	if !info.SSHPasswordAuth {
		t.Error("expected SSHPasswordAuth=true")
	}
	if info.SSHPubkeyAuth {
		t.Error("expected SSHPubkeyAuth=false")
	}
	if info.SSHPort != 2222 {
		t.Errorf("SSHPort = %d, want 2222", info.SSHPort)
	}
	if !info.SSHProtocol1 {
		t.Error("expected SSHProtocol1=true")
	}
	if info.SSHMaxAuthTries != 3 {
		t.Errorf("SSHMaxAuthTries = %d, want 3", info.SSHMaxAuthTries)
	}
	if info.SSHLoginGraceTime != 60 {
		t.Errorf("SSHLoginGraceTime = %d, want 60", info.SSHLoginGraceTime)
	}
	if len(info.SSHAllowUsers) == 0 {
		t.Error("expected SSHAllowUsers to be populated")
	}
	if len(info.SSHAllowGroups) == 0 {
		t.Error("expected SSHAllowGroups to be populated")
	}
	if !info.SSHX11Forwarding {
		t.Error("expected X11Forwarding=true")
	}
	if !info.SSHAgentForwarding {
		t.Error("expected AgentForwarding=true")
	}
	if !info.SSHPermitEmptyPwd {
		t.Error("expected PermitEmptyPasswords=true")
	}
	if info.SSHStrictModes {
		t.Error("expected StrictModes=false (explicitly no)")
	}
	if info.SSHClientAliveInterval != 60 {
		t.Errorf("ClientAliveInterval = %d, want 60", info.SSHClientAliveInterval)
	}
	if info.SSHIgnoreRhosts {
		t.Error("expected IgnoreRhosts=false (explicitly no)")
	}
	if !info.SSHHostbasedAuth {
		t.Error("expected HostbasedAuth=true")
	}
	if !info.SSHPermitUserEnv {
		t.Error("expected PermitUserEnvironment=true")
	}
	if !info.SSHTCPForwarding {
		t.Error("expected AllowTcpForwarding=true")
	}
	if info.SSHLogLevel != "DEBUG" {
		t.Errorf("LogLevel = %q, want DEBUG", info.SSHLogLevel)
	}
	if info.SSHBanner != "/etc/ssh/banner" {
		t.Errorf("Banner = %q, want /etc/ssh/banner", info.SSHBanner)
	}
	if info.SSHMaxSessions != 5 {
		t.Errorf("MaxSessions = %d, want 5", info.SSHMaxSessions)
	}
	if info.SSHMaxStartups != "10:30:60" {
		t.Errorf("MaxStartups = %q, want 10:30:60", info.SSHMaxStartups)
	}
	if info.SSHCiphers != "aes128-ctr" {
		t.Errorf("Ciphers = %q, want aes128-ctr", info.SSHCiphers)
	}
	if info.SSHMACs != "hmac-sha2-256" {
		t.Errorf("MACs = %q, want hmac-sha2-256", info.SSHMACs)
	}
	if info.SSHKexAlgorithms != "curve25519-sha256" {
		t.Errorf("KexAlgorithms = %q, want curve25519-sha256", info.SSHKexAlgorithms)
	}
}

// NOTE: TestParseSSHDuration already exists in ssh_config_linux_test.go —
// omitted here to avoid a func redeclaration.

// TestParsePasswordAging_ShadowMissing covers the absent /etc/shadow branch.
func TestParsePasswordAging_ShadowMissing(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.SecurityInfo{}
	parsePasswordAging(info)
	// absent file is not permission-denied → ShadowUnreadable must be false
	if info.ShadowUnreadable {
		t.Error("ShadowUnreadable should be false for a missing /etc/shadow")
	}
}

// TestParsePasswordAging_EmptyAndStale covers the core password-audit branches.
func TestParsePasswordAging_EmptyAndStale(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/shadow", []byte(
			"root::19000:0:99999:7:::\n"+
				"alice:x:19000:0:99999:7:::\n"+
				"deploy:x:19000:0:90:7:::\n"))
		b.PutFile("/etc/passwd", []byte(
			"root:x:0:0:root:/root:/bin/bash\n"+
				"alice:x:1000:1000::/home/alice:/bin/bash\n"+
				"deploy:x:1001:1001::/home/deploy:/bin/bash\n"))
	})
	info := &models.SecurityInfo{}
	parsePasswordAging(info)
	if len(info.EmptyPasswordAccounts) == 0 {
		t.Error("expected root in EmptyPasswordAccounts")
	}
	if len(info.StalePasswordAccounts) == 0 {
		t.Error("expected alice in StalePasswordAccounts (max=99999)")
	}
}

// TestParseWorldWritable_StickyBitPresent covers the normal /tmp that has
// sticky bit — must NOT be in WorldWritableDirs.
func TestParseWorldWritable_StickyBitPresent(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		// mode 01777 (dir + world-writable + sticky)
		m := os.ModeDir | os.ModeSticky | 0o777
		b.PutStat("/tmp", source.FileMeta{Mode: m})
		b.PutStat("/var/tmp", source.FileMeta{Mode: m})
		b.PutStat("/dev/shm", source.FileMeta{Mode: m})
	})
	info := &models.SecurityInfo{}
	parseWorldWritable(info)
	if len(info.WorldWritableDirs) != 0 {
		t.Errorf("expected no world-writable dirs when sticky bits present, got %v", info.WorldWritableDirs)
	}
}

// NOTE: TestSecurityCollectorIdentity already exists in
// security_linux_collectors_test.go — omitted here to avoid a func redeclaration.

// NOTE: TestParseFcontextRules already exists in security_selinux_deep_test.go —
// omitted here to avoid a func redeclaration.

// TestParseFcontextRules_ShortLine covers the len(fields) < 2 skip branch.
func TestParseFcontextRules_ShortLine(t *testing.T) {
	t.Parallel()
	rules := parseFcontextRules("onlyonefield\n")
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from short line, got %d", len(rules))
	}
}

// NOTE: TestAVCField and TestLastPart already exist in security_linux_test.go —
// omitted here to avoid func redeclarations.

// ── cron_linux.go ─────────────────────────────────────────────────────────────

// TestParseCronLogLine_TooFewFields covers the early return for lines with fewer
// than 6 fields.
func TestParseCronLogLine_TooFewFields(t *testing.T) {
	t.Parallel()
	ts, job := parseCronLogLine("May 19 10:00:01")
	if !ts.IsZero() || job != "" {
		t.Errorf("expected zero time and empty job for short line, got ts=%v job=%q", ts, job)
	}
}

// TestParseCronLogLine_FallbackJob covers the fallback path (no CMD token).
func TestParseCronLogLine_FallbackJob(t *testing.T) {
	t.Parallel()
	line := "May 19 10:00:01 host crond[123]: some failure message here"
	_, job := parseCronLogLine(line)
	if job == "" {
		t.Error("expected fallback job from fields[5:]")
	}
}

// TestParseCronLogLine_CMDJob covers the CMD extraction path.
func TestParseCronLogLine_CMDJob(t *testing.T) {
	t.Parallel()
	line := "May 19 10:00:01 host crond[123]: (root) CMD (backup.sh)"
	_, job := parseCronLogLine(line)
	if job != "backup.sh" {
		t.Errorf("expected job=backup.sh, got %q", job)
	}
}

// TestParseCronLogFailures_NoneRecent covers the cutoff guard: old "failed"
// lines must not be included.
func TestParseCronLogFailures_NoneRecent(t *testing.T) {
	t.Parallel()
	// Timestamp parses but resolves to year 2000, well before the 24h cutoff
	content := "Jan  1 00:00:01 host crond[1]: (root) CMD (job) FAILED"
	failures := parseCronLogFailures(content)
	if len(failures) != 0 {
		t.Errorf("expected 0 failures for old log entry, got %d", len(failures))
	}
}

// NOTE: TestCronCollectorIdentity already exists in cron_linux_collectors_test.go
// — omitted here to avoid a func redeclaration.

// ── cpufreq_linux.go ──────────────────────────────────────────────────────────

// TestCPUFreqCollector_NoSysfs covers the absent-cpufreq early return (governor
// empty → return empty info, nil).
func TestCPUFreqCollector_NoSysfs(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewCPUFreqCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.CPUFreqInfo)
	if info.Governor != "" {
		t.Errorf("expected empty Governor when sysfs absent, got %q", info.Governor)
	}
}

// NOTE: TestCPUFreqCollectorIdentity already exists in cpufreq_linux_test.go —
// omitted here to avoid a func redeclaration.

// NOTE: TestParseCPUFreqGovernor and TestParseCPUFreqKHz already exist in
// hugepages_cpufreq_linux_test.go — omitted here to avoid func redeclarations.

// ── disk_linux.go ─────────────────────────────────────────────────────────────

// TestCollectPhysicalDrives_NoPartitions covers the openFile error path
// (returns nil when /proc/partitions is missing).
func TestCollectPhysicalDrives_NoPartitions(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	drives := collectPhysicalDrives()
	if drives != nil {
		t.Errorf("expected nil drives when /proc/partitions missing, got %v", drives)
	}
}

// TestDiskDetectType_SysfsError covers diskDetectType when the rotational
// sysfs file is absent → returns DriveTypeSSD as the safe default.
func TestDiskDetectType_SysfsError(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	got := diskDetectType("sda")
	if got != models.DriveTypeSSD {
		t.Errorf("diskDetectType with missing rotational file = %v, want SSD", got)
	}
}

// NOTE: TestDiskDetectType_NVMe already exists in parsers_round2_test.go, and
// TestDiskDetectType_HDD already exists in disk_linux_extras_test.go — omitted
// here to avoid func redeclarations.

// ── dns_linux.go ─────────────────────────────────────────────────────────────

// NOTE: TestParseResolvConf_MissingFile already exists in dns_linux_source_test.go
// — omitted here to avoid a func redeclaration.

// TestParseResolvConf_DuplicateNameserver covers the dedup branch.
func TestParseResolvConf_DuplicateNameserver(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte(
			"nameserver 8.8.8.8\n"+
				"nameserver 8.8.8.8\n"+
				"nameserver 1.1.1.1\n"))
	})
	info := &models.DNSResolverInfo{}
	parseResolvConf(info)
	if len(info.Nameservers) != 2 {
		t.Errorf("expected 2 unique nameservers, got %d", len(info.Nameservers))
	}
	if len(info.DuplicateNameserver) != 1 || info.DuplicateNameserver[0] != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8 in DuplicateNameserver, got %v", info.DuplicateNameserver)
	}
}

// NOTE: TestAnalyzeDNSQuality already exists in dns_linux_source_test.go —
// omitted here to avoid a func redeclaration.

// TestAnalyzeDNSQuality_IPv6Only covers the all-IPv6 branch.
func TestAnalyzeDNSQuality_IPv6Only(t *testing.T) {
	t.Parallel()
	info := &models.DNSResolverInfo{
		Nameservers: []string{"2001:4860:4860::8888"},
	}
	analyzeDNSQuality(info)
	if !info.IPv6Only {
		t.Error("expected IPv6Only=true")
	}
}

// TestAnalyzeDNSQuality_LoopbackWithoutStub covers the loopback-non-stub branch.
func TestAnalyzeDNSQuality_LoopbackWithoutStub(t *testing.T) {
	t.Parallel()
	info := &models.DNSResolverInfo{
		Nameservers: []string{"127.0.0.1"},
		StubMode:    false,
	}
	analyzeDNSQuality(info)
	if !info.HasLoopback {
		t.Error("expected HasLoopback=true for 127.x non-stub")
	}
}

// NOTE: TestDNSCollectorIdentity already exists in dns_linux_source_test.go —
// omitted here to avoid a func redeclaration.

// ── cve_health.go ─────────────────────────────────────────────────────────────

// TestCVEHealthCollector_NoBundleEntry covers the err != nil branch (line 53–59):
// replaying a bundle without a cve/health key returns a non-nil CVEAllResult
// with a diagnostic status reason.
func TestCVEHealthCollector_NoBundleEntry(t *testing.T) {
	// no t.Parallel(): withCombinedFixture mutates the package-level activeSource.
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {})
	c := NewCVEHealthCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, ok := res.(*models.CVEAllResult)
	if !ok {
		t.Fatalf("expected *models.CVEAllResult, got %T", res)
	}
	if !strings.Contains(out.StatusReason, "not captured") {
		t.Errorf("expected 'not captured' in StatusReason, got %q", out.StatusReason)
	}
}

// NOTE: TestCVEHealthCollectorIdentity already exists in cve_health_test.go —
// omitted here to avoid a func redeclaration.

// ── packages_linux.go ─────────────────────────────────────────────────────────

// NOTE: TestPackagesCollectorIdentity already exists in packages_scanners2_test.go
// — omitted here to avoid a func redeclaration.

// TestAptAccumulateUpdate_CriticalPackage covers the critical-package prefix match.
func TestAptAccumulateUpdate_CriticalPackage(t *testing.T) {
	t.Parallel()
	info := &models.PackagesInfo{}
	criticalPkgs := map[string]bool{"openssl": true}
	aptAccumulateUpdate(info, criticalPkgs,
		"Inst openssl [1.1.1f-1ubuntu2.19] (1.1.1f-1ubuntu2.20 Ubuntu:security [amd64])")
	if info.CriticalUpdates != 1 {
		t.Errorf("CriticalUpdates = %d, want 1", info.CriticalUpdates)
	}
	if info.SecurityUpdates != 1 {
		t.Errorf("SecurityUpdates = %d, want 1", info.SecurityUpdates)
	}
}

// TestAptAccumulateUpdate_TooFewFields covers the early-return guard.
func TestAptAccumulateUpdate_TooFewFields(t *testing.T) {
	t.Parallel()
	info := &models.PackagesInfo{}
	aptAccumulateUpdate(info, nil, "Inst")
	if info.SecurityUpdates != 0 {
		t.Error("expected no update from a too-short line")
	}
}

// TestAptAccumulateUpdate_ImportantPackage covers a non-critical package
// (goes into ImportantUpdates).
func TestAptAccumulateUpdate_ImportantPackage(t *testing.T) {
	t.Parallel()
	info := &models.PackagesInfo{}
	aptAccumulateUpdate(info, map[string]bool{},
		"Inst libfoo [1.0] (1.1 Ubuntu:security [amd64])")
	if info.ImportantUpdates != 1 {
		t.Errorf("ImportantUpdates = %d, want 1", info.ImportantUpdates)
	}
}

// ── health_deep_linux.go ──────────────────────────────────────────────────────

// TestReadCgroupOOMKills_MissingFile covers the readFile error branch.
func TestReadCgroupOOMKills_MissingFile(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	got := readCgroupOOMKills("/nonexistent/subdir/memory.events")
	if got != 0 {
		t.Errorf("expected 0 OOM kills from missing file, got %d", got)
	}
}

// TestReadCgroupOOMKills_NoOOMLine covers present file but no oom_kill line.
func TestReadCgroupOOMKills_NoOOMLine(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/system.slice/memory.events", []byte("anon 0\nfile 0\n"))
	})
	got := readCgroupOOMKills("/sys/fs/cgroup/system.slice/memory.events")
	if got != 0 {
		t.Errorf("expected 0 when no oom_kill line, got %d", got)
	}
}

// TestReadCgroupOOMKills_Present covers the normal "oom_kill N" parse.
func TestReadCgroupOOMKills_Present(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/cgroup/memory.events", []byte("oom_kill 3\nanon 1000\n"))
	})
	got := readCgroupOOMKills("/sys/fs/cgroup/memory.events")
	if got != 3 {
		t.Errorf("expected 3 OOM kills, got %d", got)
	}
}

// TestComputeTopIORates_EmptyInputs covers the empty/zero-rate paths.
func TestComputeTopIORates_EmptyInputs(t *testing.T) {
	t.Parallel()
	if got := computeTopIORates(nil, nil, 5); len(got) != 0 {
		t.Errorf("expected empty result from nil maps, got %d entries", len(got))
	}

	// A process that only existed in "after" (new PID) → skipped
	after := map[int]procIOCounters{99: {name: "new", readBytes: 100, writeBytes: 50}}
	if got := computeTopIORates(nil, after, 5); len(got) != 0 {
		t.Errorf("expected new-PID to be skipped, got %d entries", len(got))
	}
}

// TestComputeTopIORates_TopN covers the top-N cap and rate computation.
func TestComputeTopIORates_TopN(t *testing.T) {
	t.Parallel()
	before := map[int]procIOCounters{
		1: {name: "proc1", readBytes: 0, writeBytes: 0},
		2: {name: "proc2", readBytes: 0, writeBytes: 0},
		3: {name: "proc3", readBytes: 0, writeBytes: 0},
	}
	after := map[int]procIOCounters{
		1: {name: "proc1", readBytes: 1000, writeBytes: 500},
		2: {name: "proc2", readBytes: 500, writeBytes: 200},
		3: {name: "proc3", readBytes: 100, writeBytes: 50},
	}
	got := computeTopIORates(before, after, 2)
	if len(got) != 2 {
		t.Fatalf("expected top-2, got %d", len(got))
	}
	if got[0].Name != "proc1" {
		t.Errorf("top entry name = %q, want proc1", got[0].Name)
	}
}

// NOTE: TestHealthDeepCollectorIdentity already exists in
// health_deep_linux_samplers_test.go — omitted here to avoid a func redeclaration.

// TestCgroupScopeIn_MissingFile covers the readFile-error early return.
func TestCgroupScopeIn_MissingFile(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	got := cgroupScopeIn("/nonexistent/subdir", "1234")
	if got != "" {
		t.Errorf("expected empty scope from missing cgroup file, got %q", got)
	}
}

// TestCgroupScopeIn_SystemdService covers cgroup v2 "system.slice" path →
// "system:<service>" label.
func TestCgroupScopeIn_SystemdService(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/fake/proc/42/cgroup", []byte("0::/system.slice/nginx.service\n"))
	})
	got := cgroupScopeIn("/fake/proc", "42")
	if got != "system:nginx.service" {
		t.Errorf("cgroupScopeIn = %q, want system:nginx.service", got)
	}
}

// TestCGV1FallbackScope covers the cgroup v1 cpu subsystem path fallback.
func TestCGV1FallbackScope(t *testing.T) {
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/fake/proc/42/cgroup", []byte("8:cpu:/system.slice/ssh.service\n"))
	})
	got := cgroupScopeIn("/fake/proc", "42")
	if got == "" {
		t.Error("expected non-empty cgroup scope from v1 cpu path")
	}
}
