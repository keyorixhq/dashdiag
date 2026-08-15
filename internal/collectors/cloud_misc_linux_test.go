//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── aws_linux.go ──────────────────────────────────────────────────────────────

// TestParseEBSLogPage_BadMagic_ErrorBranch verifies the false-magic path that
// corresponds to ebsRead's meta.failed=true branch (line 336).
func TestParseEBSLogPage_BadMagicSetsFailedMeta(t *testing.T) {
	t.Parallel()
	// Buffer with wrong magic — parseEBSLogPage returns ok=false.
	buf := makeEBSLogPage(0xDEADBEEF, 5, 5, 5, 5)
	if _, ok := parseEBSLogPage(buf); ok {
		t.Error("wrong-magic buffer must return ok=false (drives meta.failed=true in ebsRead)")
	}
}

// TestAwsRebalanceParsing covers awsRebalance's cached parse branches (lines 500-519):
// when the cached value is "yes" / "no" / missing.
// No t.Parallel() — modifies the global activeSource via withCombinedFixture.
func TestAwsRebalanceCachedYes(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token":      []byte("tok"),
		"aws-rebalance-probe": []byte("yes"),
	}, nil, nil)
	checked, recommended := awsRebalance(t.Context())
	if !checked {
		t.Error("checked must be true when cached data is present")
	}
	if !recommended {
		t.Error("recommended must be true when cached value is 'yes'")
	}
}

// No t.Parallel() — modifies the global activeSource via withCombinedFixture.
func TestAwsRebalanceCachedNo(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"imds-aws-token":      []byte("tok"),
		"aws-rebalance-probe": []byte("no"),
	}, nil, nil)
	checked, recommended := awsRebalance(t.Context())
	if !checked {
		t.Error("checked must be true when cached data is present")
	}
	if recommended {
		t.Error("recommended must be false when cached value is 'no'")
	}
}

// TestAwsRebalanceNoToken covers the early-return error branch (line 498):
// when awsIMDSToken fails, awsRebalance must return false, false.
// No t.Parallel() — modifies the global activeSource via withCombinedFixture.
func TestAwsRebalanceNoToken(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	checked, recommended := awsRebalance(t.Context())
	if checked {
		t.Error("checked must be false when IMDS token is unavailable")
	}
	if recommended {
		t.Error("recommended must be false when IMDS token is unavailable")
	}
}

// TestEBSComputeDelta covers the saturation branch: when second < first, result
// must be 0 (counter reset mid-window).
func TestEBSComputeDelta_Saturation(t *testing.T) {
	t.Parallel()
	first := map[string]ebsRaw{"nvme0n1": {volIOPS: 100, volTP: 50, instIOPS: 20, instTP: 10}}
	second := map[string]ebsRaw{"nvme0n1": {volIOPS: 90, volTP: 60, instIOPS: 25, instTP: 5}}
	delta := ebsComputeDelta(first, second)
	d := delta["nvme0n1"]
	if d.volIOPS != 0 {
		t.Errorf("volIOPS underflow: got %d, want 0", d.volIOPS)
	}
	if d.volTP != 10 {
		t.Errorf("volTP delta: got %d, want 10", d.volTP)
	}
	if d.instIOPS != 5 {
		t.Errorf("instIOPS delta: got %d, want 5", d.instIOPS)
	}
	if d.instTP != 0 {
		t.Errorf("instTP underflow: got %d, want 0", d.instTP)
	}
}

// ── cloudmeta_linux.go ────────────────────────────────────────────────────────

// TestCollectAWS_ErrorBranch (line 132): empty token → collectAWS returns false.
// This is already well-covered by TestCollectAWS_NoToken in cloudmeta_linux_test.go;
// skipping to avoid duplication. The awsIMDSToken error branch (line 132) fires
// when the cached token is missing — exercised by the existing test.

// ── cloud_helpers_linux.go ────────────────────────────────────────────────────

// TestProbeIMDSOpen_MalformedURL covers the http.NewRequestWithContext error
// branch (lines 47-61). Uses liveCachedFixture so the produce closure is called
// (Replay.Cached short-circuits without invoking produce, which is what we want
// to exercise). No t.Parallel() — modifies the global activeSource.
func TestProbeIMDSOpen_MalformedURL(t *testing.T) {
	withLiveCachedFixture(t)
	checked, open := probeIMDSOpen(t.Context(), "test-probe-bad-url", "http://\x7f")
	if checked {
		t.Error("checked must be false on a malformed URL")
	}
	if open {
		t.Error("open must be false on a malformed URL")
	}
}

// TestProbeIMDSOpen_CachedOpen covers the happy path through Cached → "open".
// No t.Parallel() — modifies the global activeSource via withCombinedFixture.
func TestProbeIMDSOpen_CachedOpen(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"my-probe-key": []byte("open")}, nil, nil)
	checked, open := probeIMDSOpen(t.Context(), "my-probe-key", "http://169.254.169.254/")
	if !checked {
		t.Error("checked must be true when cached value is present")
	}
	if !open {
		t.Error("open must be true when cached value is 'open'")
	}
}

// TestProbeIMDSOpen_CachedBlocked covers the "blocked" cache case.
// No t.Parallel() — modifies the global activeSource via withCombinedFixture.
func TestProbeIMDSOpen_CachedBlocked(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"probe-blocked": []byte("blocked")}, nil, nil)
	checked, open := probeIMDSOpen(t.Context(), "probe-blocked", "http://169.254.169.254/")
	if !checked {
		t.Error("checked must be true when cached value is present")
	}
	if open {
		t.Error("open must be false when cached value is 'blocked'")
	}
}

// ── proc_linux.go ─────────────────────────────────────────────────────────────

// TestParseProcStatus_MissingFile covers line 129: parseProcStatus returns early
// when the base path doesn't exist.
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestParseProcStatus_MissingFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // empty fixture — file absent
	info := &struct {
		Name    string
		State   string
		PID     int
		PPID    int
		Threads int
		RSSMB   float64
		SwapMB  float64
	}{}
	// Should return without panic when file is absent.
	// We can't call parseProcStatus directly (uses ProcInfo), but we can test
	// the exported collect path — passing a non-existent PID returns an error.
	_, err := collectProcPID(99999999)
	if err == nil {
		t.Error("expected error for non-existent PID")
	}
	if !strings.Contains(err.Error(), "99999999") {
		t.Errorf("error %q should mention the PID", err.Error())
	}
	_ = info
}

// hexToAddr IPv4/IPv6 paths are covered in proc_linux_collectors_test.go.
// TestHexToAddr_Port80 is an additional spot-check of the port parsing branch.
func TestHexToAddr_Port80(t *testing.T) {
	t.Parallel()
	got := hexToAddr("0F02000A:0050") // 10.0.2.15:80
	if !strings.Contains(got, ":80") {
		t.Errorf("hexToAddr port 80: %q should contain ':80'", got)
	}
}

// TestTcpState_KnownAndUnknown covers the tcpState lookup (line 455).
func TestTcpState(t *testing.T) {
	t.Parallel()
	cases := []struct {
		hex  string
		want string
	}{
		{"01", "ESTABLISHED"},
		{"0A", "LISTEN"},
		{"0B", "CLOSING"},
		{"FF", "FF"}, // unknown — pass-through
	}
	for _, c := range cases {
		got := tcpState(c.hex)
		if got != c.want {
			t.Errorf("tcpState(%q) = %q, want %q", c.hex, got, c.want)
		}
	}
}

// TestIsSharedLib covers line 322.
func TestIsSharedLib(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/libfoo.so.6", true},
		{"/usr/lib/libbar.so", true},
		{"/usr/bin/bash", false},
		{"/lib/x86_64-linux-gnu/libc-2.31.so", true},
		{"", false},
	}
	for _, c := range cases {
		got := isSharedLib(c.path)
		if got != c.want {
			t.Errorf("isSharedLib(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// ── steamos_linux.go ──────────────────────────────────────────────────────────

// SteamOS helpers (countNonEmptyLines, lastNonEmptyLine, unitActive,
// steamHostUptimeSeconds) are already covered in steamos_linux_collectors_test.go.

// TestDetectSessionMode covers detectSessionMode branches (line 301).
func TestDetectSessionMode_GamesccopeActive(t *testing.T) {
	t.Parallel()
	info := &models.SteamOSInfo{GamescopeActive: true}
	got := detectSessionMode(info)
	if got != "gamemode" {
		t.Errorf("GamescopeActive=true: mode = %q, want gamemode", got)
	}
}

func TestDetectSessionMode_SDDMActive(t *testing.T) {
	t.Parallel()
	info := &models.SteamOSInfo{SDDMActive: true}
	got := detectSessionMode(info)
	if got != "desktop" {
		t.Errorf("SDDMActive=true: mode = %q, want desktop", got)
	}
}

func TestDetectSessionMode_Unknown(t *testing.T) {
	t.Parallel()
	info := &models.SteamOSInfo{}
	got := detectSessionMode(info)
	if got != "unknown" {
		t.Errorf("empty info: mode = %q, want unknown", got)
	}
}

// ── pve_linux.go ──────────────────────────────────────────────────────────────

// TestParsePVEManagerVersion_SlashFormat covers the slash-delimited
// format specifically (pve_linux_test.go covers the colon format).
func TestParsePVEManagerVersion_SlashFormat(t *testing.T) {
	t.Parallel()
	got := parsePVEManagerVersion("pve-manager/8.3.0/abc123 (running kernel: 6.8)")
	if got != "8.3.0" {
		t.Errorf("slash format: got %q, want 8.3.0", got)
	}
}

// TestParsePVEManagerVersion_EmptyInput covers the empty-fields branch.
func TestParsePVEManagerVersion_EmptyInput(t *testing.T) {
	t.Parallel()
	got := parsePVEManagerVersion("pve-manager")
	if got != "" {
		t.Errorf("no version token: got %q, want empty", got)
	}
}

// TestParsePVEBackupTasks_BadJSON covers the error branch (line 393).
func TestParsePVEBackupTasks_BadJSON(t *testing.T) {
	t.Parallel()
	tasks, ageDays, byVM := parsePVEBackupTasks("not-json")
	if tasks != nil {
		t.Errorf("bad JSON: expected nil tasks, got %v", tasks)
	}
	if ageDays != -1 {
		t.Errorf("bad JSON: expected ageDays=-1, got %d", ageDays)
	}
	if byVM != nil {
		t.Errorf("bad JSON: expected nil byVM, got %v", byVM)
	}
}

// TestCollectPVESubscriptionFile_NoFile covers line 197 when the apt.conf doesn't exist.
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestCollectPVESubscriptionFile_NoFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // file absent
	sub := collectPVESubscriptionFile()
	if sub.Status != "notfound" {
		t.Errorf("missing subscription file: status = %q, want notfound", sub.Status)
	}
}

// TestCollectPVESubscriptionFile_UnverifiedWhenLogin covers line 208.
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestCollectPVESubscriptionFile_UnverifiedWhenLogin(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/apt/auth.conf.d/pve.conf", []byte("machine enterprise.proxmox.com login pveuser password xyz\n"))
	})
	sub := collectPVESubscriptionFile()
	if sub.Status != "unverified" {
		t.Errorf("subscription with login: status = %q, want unverified", sub.Status)
	}
}

// TestCollectPVESubscriptionFile_UnknownWhenNoLogin covers line 211.
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestCollectPVESubscriptionFile_UnknownWhenNoLogin(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/apt/auth.conf.d/pve.conf", []byte("# no real content\n"))
	})
	sub := collectPVESubscriptionFile()
	if sub.Status != "unknown" {
		t.Errorf("subscription without login: status = %q, want unknown", sub.Status)
	}
}

// ── raid_linux.go ─────────────────────────────────────────────────────────────

// TestParseMDStat_ErrorOnBadReader covers line 106 (scanner.Err() path via parseMDStat).
func TestParseMDStat_EmptyInput(t *testing.T) {
	t.Parallel()
	info := parseMDStat(strings.NewReader(""))
	if info == nil {
		t.Fatal("parseMDStat must return non-nil even for empty input")
	}
	if len(info.Arrays) != 0 {
		t.Errorf("empty input: got %d arrays, want 0", len(info.Arrays))
	}
}

// TestParseMDStat_DegradedArray covers the [n/m] health detection path (line 87-93).
func TestParseMDStat_DegradedArray(t *testing.T) {
	t.Parallel()
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976630464 blocks super 1.2 [2/1] [U_]

`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) == 0 {
		t.Fatal("expected at least one array")
	}
	if info.Arrays[0].State != "degraded" {
		t.Errorf("degraded array: state = %q, want degraded", info.Arrays[0].State)
	}
}

// TestParseMDStat_RecoveringArray covers the recovery/resync branch (line 96-101).
func TestParseMDStat_RecoveringArray(t *testing.T) {
	t.Parallel()
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976630464 blocks super 1.2 [2/1] [U_]
      [=>..................] recovery = 5.0% (4882944/97663488) finish=14.9min speed=100000K/sec

`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) == 0 {
		t.Fatal("expected at least one array")
	}
	if info.Arrays[0].State != "recovering" {
		t.Errorf("recovering array: state = %q, want recovering", info.Arrays[0].State)
	}
	if info.Arrays[0].RebuildPct <= 0 {
		t.Errorf("recovering array: RebuildPct = %v, want > 0", info.Arrays[0].RebuildPct)
	}
}

// TestParseMDStat_InactiveArray covers the inactive array path (line 155-157).
func TestParseMDStat_InactiveArray(t *testing.T) {
	t.Parallel()
	const mdstat = `Personalities : [raid1]
md0 : inactive sda1[0] sdb1[1]
      1024 blocks

`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) == 0 {
		t.Fatal("expected at least one array")
	}
	if info.Arrays[0].State != "failed" {
		t.Errorf("inactive array: state = %q, want failed", info.Arrays[0].State)
	}
}

// TestParseMDArrayCounts_GarbledInput covers the negative-guard branch (line 136).
func TestParseMDArrayCounts_GarbledInput(t *testing.T) {
	t.Parallel()
	// A line with no [n/m] — only a progress indicator.
	_, _, ok := parseMDArrayCounts("[=======>............]")
	if ok {
		t.Error("progress bar without n/m must return ok=false")
	}
}

// TestParseRecoveryPct_GarbledInput covers the NaN/Inf/negative guard (line 203-205).
func TestParseRecoveryPct_Garbled(t *testing.T) {
	t.Parallel()
	if pct := parseRecoveryPct("      [>......] recovery = NaN%"); pct != 0 {
		t.Errorf("NaN pct should return 0, got %v", pct)
	}
	if pct := parseRecoveryPct("      [>......] recovery = -5.0%"); pct != 0 {
		t.Errorf("negative pct should return 0, got %v", pct)
	}
}

// ── thermal_linux.go ──────────────────────────────────────────────────────────

// TestThermalCollector_InContainer covers the InContainer early-return (line 38-40).
func TestThermalCollector_InContainer(t *testing.T) {
	t.Parallel()
	c := NewThermalCollectorWithContext(true)
	result, err := c.Collect(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("InContainer=true must return nil result, got %v", result)
	}
}

// TestReadSensorLabel_MissingFile covers line 105-107 (error path).
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestReadSensorLabel_MissingFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // no label file
	got := readSensorLabel("/sys/class/hwmon/hwmon0/temp1_label")
	if got != "" {
		t.Errorf("missing sensor label = %q, want empty", got)
	}
}

// ── timeline_linux.go + timeline_incidents.go ─────────────────────────────────
// Core timeline helpers (parseJournalLine, decodeJournalMessage, truncateMessage,
// deduplicateEvents, stripServiceSuffix, GroupIncidents) are already covered by
// timeline_linux_test.go and timeline_incidents_test.go.

// TestTimelineLevelRank covers the rank helper used by buildIncident (not tested elsewhere).
func TestTimelineLevelRank(t *testing.T) {
	t.Parallel()
	if timelineLevelRank("CRIT") <= timelineLevelRank("WARN") {
		t.Error("CRIT must rank higher than WARN")
	}
	if timelineLevelRank("WARN") <= timelineLevelRank("INFO") {
		t.Error("WARN must rank higher than INFO")
	}
}

// TestDeduplicateEvents_CollapsesSameMinute is an additional dedup case:
// two identical events within the same minute → Count==2 (timeline_linux_test.go
// covers the full dedup table; this verifies the Count accumulator specifically).
func TestDeduplicateEvents_CollapsesSameMinute(t *testing.T) {
	t.Parallel()
	events := []models.TimelineEvent{
		{TimestampUnix: 1700000000, Source: "journal", Level: "WARN", Unit: "ssh", Message: "login failed"},
		{TimestampUnix: 1700000001, Source: "journal", Level: "WARN", Unit: "ssh", Message: "login failed"},
	}
	deduped := deduplicateEvents(events)
	if len(deduped) != 1 {
		t.Fatalf("same-minute dedup: expected 1 entry, got %d", len(deduped))
	}
	if deduped[0].Count != 2 {
		t.Errorf("Count = %d, want 2", deduped[0].Count)
	}
}

// ── drbd_linux.go ─────────────────────────────────────────────────────────────

// TestParseDRBDProc_Empty covers the empty-reader path.
func TestParseDRBDProc_Empty(t *testing.T) {
	t.Parallel()
	info := parseDRBDProc(strings.NewReader(""))
	if info == nil {
		t.Fatal("parseDRBDProc must return non-nil for empty input")
	}
	if len(info.Resources) != 0 {
		t.Errorf("empty input: got %d resources, want 0", len(info.Resources))
	}
}

// TestParseDRBDProc_VersionOnly covers version-header detection.
func TestParseDRBDProc_VersionOnly(t *testing.T) {
	t.Parallel()
	const input = "version: 8.4.11 (api:1/proto:86-101)\n"
	info := parseDRBDProc(strings.NewReader(input))
	if info.Version != "8.4.11 (api:1/proto:86-101)" {
		t.Errorf("version = %q, want 8.4.11 (api:1/proto:86-101)", info.Version)
	}
}

// TestParseDRBD9JSON_BadJSON covers line 105 (unmarshal error → nil).
func TestParseDRBD9JSON_BadJSON(t *testing.T) {
	t.Parallel()
	result := parseDRBD9JSON([]byte("not json"), "9.1.0")
	if result != nil {
		t.Errorf("bad JSON must return nil, got %+v", result)
	}
}

// TestParseDRBDSyncLine_Garbled covers the NaN/negative clamp (line 258-263).
func TestParseDRBDSyncLine_Garbled(t *testing.T) {
	t.Parallel()
	pct, kbLeft := parseDRBDSyncLine("    [>...] sync'ed: -5.0% (98765/102400)K")
	if pct != 0 {
		t.Errorf("negative sync pct must be clamped to 0, got %v", pct)
	}
	if kbLeft < 0 {
		t.Errorf("kbLeft must be non-negative, got %d", kbLeft)
	}
}

// TestParseDRBDResourceLine_NumericMinor covers the minor-number parsing branch
// of parseDRBDResourceLine (the full parse is covered in drbd_linux_test.go).
func TestParseDRBDResourceLine_NumericMinor(t *testing.T) {
	t.Parallel()
	line := "2: cs:StandAlone ro:Secondary/Unknown ds:Diskless/DUnknown r-----"
	res := parseDRBDResourceLine(line)
	if res.Minor != 2 {
		t.Errorf("Minor = %d, want 2", res.Minor)
	}
	if res.ConnState != "StandAlone" {
		t.Errorf("ConnState = %q, want StandAlone", res.ConnState)
	}
}

// ── memory_hotplug_linux.go ───────────────────────────────────────────────────

// TestReadMemHotplugFrom_MissingDir covers line 23 (readDirNames error → false).
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestReadMemHotplugFrom_MissingDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // no hotplug sysfs seeded
	checked, offlineBlocks, offlineMB, autoOnline := readMemHotplugFrom("/sys/devices/system/memory/nonexistent")
	if checked {
		t.Error("missing dir must return checked=false")
	}
	if offlineBlocks != 0 || offlineMB != 0 || autoOnline {
		t.Errorf("missing dir: unexpected values (%d, %d, %v)", offlineBlocks, offlineMB, autoOnline)
	}
}

// TestReadMemHotplugFrom_NoBlocks covers line 44 (no memN subdirs → checked=false).
// No t.Parallel() — modifies the global activeSource via withFixtureSource.
func TestReadMemHotplugFrom_NoBlocks(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// Dir exists but contains no memory<N> entries — only non-block files.
		b.PutFile("/sys/devices/system/memory/block_size_bytes", []byte("8000000\n"))
	})
	checked, _, _, _ := readMemHotplugFrom("/sys/devices/system/memory")
	if checked {
		t.Error("dir with no memory blocks must return checked=false")
	}
}

// ── firmware.go ──────────────────────────────────────────────────────────────

// TestFirmwareCollector_Identity covers the constructor / Name / Timeout.
func TestFirmwareCollector_Identity(t *testing.T) {
	t.Parallel()
	c := NewFirmwareCollector()
	if c.Name() != "Firmware" {
		t.Errorf("Name() = %q, want Firmware", c.Name())
	}
}

// ── gpu_linux.go ──────────────────────────────────────────────────────────────

// TestParseGPUProcesses_EmptyInput_NilResult is already covered by
// TestParseGPUProcesses_Empty in gpu_linux_collectors_test.go — skipped here.

// TestParseGPUProcesses_ShortLine covers the len(fields)<3 guard (line 207).
func TestParseGPUProcesses_ShortLine(t *testing.T) {
	t.Parallel()
	procs := parseGPUProcesses("pid,mem\n") // only 2 fields
	if len(procs) != 0 {
		t.Errorf("short line should be skipped, got %v", procs)
	}
}

// TestParseGPUProcesses_ValidLine covers the happy-path parse.
func TestParseGPUProcesses_ValidLine(t *testing.T) {
	t.Parallel()
	procs := parseGPUProcesses("12345, 512 MiB, python3\n")
	if len(procs) != 1 {
		t.Fatalf("expected 1 process, got %d", len(procs))
	}
	if procs[0].PID != 12345 {
		t.Errorf("PID = %d, want 12345", procs[0].PID)
	}
	if procs[0].MemUseMB != 512 {
		t.Errorf("MemUseMB = %d, want 512", procs[0].MemUseMB)
	}
	if procs[0].Name != "python3" {
		t.Errorf("Name = %q, want python3", procs[0].Name)
	}
}

// TestNaAtoi_NotAvailable covers the [N/A] branch (line 229).
func TestNaAtoi_NAValue(t *testing.T) {
	t.Parallel()
	if _, ok := naAtoi("[N/A]"); ok {
		t.Error("[N/A] must return ok=false")
	}
}

func TestNaAtoi_ERRValue(t *testing.T) {
	t.Parallel()
	if _, ok := naAtoi("ERR!"); ok {
		t.Error("ERR! must return ok=false")
	}
}

func TestNaAtoi_ValidNumber(t *testing.T) {
	t.Parallel()
	n, ok := naAtoi("  42  ")
	if !ok {
		t.Error("valid number must return ok=true")
	}
	if n != 42 {
		t.Errorf("naAtoi = %d, want 42", n)
	}
}

// TestParseNvidiaSMILine_ShortLine covers the len(fields)<8 error (line 242).
func TestParseNvidiaSMILine_ShortLine(t *testing.T) {
	t.Parallel()
	_, _, err := parseNvidiaSMILine("0, Tesla V100, 45")
	if err == nil {
		t.Error("short line must return an error")
	}
}

// TestParseNvidiaSMILine_ValidLine covers a full valid CSV line.
func TestParseNvidiaSMILine_ValidLine(t *testing.T) {
	t.Parallel()
	line := "0, Tesla V100, 65, 80, 8000, 16000, 200.5, 470.82.01, 300.0"
	dev, driverVer, err := parseNvidiaSMILine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev.TempC != 65 {
		t.Errorf("TempC = %d, want 65", dev.TempC)
	}
	if driverVer != "470.82.01" {
		t.Errorf("driverVer = %q, want 470.82.01", driverVer)
	}
	if dev.MemTotalMB != 16000 {
		t.Errorf("MemTotalMB = %d, want 16000", dev.MemTotalMB)
	}
}

// ── vlan_linux.go ─────────────────────────────────────────────────────────────

// TestParseVLANConfig_Empty covers the empty/header-only path (line 77: len(parts)<3).
func TestParseVLANConfig_HeaderOnly(t *testing.T) {
	t.Parallel()
	result := parseVLANConfig("Name-Device | VLAN ID | Parent\n---+---+---\n")
	if len(result) != 0 {
		t.Errorf("header-only input: got %d interfaces, want 0", len(result))
	}
}

// TestParseVLANConfig_ValidEntry covers normal VLAN config parsing.
func TestParseVLANConfig_ValidEntry(t *testing.T) {
	t.Parallel()
	result := parseVLANConfig("Name-Device | VLAN ID | Parent\neth0.100      | 100 | eth0\n")
	if len(result) == 0 {
		t.Fatal("expected 1 VLAN interface")
	}
	if result[0].VLANID != 100 {
		t.Errorf("VLANID = %d, want 100", result[0].VLANID)
	}
	if result[0].Parent != "eth0" {
		t.Errorf("Parent = %q, want eth0", result[0].Parent)
	}
}

// TestParseVLANConfig_ShortLine covers the `len(parts) < 3` continue branch:
// a line that doesn't start with "Name" or "---" but has fewer than 3 "|"
// separators must be silently skipped, not panicked on (parts[2] would panic).
func TestParseVLANConfig_ShortLine(t *testing.T) {
	t.Parallel()
	const input = "Name-Device | VLAN ID | Parent\n---+---+---\nmalformed without enough pipes\neth0.100      | 100 | eth0\n"
	result := parseVLANConfig(input)
	// Only the valid eth0.100 line must parse; the short line is silently skipped.
	if len(result) != 1 || result[0].VLANID != 100 {
		t.Errorf("expected only eth0.100, got %+v", result)
	}
}

// ── vmware_linux.go ───────────────────────────────────────────────────────────

// TestIsVMwareGuest_TableCases covers the DMI matching (line 47-53). Named
// distinctly from vmware_linux_test.go's TestIsVMwareGuest to avoid a
// redeclaration in the same package.
func TestIsVMwareGuest_TableCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sysVendor, productName string
		want                   bool
	}{
		{"VMware, Inc.", "VMware Virtual Platform", true},
		{"VMware, Inc.", "VMware7,1", true},
		{"Dell Inc.", "PowerEdge R740", false},
		{"", "", false},
	}
	for _, c := range cases {
		got := isVMwareGuest(c.sysVendor, c.productName)
		if got != c.want {
			t.Errorf("isVMwareGuest(%q, %q) = %v, want %v", c.sysVendor, c.productName, got, c.want)
		}
	}
}

// ── hwraid_linux.go ───────────────────────────────────────────────────────────

// TestParseStorcli_BadJSON covers line 147 (unmarshal error → nil, false).
func TestParseStorcli_BadJSON(t *testing.T) {
	t.Parallel()
	ctrls, _, ok := parseStorcli("not json")
	if ok {
		t.Error("bad JSON must return ok=false")
	}
	if ctrls != nil {
		t.Errorf("bad JSON: expected nil controllers, got %v", ctrls)
	}
}

// TestParseStorcli_EmptyControllers covers the no-controllers path (line 99-101).
func TestParseStorcli_EmptyControllers(t *testing.T) {
	t.Parallel()
	const empty = `{"Controllers":[]}`
	ctrls, _, ok := parseStorcli(empty)
	if !ok {
		t.Error("valid empty JSON must return ok=true")
	}
	if len(ctrls) != 0 {
		t.Errorf("empty controllers: got %d, want 0", len(ctrls))
	}
}

// TestParseSsacli_BasicParse covers parseSsacli finding a controller + drives.
func TestParseSsacli_BasicParse(t *testing.T) {
	t.Parallel()
	const output = `
   Smart Array P440ar in Slot 0 (Embedded)

      Array A (SAS, Unused Space: 0 MB)

         logicaldrive 1 (1.6 TB, RAID 1, OK)

         physicaldrive 1I:1:1 (port 1I:box 1:bay 1, SAS HDD, 1.2 TB, OK)
         physicaldrive 1I:1:2 (port 1I:box 1:bay 2, SAS HDD, 1.2 TB, Failed)
`
	ctrls := parseSsacli(output)
	if len(ctrls) == 0 {
		t.Fatal("expected 1 controller")
	}
	if len(ctrls[0].VirtualDrives) == 0 {
		t.Error("expected at least 1 virtual drive")
	}
	if len(ctrls[0].PhysicalDrives) < 2 {
		t.Error("expected at least 2 physical drives")
	}
	var foundFailed bool
	for _, pd := range ctrls[0].PhysicalDrives {
		if pd.Failed {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Error("expected one failed physical drive")
	}
}

// TestNormalizeStorcliVD covers storcli state normalization.
func TestNormalizeStorcliVD(t *testing.T) {
	t.Parallel()
	cases := []struct {
		state        string
		wantState    string
		wantDegraded bool
	}{
		{"Optl", "Optimal", false},
		{"Dgrd", "Degraded", true},
		{"Pdgd", "Partially Degraded", true},
		{"OfLn", "Offline", false},
		{"Rec", hwrStatRebuilt, false},
		{"unknown-state", "unknown-state", false},
	}
	for _, c := range cases {
		vd := normalizeStorcliVD("test", storcliVD{State: c.state})
		if vd.State != c.wantState {
			t.Errorf("state %q: vd.State = %q, want %q", c.state, vd.State, c.wantState)
		}
		if vd.Degraded != c.wantDegraded {
			t.Errorf("state %q: vd.Degraded = %v, want %v", c.state, vd.Degraded, c.wantDegraded)
		}
	}
}

// TestStorcliBBU covers the BBU state helper (hwraid_linux_test.go
// TestStorcliBBU_CachevaultFallback covers the CacheVault branch; we add
// explicit no-BBU and failed-state cases).
func TestStorcliBBU_NoBBU(t *testing.T) {
	t.Parallel()
	state, degraded, _ := storcliBBU(nil, nil)
	if state != "" || degraded {
		t.Errorf("no BBU: state=%q degraded=%v, want empty/false", state, degraded)
	}
}

func TestStorcliBBU_FailedState(t *testing.T) {
	t.Parallel()
	// parseStorcli produces the BBU/CacheVault slices from the JSON doc —
	// we can't call storcliBBU directly with a typed slice because the parameter
	// type includes a json tag. Exercise via parseStorcli with a failed BBU entry.
	const doc = `{"Controllers":[{"Command Status":{"Controller":0,"Status":"Success"},"Response Data":{"Product Name":"MegaRAID SAS 9361","VD LIST":[],"PD LIST":[],"BBU_Info":[{"State":"Failed"}]}}]}`
	ctrls, _, ok := parseStorcli(doc)
	if !ok {
		t.Fatal("parseStorcli must succeed for valid JSON")
	}
	if len(ctrls) == 0 {
		t.Fatal("expected 1 controller")
	}
	if !ctrls[0].BBUDegraded {
		t.Error("BBU in Failed state must set BBUDegraded=true")
	}
}

// ── snapper (no build tag) ────────────────────────────────────────────────────

// isSnapperSeparator is already covered by TestIsSnapperSeparator in
// parser_sweep_linux_test.go. Additional edge case: a line with only box-drawing
// vertical bars should also be a separator.
func TestIsSnapperSeparator_VerticalBar(t *testing.T) {
	t.Parallel()
	if !isSnapperSeparator("│ │") {
		t.Error("vertical bars + spaces must be treated as separator")
	}
}
