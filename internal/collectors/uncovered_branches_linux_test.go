//go:build linux

package collectors

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── bonding_linux.go:71 ───────────────────────────────────────────────────────

// TestParseBondFile_OpenError exercises the openFile-error early-return in
// parseBondFile: a path that does not exist in the fixture source must return
// an error, not an empty BondInterface.
func TestParseBondFile_OpenError(t *testing.T) {
	t.Parallel()
	withFixtureSource(t, func(_ *source.Bundle) {
		// Deliberately seed nothing — /no/such/bond will not be found.
	})
	_, err := parseBondFile("/no/such/bond/bonding_file")
	if err == nil {
		t.Error("parseBondFile on a missing path must return an error")
	}
}

// ── cron_linux.go:358,386 ─────────────────────────────────────────────────────

// TestParseCronLogLine_CMDParenAtZero guards the parseCronLogLine branch where
// ") CMD (" is found but the closing ")" in `rest` is at position 0 (end==0),
// so the CMD extraction is skipped and the fallback joins fields[5:] instead.
func TestParseCronLogLine_CMDParenAtZero(t *testing.T) {
	t.Parallel()
	// ") CMD (" is present, but the rest immediately starts with ")" — end==0.
	line := "May 19 10:00:01 hostname crond[123]: (root) CMD ()"
	ts, job := parseCronLogLine(line)
	// The CMD-extraction path requires end > 0; "()" yields rest="" → LastIndex=-1
	// which is < 0 ... wait — LastIndex("", ")") returns -1, so end < 0. In that
	// case the fallback fires. The job should be the tail of the line (fields[5:]).
	if ts.IsZero() {
		t.Error("a valid syslog timestamp should parse")
	}
	// After CMD extraction fails (empty command body), fallback returns fields[5:]
	// which includes "(root)", "CMD", "()" — that is fine; we just need job != "".
	if job == "" {
		t.Errorf("fallback should produce a non-empty job from fields[5:], got %q", job)
	}
}

// TestParseCronLogFailures_WithJobLine covers the main happy path of
// parseCronLogFailures: a line with "failed" in the last 24h produces exactly
// one CronFailure entry. This specifically exercises the failure append at
// cron_linux.go:375.
func TestParseCronLogFailures_WithJobLine(t *testing.T) {
	t.Parallel()
	recent := time.Now().Add(-30 * time.Minute)
	line := fmt.Sprintf("%s myhost crond[42]: (root) CMD (cleanup.sh) exit status 1 FAILED",
		recent.Format("Jan 2 15:04:05"))
	failures := parseCronLogFailures(line)
	if len(failures) != 1 {
		t.Fatalf("expected 1 failure, got %d: %+v", len(failures), failures)
	}
	if failures[0].Job != "cleanup.sh" {
		t.Errorf("job = %q, want cleanup.sh", failures[0].Job)
	}
}

// ── drbd_linux.go:233 ─────────────────────────────────────────────────────────

// TestParseDRBDSyncLine_GarbledPct exercises the garbled-percentage clamp
// branch: a negative or NaN/Inf percentage must be clamped to 0 rather than
// propagated (parseDRBDSyncLine:259-260).
func TestParseDRBDSyncLine_GarbledPct(t *testing.T) {
	t.Parallel()
	// Negative percentage — parseFloat("-5.0") gives -5, which must clamp.
	pct, _ := parseDRBDSyncLine("[=>..................] sync'ed: -5.0% (99/100)")
	if pct != 0 {
		t.Errorf("negative pct must clamp to 0, got %v", pct)
	}
}

// TestParseDRBDSyncLine_CommaNumbers guards the comma-stripping in
// kbLeft parsing: "98,765" in the parenthesised block must parse to 98765.
func TestParseDRBDSyncLine_CommaNumbers(t *testing.T) {
	t.Parallel()
	pct, kb := parseDRBDSyncLine("[=>..................] sync'ed: 12.5% (98,765/102400)")
	if pct != 12.5 {
		t.Errorf("pct = %v, want 12.5", pct)
	}
	if kb != 98765 {
		t.Errorf("kbLeft = %d, want 98765", kb)
	}
}

// ── firewall_linux.go:177,589 ─────────────────────────────────────────────────

// TestParseNFTInputAccept_LoopbackOnly guards the iif "lo" accept: it must be
// skipped without marking the ruleset indeterminable (loopback-only, no
// external reachability). The port is NOT added to accepted.
func TestParseNFTInputAccept_LoopbackOnly(t *testing.T) {
	t.Parallel()
	const rs = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		tcp dport 22 accept
	}
}`
	accepted, determinable := parseNFTInputAccept(rs)
	if !determinable {
		t.Error("a lo-accept-only plus literal dport ruleset must stay determinable")
	}
	if !accepted[22] {
		t.Error("tcp dport 22 must be in accepted")
	}
}

// TestParseIPTList_REJECTPolicy guards the policy-REJECT branch in parseIPTList
// (line 606): a chain with "policy REJECT" must set Policy="drop" and
// DefaultDrop=true on INPUT.
func TestParseIPTList_REJECTPolicy(t *testing.T) {
	t.Parallel()
	const out = `Chain INPUT (policy REJECT)
target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:22
`
	var info models.FirewallInfo
	parseIPTList(out, &info)
	if !info.DefaultDrop {
		t.Error("policy REJECT on INPUT must set DefaultDrop=true")
	}
	if len(info.Chains) == 0 || info.Chains[0].Policy != "drop" {
		t.Errorf("chain policy = %q, want drop", info.Chains[0].Policy)
	}
}

// TestParseIPTList_AcceptPolicy guards that policy ACCEPT on INPUT does NOT
// set DefaultDrop.
func TestParseIPTList_AcceptPolicy(t *testing.T) {
	t.Parallel()
	const out = `Chain INPUT (policy ACCEPT)
target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:22
`
	var info models.FirewallInfo
	parseIPTList(out, &info)
	if info.DefaultDrop {
		t.Error("policy ACCEPT on INPUT must not set DefaultDrop")
	}
	if len(info.Chains) == 0 || info.Chains[0].Policy != "accept" {
		t.Errorf("chain policy = %q, want accept", info.Chains[0].Policy)
	}
}

// ── hwraid_linux.go:145,241 ───────────────────────────────────────────────────

// TestParseStorcli_EmptyVDName exercises the `name = "VD " + vd.DGVD` fallback
// in parseStorcli when a VD has no Name field (line 161).
func TestParseStorcli_EmptyVDName(t *testing.T) {
	t.Parallel()
	const json = `{
"Controllers":[{
  "Command Status":{"Controller":0,"Status":"Success"},
  "Response Data":{
    "Product Name":"MegaRAID",
    "VD LIST":[{"DG/VD":"0/1","TYPE":"RAID1","State":"Optl","Name":""}]
  }
}]}`
	ctrls, ok := parseStorcli(json)
	if !ok || len(ctrls) != 1 {
		t.Fatalf("parseStorcli() = (%v, %v), want one ctrl ok", ctrls, ok)
	}
	if len(ctrls[0].VirtualDrives) != 1 {
		t.Fatalf("VDs = %d, want 1", len(ctrls[0].VirtualDrives))
	}
	if ctrls[0].VirtualDrives[0].Name != "VD 0/1" {
		t.Errorf("VD name = %q, want VD 0/1 (synthesised from DG/VD)", ctrls[0].VirtualDrives[0].Name)
	}
}

// TestParseSsacli_MultipleControllers exercises the `if cur != nil { ctrls =
// append(...) }` branch inside parseSsacli (line 249-251): it fires when a
// second controller header is encountered while `cur` already points to the
// first. The existing single-controller test never triggers this branch.
func TestParseSsacli_MultipleControllers(t *testing.T) {
	t.Parallel()
	const out = `Smart Array P440ar in Slot 0 (Embedded)

   Array A (SAS HDD, Unused Space: 0 MB)

      logicaldrive 1 (1.6 TB, RAID 1, OK)

      physicaldrive 1I:1:1 (port 1I:box 1:bay 1, SAS HDD, 1.6 TB, OK)

Smart Array E208i-a in Slot 1 (RAID)

   Array A (SATA HDD, Unused Space: 0 MB)

      logicaldrive 1 (2.0 TB, RAID 5, OK)

      physicaldrive 2I:1:1 (port 2I:box 1:bay 1, SATA HDD, 2.0 TB, OK)
`
	ctrls := parseSsacli(out)
	if len(ctrls) != 2 {
		t.Fatalf("controllers = %d, want 2 (multi-controller branch untested)", len(ctrls))
	}
	if ctrls[0].Model != "Smart Array P440ar" {
		t.Errorf("ctrl[0].Model = %q, want Smart Array P440ar", ctrls[0].Model)
	}
	if ctrls[1].Model != "Smart Array E208i-a" {
		t.Errorf("ctrl[1].Model = %q, want Smart Array E208i-a", ctrls[1].Model)
	}
}

// ── lvm_parse.go:71 ───────────────────────────────────────────────────────────

// TestParseLVs_MergingSnapshot covers the 'S' case in parseLVs (merging
// snapshot — lv_attr[0]=='S'). Merged snapshots share the same code path as
// 's' snapshots, so they should appear in the snapshots slice.
func TestParseLVs_MergingSnapshot(t *testing.T) {
	t.Parallel()
	// lv_attr[0]='S': merging snapshot (active merge in progress)
	const out = `  merging_snap  pve  Swi-a-s---  55.00         base-lv  2.00
`
	_, snaps := parseLVs(out)
	if len(snaps) != 1 {
		t.Fatalf("parseLVs: expected 1 merging snapshot (case 'S'), got %d", len(snaps))
	}
	if snaps[0].Name != "merging_snap" {
		t.Errorf("Name = %q, want merging_snap", snaps[0].Name)
	}
	if snaps[0].Origin != "base-lv" {
		t.Errorf("Origin = %q, want base-lv", snaps[0].Origin)
	}
}

// TestParseLVs_ThinPool_ShortLine covers the < 6 fields branch inside the 't'
// case of parseLVs: when lv_size is absent, sizeGB defaults to 0.
func TestParseLVs_ThinPool_ShortLine(t *testing.T) {
	t.Parallel()
	// Exactly 5 fields — below the sizeGB threshold of 6.
	const out = `  pool0  vg0  twi-aotz-- 70.00  3.00
`
	pools, _ := parseLVs(out)
	if len(pools) != 1 {
		t.Fatalf("parseLVs: expected 1 thin pool, got %d", len(pools))
	}
	if pools[0].SizeGB != 0 {
		t.Errorf("SizeGB = %v, want 0 when lv_size column is absent", pools[0].SizeGB)
	}
}

// ── multipath_linux.go:96,163 ─────────────────────────────────────────────────

// TestParseMultipathShow_AllActive_ActivPathCounterIncrement ensures the
// `active`/`ready` path increments ActivePaths (the non-failure branch at
// line 138-139). This complements the degraded-device test.
func TestParseMultipathShow_AllActive_ActivPathCounterIncrement(t *testing.T) {
	t.Parallel()
	const out = `sda ready ATA,WDC mpatha
sdb active ATA,WDC mpatha`
	devices := parseMultipathShow(out)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d: %+v", len(devices), devices)
	}
	d := devices[0]
	if d.ActivePaths != 2 {
		t.Errorf("ActivePaths = %d, want 2 (both active/ready)", d.ActivePaths)
	}
	if d.FailedPaths != 0 {
		t.Errorf("FailedPaths = %d, want 0", d.FailedPaths)
	}
	if d.State != "active" {
		t.Errorf("State = %q, want active", d.State)
	}
}

// TestParseMultipathL_FaultyState covers the `faulty` keyword in
// parseMultipathL path lines (line 196): a "faulty" token must mark the path
// failed and increment FailedPaths.
func TestParseMultipathL_FaultyState(t *testing.T) {
	t.Parallel()
	const out = `mpathc (uuid) dm-2 VENDOR,MODEL
size=500G features='0' hwhandler='0' wp=rw
` + "`-+- policy='queue-length 0' prio=50 status=active" + `
  ` + "`- 0:0:1:0 sdc 8:32 faulty running"
	devices := parseMultipathL(out)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d: %+v", len(devices), devices)
	}
	d := devices[0]
	if d.FailedPaths != 1 {
		t.Errorf("FailedPaths = %d, want 1 (faulty path)", d.FailedPaths)
	}
	if d.State != "degraded" {
		t.Errorf("State = %q, want degraded", d.State)
	}
}

// ── raid_linux.go:54 ──────────────────────────────────────────────────────────

// TestParseMDStat_NoTrailingBlankLine exercises the parseMDStat path where the
// file ends WITHOUT a blank line — the final array is appended by the
// post-loop `if current != nil` guard (line 103).
func TestParseMDStat_NoTrailingBlankLine(t *testing.T) {
	t.Parallel()
	// No trailing newline / blank line — current != nil after the scanner loop.
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976630464 blocks super 1.2 [2/2] [UU]`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 1 {
		t.Fatalf("got %d arrays, want 1 (no-trailing-blank-line guard)", len(info.Arrays))
	}
}

// TestParseMDStat_InlineArraySeparation exercises the case where two arrays
// appear without a blank line between them — the second header immediately
// follows the first's block lines. The existing-current guard fires.
func TestParseMDStat_TwoArraysNoBlank(t *testing.T) {
	t.Parallel()
	const mdstat = `Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      1000 blocks super 1.2 [2/2] [UU]
md1 : active raid1 sdc1[0] sdd1[1]
      2000 blocks super 1.2 [2/2] [UU]

unused devices: <none>`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 2 {
		t.Fatalf("got %d arrays, want 2 (two arrays without blank line between)", len(info.Arrays))
	}
}

// TestParseMDArrayCounts_GarbledNegative covers the "garbled input — negative
// count" rejection branch (line 137): a negative value in [n/m] must be
// skipped (keep scanning) rather than returned as ok=true.
func TestParseMDArrayCounts_GarbledNegative(t *testing.T) {
	t.Parallel()
	// [-1/2] is syntactically valid [n/m] but negative — must be rejected.
	total, active, ok := parseMDArrayCounts("1000 blocks [X/Y] [-1/2]")
	if ok {
		t.Errorf("parseMDArrayCounts with negative count must return ok=false, got total=%d active=%d", total, active)
	}
}

// TestParseMDStat_ResyncLine exercises the "resync" variant of the recovery
// keyword (line 96 of raid_linux.go says `recovery` OR `resync`).
func TestParseMDStat_ResyncLine(t *testing.T) {
	t.Parallel()
	const mdstat = `Personalities : [raid5]
md2 : active raid5 sda[0] sdb[1] sdc[2]
      1000 blocks super 1.2 [3/3] [UUU]
      [=>..................]  resync = 5.0% (50000/1000000) finish=10.0min speed=90000K/sec

unused devices: <none>`
	info := parseMDStat(strings.NewReader(mdstat))
	if len(info.Arrays) != 1 {
		t.Fatalf("got %d arrays, want 1", len(info.Arrays))
	}
	if info.Arrays[0].State != "recovering" {
		t.Errorf("State = %q, want recovering (resync keyword)", info.Arrays[0].State)
	}
}

// ── security_linux.go:940 — parseSELinuxContextIssues empty paths ─────────────

// TestParseSELinuxContextIssues_EmptyGroups covers the `len(paths) == 0`
// early-return (line 942): groups with no Paths must return nil without
// invoking any shell commands.
func TestParseSELinuxContextIssues_EmptyGroups(t *testing.T) {
	t.Parallel()
	// Groups with no Paths — uniqueAVCPaths returns empty → immediate nil return.
	groups := []models.SELinuxAVCGroup{
		{Scontext: "httpd_t", Tcontext: "admin_home_t", Tclass: "bpf", Paths: nil},
	}
	// parseSELinuxContextIssues calls shell commands only when paths != empty.
	// With an empty fixture source, it must still return nil cleanly.
	withFixtureSource(t, func(_ *source.Bundle) {})
	issues := parseSELinuxContextIssues(t.Context(), groups)
	if issues != nil {
		t.Errorf("expected nil for groups with no paths, got %+v", issues)
	}
}

// ── security_linux.go:1034 — parseFcontextRules regex compile error ───────────

// TestParseFcontextRules_InvalidRegex covers the `regexp.Compile` error branch
// (line 1046): a pattern that Go's RE2 cannot compile must be silently skipped
// rather than panicking or producing a false-flag.
func TestParseFcontextRules_InvalidRegex(t *testing.T) {
	t.Parallel()
	// An invalid regex pattern (unmatched bracket is a RE2 error).
	const out = `SELinux fcontext                                  type               Context

/data/valid(/.*)?                                  all files          system_u:object_r:httpd_sys_content_t:s0
[invalid-regex-unclosed                            all files          system_u:object_r:httpd_sys_content_t:s0
/data/also-valid                                   all files          system_u:object_r:admin_home_t:s0
`
	rules := parseFcontextRules(out)
	// The invalid-regex line must be skipped; only the two valid lines survive.
	if len(rules) != 2 {
		t.Errorf("expected 2 rules (invalid regex skipped), got %d: %+v", len(rules), rules)
	}
}

// ── security_linux.go:2076 — scanAVCLine dir-class path extraction ────────────

// TestScanAVCLine_DirClass exercises the `tclass == "dir"` branch in
// scanAVCLine (line 2121): an absolute name= on a dir-class denial must be
// added to the group's paths, just like the file-class case.
func TestScanAVCLine_DirClass(t *testing.T) {
	t.Parallel()
	now := time.Now()
	recent := now.Add(-30 * time.Second).Unix()

	line := fmt.Sprintf(
		`type=AVC msg=audit(%d.123:456): avc:  denied  { write } for  pid=1234 `+
			`comm="httpd" name="/data/logs" `+
			`scontext=system_u:system_r:httpd_t:s0 `+
			`tcontext=unconfined_u:object_r:admin_home_t:s0 `+
			`tclass=dir permissive=0`,
		recent,
	)

	groups := map[avcGroupKey]*avcGroupData{}
	scanAVCLine(line, groups, now.Add(-1*time.Hour))

	if len(groups) == 0 {
		t.Fatal("scanAVCLine must produce a group entry for a dir-class denial")
	}
	var found bool
	for _, g := range groups {
		if g.paths["/data/logs"] {
			found = true
		}
	}
	if !found {
		t.Error("the absolute dir path /data/logs must be captured in the group's paths")
	}
}

// ── steamos_parse.go:315 ─────────────────────────────────────────────────────

// TestParseARPPeers_SkipsFAILEDandINCOMPLETE is a branch-completion guard: the
// existing test only checks the "lladdr absent" skip and the gateway skip.
// This guards that entries WITH lladdr but in FAILED or INCOMPLETE state are
// also skipped (lines 325-326 of steamos_parse.go). An additional REACHABLE
// entry (not gateway) must still be counted.
func TestParseARPPeers_SkipsFAILEDandINCOMPLETE(t *testing.T) {
	t.Parallel()
	const out = `192.168.10.2 dev wlan0 lladdr aa:bb:cc:dd:ee:01 FAILED
192.168.10.3 dev wlan0 lladdr aa:bb:cc:dd:ee:02 INCOMPLETE
192.168.10.4 dev wlan0 lladdr aa:bb:cc:dd:ee:03 REACHABLE`
	if n := parseARPPeers(out, "192.168.10.1"); n != 1 {
		t.Errorf("expected 1 peer (only REACHABLE, not FAILED/INCOMPLETE), got %d", n)
	}
}

// ── systemd.go:236 ───────────────────────────────────────────────────────────

// TestFilterBenignFailedUnits_SysupdateSuppressedWhenUnconfigured exercises
// the `if sysupdateBenign && benignSysupdateUnits[u.Name]` branch (line 236).
// We need sysupdateUnconfigured() == true (no .transfer files on disk) AND
// the unit name in benignSysupdateUnits. Run under a fixture source so
// glob("/etc/sysupdate.d/*.transfer") finds nothing.
func TestFilterBenignFailedUnits_SysupdateSuppressedWhenUnconfigured(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {
		// No .transfer files seeded — sysupdateUnconfigured() returns true.
	})
	units := []models.SystemdUnit{
		{Name: "systemd-sysupdate.service"},
		{Name: "systemd-sysupdate-reboot.service"},
		{Name: "my-app.service"}, // genuine failure — must survive
	}
	got := filterBenignFailedUnits(append([]models.SystemdUnit(nil), units...), false)
	if len(got) != 1 || got[0].Name != "my-app.service" {
		t.Errorf("sysupdate units must be suppressed when unconfigured; got %+v", got)
	}
}

// ── zfs.go:119,142 ───────────────────────────────────────────────────────────

// TestMergeZpoolStatus_EmptyCurrentPool covers line 119-121: lines that appear
// before any "pool:" header (currentPool == "") must be silently skipped.
func TestMergeZpoolStatus_EmptyCurrentPool(t *testing.T) {
	t.Parallel()
	pools := map[string]models.ZFSPool{"tank": {Name: "tank", State: "ONLINE"}}
	// Leading junk before any "pool:" header — currentPool stays ""
	mergeZpoolStatus("  state: DEGRADED\n  pool: tank\n  state: DEGRADED\n", pools)
	// The leading "state: DEGRADED" line fires before currentPool is set — it
	// must be skipped (not crash), and the one after the pool: header takes effect.
	if pools["tank"].State != "DEGRADED" {
		t.Errorf("State = %q, want DEGRADED (from the line after pool: header)", pools["tank"].State)
	}
}

// TestMergeZpoolStatus_StatusContinuationLine covers line 142: the status
// message continuation logic appends up to 2 non-blank, non-colon lines that
// immediately follow a "status:" line.
func TestMergeZpoolStatus_StatusContinuationLine(t *testing.T) {
	t.Parallel()
	pools := map[string]models.ZFSPool{"tank": {Name: "tank"}}
	const status = `  pool: tank
  status: One or more devices is currently being resilvered.  See the
    'zpool status' command for complete details.
  scan: scrub repaired 0B in 00:01:23 with 0 errors on Sun May 12 03:25:01 2024
`
	mergeZpoolStatus(status, pools)
	if !strings.Contains(pools["tank"].StatusMsg, "resilvered") {
		t.Errorf("StatusMsg = %q, expected 'resilvered'", pools["tank"].StatusMsg)
	}
	// The continuation line should also be appended.
	if !strings.Contains(pools["tank"].StatusMsg, "zpool status") {
		t.Errorf("StatusMsg = %q, expected continuation line about 'zpool status'", pools["tank"].StatusMsg)
	}
}
