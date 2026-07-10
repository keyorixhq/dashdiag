//go:build linux

package collectors

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── parseProcNetTCP ──────────────────────────────────────────────────────────

// TestParseProcNetTCP_MalformedLinesSkipped covers the defensive branches
// parseListeningPorts's happy-path test never exercises: a short field count,
// a non-listening state (st != 0A), a local_address with no colon, and a
// non-hex port token — none of these must panic or add a bogus port.
func TestParseProcNetTCP_MalformedLinesSkipped(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: TOOFEW\n"+ // < 10 fields
				"   1: 00000000:1F90 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0\n"+ // st=06, not listening
				"   2: BADADDR 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0\n"+ // no colon in local_address
				"   3: 00000000:ZZZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1 0000000000000000 100 0 0 10 0\n")) // non-hex port
	})
	info := &models.SecurityInfo{}
	parseProcNetTCP("/proc/net/tcp", info)
	if len(info.ListeningPorts) != 0 {
		t.Errorf("expected 0 listening ports from malformed/non-listening lines, got %+v", info.ListeningPorts)
	}
}

// TestParseProcNetTCP_DedupesSamePort covers the "seen" dedup branch: two
// listening rows for the same port must produce only one ListeningPorts entry.
func TestParseProcNetTCP_DedupesSamePort(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0\n"+
				"   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0\n"))
	})
	info := &models.SecurityInfo{}
	parseProcNetTCP("/proc/net/tcp", info)
	if len(info.ListeningPorts) != 1 {
		t.Errorf("expected 1 deduped listening port, got %+v", info.ListeningPorts)
	}
}

// TestParseProcNetTCP_SystemdSocketActivationResolvesWellKnownName covers the
// "systemd"/"" process-name resolution branch via wellKnownPortName.
func TestParseProcNetTCP_SystemdSocketActivationResolvesWellKnownName(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/proc/100/fd/3": "socket:[999]",
	}, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
				"   0: 00000000:19B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0\n")) // 0x19B3 = 6579
		b.PutGlob("/proc/[0-9]*/fd", []string{"/proc/100/fd"})
		b.PutFile("/proc/100/comm", []byte("systemd\n"))
		b.PutDir("/proc/100/fd", []string{"3"})
	})
	info := &models.SecurityInfo{}
	parseProcNetTCP("/proc/net/tcp", info)
	if len(info.ListeningPorts) != 1 {
		t.Fatalf("expected 1 listening port, got %+v", info.ListeningPorts)
	}
	if info.ListeningPorts[0].Process != "systemd" {
		// wellKnownPortName has no entry for this arbitrary port, so it stays "systemd" —
		// still proves the branch runs without panicking / mis-resolving.
		t.Errorf("Process = %q, want systemd (no well-known mapping for this port)", info.ListeningPorts[0].Process)
	}
}

// ── parseSELinuxDenials ──────────────────────────────────────────────────────

// TestParseSELinuxDenials_EnforcingWithDenials_PopulatesAVCGroups covers the
// "os.Getuid()==0 && n>0" branch: when running as root (true under the Docker
// test image) with at least one in-window denial, parseSELinuxDenials must
// also populate the structured SELinuxAVCGroups, not just the raw count.
func TestParseSELinuxDenials_EnforcingWithDenials_PopulatesAVCGroups(t *testing.T) {
	swapGetuid(t, 0) // structured AVC grouping is root-gated; CI runs non-root
	recent := time.Now().Add(-time.Minute).Unix()
	line := fmt.Sprintf(`type=AVC msg=audit(%d.123:1): avc:  denied  { write } for  pid=1 comm="httpd" name="/x" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0`, recent)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/fs/selinux/enforce", []byte("1\n"))
		b.PutFile("/var/log/audit/audit.log", []byte(line+"\n"))
		b.PutCmdNotFound("getsebool", nil)
	})
	info := &models.SecurityInfo{}
	parseSELinuxDenials(context.Background(), info)
	if info.SELinuxDenials != 1 {
		t.Fatalf("expected SELinuxDenials=1, got %d", info.SELinuxDenials)
	}
	if len(info.SELinuxAVCGroups) != 1 {
		t.Errorf("expected 1 structured AVC group when running as root with denials>0, got %+v", info.SELinuxAVCGroups)
	}
}

// ── parsePortRangeToken ──────────────────────────────────────────────────────

func TestParsePortRangeToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		tok    string
		wantLo int
		wantHi int
		wantOK bool
	}{
		{"single port", "22", 22, 22, true},
		{"range", "8008-8010", 8008, 8010, true},
		{"whitespace padded", "  443  ", 443, 443, true},
		{"malformed range low", "abc-100", 0, 0, false},
		{"malformed range high", "100-abc", 0, 0, false},
		{"non-numeric single", "abc", 0, 0, false},
		{"empty token", "", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lo, hi, ok := parsePortRangeToken(tt.tok)
			if lo != tt.wantLo || hi != tt.wantHi || ok != tt.wantOK {
				t.Errorf("parsePortRangeToken(%q) = (%d,%d,%v), want (%d,%d,%v)",
					tt.tok, lo, hi, ok, tt.wantLo, tt.wantHi, tt.wantOK)
			}
		})
	}
}

// ── matchpathconContext / lsZContext ────────────────────────────────────────

func TestMatchpathconContext(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("matchpathcon", []string{"-n", "/data/app"}, "system_u:object_r:httpd_sys_content_t:s0\n", 0)
	})
	if got := matchpathconContext("/data/app"); got != "system_u:object_r:httpd_sys_content_t:s0" {
		t.Errorf("matchpathconContext() = %q", got)
	}
}

func TestMatchpathconContext_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("matchpathcon", []string{"-n", "/data/app"})
	})
	if got := matchpathconContext("/data/app"); got != "" {
		t.Errorf("matchpathconContext() = %q, want empty when matchpathcon is unavailable", got)
	}
}

func TestLsZContext(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ls", []string{"-dZ", "/data/app"}, "unconfined_u:object_r:admin_home_t:s0 /data/app\n", 0)
	})
	if got := lsZContext("/data/app"); got != "unconfined_u:object_r:admin_home_t:s0" {
		t.Errorf("lsZContext() = %q", got)
	}
}

func TestLsZContext_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ls", []string{"-dZ", "/data/app"})
	})
	if got := lsZContext("/data/app"); got != "" {
		t.Errorf("lsZContext() = %q, want empty when ls is unavailable", got)
	}
}

func TestLsZContext_EmptyOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ls", []string{"-dZ", "/data/app"}, "", 0)
	})
	if got := lsZContext("/data/app"); got != "" {
		t.Errorf("lsZContext() = %q, want empty for blank stdout", got)
	}
}

// ── collectSemanageFcontextRules ─────────────────────────────────────────────

func TestCollectSemanageFcontextRules(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("semanage", []string{"fcontext", "-C", "-l"},
			"SELinux fcontext                                  type               Context\n\n"+
				"/data/app(/.*)?                                    all files          system_u:object_r:httpd_sys_content_t:s0\n", 0)
	})
	rules := collectSemanageFcontextRules(context.Background())
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d: %+v", len(rules), rules)
	}
	if !rules[0].pattern.MatchString("/data/app/x") {
		t.Errorf("expected rule to match /data/app/x")
	}
}

func TestCollectSemanageFcontextRules_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("semanage", []string{"fcontext", "-C", "-l"})
	})
	if got := collectSemanageFcontextRules(context.Background()); got != nil {
		t.Errorf("expected nil when semanage is unavailable, got %+v", got)
	}
}

// ── pamFailuresFromCounts ─────────────────────────────────────────────────────

// TestPamFailuresFromCounts covers the sort order: count descending, then
// service ascending, then user ascending as tiebreakers — map iteration order
// must never leak into the result (replay-hermeticity concern, same rationale
// as buildSELinuxAVCGroups's own tiebreak sort).
func TestPamFailuresFromCounts(t *testing.T) {
	t.Parallel()
	counts := map[pamKey]int{
		{service: "sudo", user: "alice"}:  2,
		{service: "su", user: "bob"}:      5,
		{service: "cron", user: "alice"}:  2,
		{service: "sudo", user: "alice2"}: 2,
	}
	got := pamFailuresFromCounts(counts)
	want := []models.PAMFailure{
		{Service: "su", User: "bob", Count: 5},
		{Service: "cron", User: "alice", Count: 2},
		{Service: "sudo", User: "alice", Count: 2},
		{Service: "sudo", User: "alice2", Count: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pamFailuresFromCounts() = %+v, want %+v", got, want)
	}
}

func TestPamFailuresFromCounts_Empty(t *testing.T) {
	t.Parallel()
	got := pamFailuresFromCounts(map[pamKey]int{})
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %+v", got)
	}
}

// ── parseUSBGuard ─────────────────────────────────────────────────────────────

func TestParseUSBGuard_ActiveViaCgroup(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/usbguard", source.FileMeta{})
		b.PutStat("/sys/fs/cgroup/system.slice/usbguard.service", source.FileMeta{})
	})
	info := &models.SecurityInfo{}
	parseUSBGuard(info)
	if !info.USBGuardActive {
		t.Error("expected USBGuardActive=true when binary and cgroup unit both exist")
	}
}

func TestParseUSBGuard_ActiveViaPidFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/run/usbguard/usbguard-daemon.pid", source.FileMeta{})
	})
	info := &models.SecurityInfo{}
	parseUSBGuard(info)
	if !info.USBGuardActive {
		t.Error("expected USBGuardActive=true via the pid-file fallback")
	}
}

func TestParseUSBGuard_BinaryPresentButNotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/usbguard", source.FileMeta{})
	})
	info := &models.SecurityInfo{}
	parseUSBGuard(info)
	if info.USBGuardActive {
		t.Error("expected USBGuardActive=false when the binary exists but no cgroup unit or pid file does")
	}
}

func TestParseUSBGuard_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.SecurityInfo{}
	parseUSBGuard(info)
	if info.USBGuardActive {
		t.Error("expected USBGuardActive=false when usbguard is entirely absent")
	}
}

// ── parseSUSEExpiry ──────────────────────────────────────────────────────────

func TestParseSUSEExpiry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		expiresAt   string
		wantOK      bool
		wantExpired bool // want days == 0 because it's in the past
	}{
		{"empty string", "", false, false},
		{"unparseable garbage", "not-a-date", false, false},
		{"far future", "2099-01-01 00:00:00 UTC", true, false},
		{"far past (expired)", "2000-01-01 00:00:00 UTC", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			days, ok := parseSUSEExpiry(tt.expiresAt)
			if ok != tt.wantOK {
				t.Fatalf("parseSUSEExpiry(%q) ok = %v, want %v", tt.expiresAt, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if tt.wantExpired && days != 0 {
				t.Errorf("parseSUSEExpiry(%q) days = %d, want 0 (expired, clamped)", tt.expiresAt, days)
			}
			if !tt.wantExpired && days <= 0 {
				t.Errorf("parseSUSEExpiry(%q) days = %d, want > 0 (future)", tt.expiresAt, days)
			}
		})
	}
}

// ── suggestSELinuxFix ─────────────────────────────────────────────────────────

// TestSuggestSELinuxFix_KnownBooleanExists covers the first (highest-priority)
// branch: a known (stype,ttype,tclass) pattern whose boolean actually exists on
// this system (getsebool succeeds) must return the boolean fix, not fall through
// to the port/fcontext/audit2allow branches below it.
func TestSuggestSELinuxFix_KnownBooleanExists(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("getsebool", []string{"httpd_can_network_connect"}, "httpd_can_network_connect --> off\n", 0)
	})
	boolName, fixCmd := suggestSELinuxFix(context.Background(), "container_t", "httpd_t", "process", nil)
	if boolName != "httpd_can_network_connect" {
		t.Errorf("boolName = %q, want httpd_can_network_connect", boolName)
	}
	if fixCmd != "setsebool -P httpd_can_network_connect on" {
		t.Errorf("fixCmd = %q", fixCmd)
	}
}

// TestSuggestSELinuxFix_KnownBooleanPatternButAbsent covers the "pattern
// matches, but the boolean doesn't exist on this build" fallthrough: the
// matched rule must be skipped and (in this case, tclass=port,tcp_socket)
// fall to the port-labeling branch, not incorrectly return the boolean.
func TestSuggestSELinuxFix_KnownBooleanPatternButAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("getsebool", []string{"selinuxuser_tcp_server"})
	})
	boolName, fixCmd := suggestSELinuxFix(context.Background(), "sshd_t", "unreserved_port_t", "tcp_socket", nil)
	if boolName != "" {
		t.Errorf("boolName = %q, want empty (boolean doesn't exist)", boolName)
	}
	want := "semanage port -a -t sshd_t_port_t -p tcp <PORT>"
	if fixCmd != want {
		t.Errorf("fixCmd = %q, want %q", fixCmd, want)
	}
}

// TestSuggestSELinuxFix_FileContextWriteOrCreate covers the file/dir-class
// branch: a write/create/open/read perm on a file-class denial must return a
// semanage fcontext + restorecon suggestion.
func TestSuggestSELinuxFix_FileContextWriteOrCreate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	_, fixCmd := suggestSELinuxFix(context.Background(), "unconfined_t", "admin_home_t", "file", []string{"write"})
	want := "semanage fcontext -a -t admin_home_t_t '/path/to/file'  && restorecon -v /path/to/file"
	if fixCmd != want {
		t.Errorf("fixCmd = %q, want %q", fixCmd, want)
	}
}

// TestSuggestSELinuxFix_FileClassNoMatchingPermFallsToAudit2Allow covers the
// case where tclass is "file" but none of the tracked perms (read/write/open/
// create) are present — must skip the fcontext branch and fall to audit2allow.
func TestSuggestSELinuxFix_FileClassNoMatchingPermFallsToAudit2Allow(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	boolName, fixCmd := suggestSELinuxFix(context.Background(), "unconfined_t", "admin_home_t", "file", []string{"getattr"})
	if boolName != "" {
		t.Errorf("boolName = %q, want empty", boolName)
	}
	want := "ausearch -m avc -ts recent | audit2allow -M my_unconfined_t && semodule -i my_unconfined_t.pp"
	if fixCmd != want {
		t.Errorf("fixCmd = %q, want %q", fixCmd, want)
	}
}

// TestSuggestSELinuxFix_UnknownFallsToAudit2Allow covers the final fallback:
// an entirely unrecognized (stype,ttype,tclass) with no perms.
func TestSuggestSELinuxFix_UnknownFallsToAudit2Allow(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	boolName, fixCmd := suggestSELinuxFix(context.Background(), "custom_t", "custom_target_t", "chr_file", nil)
	if boolName != "" {
		t.Errorf("boolName = %q, want empty", boolName)
	}
	want := "ausearch -m avc -ts recent | audit2allow -M my_custom_t && semodule -i my_custom_t.pp"
	if fixCmd != want {
		t.Errorf("fixCmd = %q, want %q", fixCmd, want)
	}
}

// TestBuildSELinuxAVCGroups_TcontextAndTclassTiebreak covers the two deeper
// sort tiebreakers buildSELinuxAVCGroups_SortAndCap can't reach (its dummy
// groups all shared the same Tcontext/Tclass): equal Count AND equal Scontext
// must fall through to a Tcontext comparison, and equal Count+Scontext+Tcontext
// must fall through to Tclass.
func TestBuildSELinuxAVCGroups_TcontextAndTclassTiebreak(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("getsebool", nil)
	})
	groups := map[avcGroupKey]*avcGroupData{
		{stype: "same_t", ttype: "zzz_t", tclass: "file"}: {perms: map[string]bool{}, paths: map[string]bool{}, count: 1},
		{stype: "same_t", ttype: "aaa_t", tclass: "dir"}:  {perms: map[string]bool{}, paths: map[string]bool{}, count: 1},
		{stype: "same_t", ttype: "aaa_t", tclass: "bpf"}:  {perms: map[string]bool{}, paths: map[string]bool{}, count: 1},
	}
	result := buildSELinuxAVCGroups(context.Background(), groups)
	if len(result) != 3 {
		t.Fatalf("expected 3 groups, got %d: %+v", len(result), result)
	}
	// Same Scontext throughout -> ordered by Tcontext asc, then Tclass asc.
	if result[0].Tcontext != "aaa_t" || result[0].Tclass != "bpf" {
		t.Errorf("result[0] = %+v, want Tcontext=aaa_t Tclass=bpf (Tcontext tie broken by Tclass)", result[0])
	}
	if result[1].Tcontext != "aaa_t" || result[1].Tclass != "dir" {
		t.Errorf("result[1] = %+v, want Tcontext=aaa_t Tclass=dir", result[1])
	}
	if result[2].Tcontext != "zzz_t" {
		t.Errorf("result[2] = %+v, want Tcontext=zzz_t last", result[2])
	}
}

// ── parseSELinuxExtras ────────────────────────────────────────────────────────

// TestParseSELinuxExtras_FullDeepDiagnosis exercises every branch beyond the
// autorelabel flag already covered in security_linux_collectors_test.go:
// booleans collected (AVCGroups present), the deep-diagnosis gate firing
// (unlabeled ports + context issues), AppArmor denial grouping, PAM locked
// accounts, and PAM module failures — in one pass, since they all share info.
func TestParseSELinuxExtras_FullDeepDiagnosis(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("getsebool", []string{"-a"}, "httpd_can_network_connect --> off\n", 0)
		b.PutCmd("semanage", []string{"port", "-l"}, "SELinux Port Type              Proto  Port Number\n\nssh_port_t                      tcp    22\n", 0)
		b.PutCmd("semanage", []string{"fcontext", "-C", "-l"}, "SELinux fcontext                                  type               Context\n", 0)
		b.PutCmdNotFound("matchpathcon", []string{"-n", "/data/app/config.ini"})
		b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
			"--no-pager", "--since", "24 hours ago", "-o", "short"},
			`type=1400 apparmor="DENIED" operation="open" profile="/usr/sbin/nginx" name="/etc/shadow" pid=1`+"\n", 0)
		b.PutCmd("faillock", []string{"--user", ""}, "alice                            [Locked]\n", 0)
		b.PutFile("/var/log/secure", []byte(""))
	})
	info := &models.SecurityInfo{
		AppArmorMode:   "enforce",
		SELinuxMode:    "enforcing",
		SELinuxDenials: 2,
		SELinuxAVCGroups: []models.SELinuxAVCGroup{
			{Scontext: "httpd_t", Tcontext: "admin_home_t", Tclass: "process"},
		},
		ListeningPorts: []models.PortEntry{{Port: 8080, Protocol: "tcp"}},
	}
	parseSELinuxExtras(context.Background(), info)

	if len(info.SELinuxBooleans) == 0 {
		t.Error("expected SELinuxBooleans to be populated from getsebool -a")
	}
	if len(info.SELinuxUnlabeledPorts) != 1 || info.SELinuxUnlabeledPorts[0].Port != 8080 {
		t.Errorf("expected deep-diagnosis gate to run unlabeled-port scan, got %+v", info.SELinuxUnlabeledPorts)
	}
	if info.AppArmorDenials != 1 || len(info.AppArmorGroups) != 1 {
		t.Errorf("expected 1 AppArmor denial group, got denials=%d groups=%+v", info.AppArmorDenials, info.AppArmorGroups)
	}
	if len(info.PAMLockedAccounts) != 1 || info.PAMLockedAccounts[0] != "alice" {
		t.Errorf("expected PAMLockedAccounts=[alice], got %+v", info.PAMLockedAccounts)
	}
}

// TestParseSELinuxExtras_AppArmorDisabledSkipsGrouping covers the AppArmorMode
// gate: "disabled" (and empty) must skip collectAppArmorDenials entirely.
func TestParseSELinuxExtras_AppArmorDisabledSkipsGrouping(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("faillock", []string{"--user", ""})
		b.PutFile("/var/log/secure", []byte(""))
	})
	info := &models.SecurityInfo{AppArmorMode: "disabled"}
	parseSELinuxExtras(context.Background(), info)
	if info.AppArmorGroups != nil || info.AppArmorDenials != 0 {
		t.Errorf("expected no AppArmor grouping when AppArmorMode=disabled, got denials=%d groups=%+v",
			info.AppArmorDenials, info.AppArmorGroups)
	}
}

// TestParseSELinuxExtras_ShallowGateSkipsDeepDiagnosis covers the negative
// side of selinuxDeepDiagnosisGate: zero denials must skip the unlabeled-port
// and context-issue scans even when AVCGroups is non-empty from a stale prior run.
func TestParseSELinuxExtras_ShallowGateSkipsDeepDiagnosis(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("faillock", []string{"--user", ""})
		b.PutFile("/var/log/secure", []byte(""))
	})
	info := &models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: 0}
	parseSELinuxExtras(context.Background(), info)
	if info.SELinuxUnlabeledPorts != nil || info.SELinuxContextIssues != nil {
		t.Errorf("expected no deep diagnosis with SELinuxDenials=0, got ports=%+v issues=%+v",
			info.SELinuxUnlabeledPorts, info.SELinuxContextIssues)
	}
}

// ── buildSELinuxAVCGroups ─────────────────────────────────────────────────────

// TestBuildSELinuxAVCGroups_SortAndCap covers the count-desc sort, the
// scontext/tcontext/tclass tiebreak for equal counts, and the top-10 cap.
func TestBuildSELinuxAVCGroups_SortAndCap(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("getsebool", nil) // force every suggestSELinuxFix call to the fallback path
	})
	groups := map[avcGroupKey]*avcGroupData{}
	// 12 distinct groups, all with count=1 except one with count=5 (the winner).
	for i := range 12 {
		key := avcGroupKey{stype: string(rune('a' + i)), ttype: "t", tclass: "process"}
		groups[key] = &avcGroupData{perms: map[string]bool{"read": true}, paths: map[string]bool{}, count: 1}
	}
	groups[avcGroupKey{stype: "zzz_winner", ttype: "t", tclass: "process"}] = &avcGroupData{
		perms: map[string]bool{"write": true}, paths: map[string]bool{}, count: 5,
	}

	result := buildSELinuxAVCGroups(context.Background(), groups)
	if len(result) != 10 {
		t.Fatalf("expected result capped at 10, got %d", len(result))
	}
	if result[0].Scontext != "zzz_winner" || result[0].Count != 5 {
		t.Errorf("result[0] = %+v, want the count=5 winner first", result[0])
	}
	// Remaining entries (count=1) must be in ascending Scontext order (tiebreak).
	for i := 1; i < len(result)-1; i++ {
		if result[i].Scontext > result[i+1].Scontext {
			t.Errorf("tiebreak order violated at index %d: %q > %q", i, result[i].Scontext, result[i+1].Scontext)
		}
	}
}
