//go:build linux

package collectors

import (
	"fmt"
	"os"
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
