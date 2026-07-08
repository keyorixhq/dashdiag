//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestCronCollectorIdentity(t *testing.T) {
	c := NewCronCollector()
	if c == nil {
		t.Fatal("NewCronCollector returned nil")
	}
	if c.Name() != "Cron" {
		t.Errorf("Name() = %q, want Cron", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

func TestDetectCronDaemon_SystemdActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "crond"}, "active\n", 0)
		b.PutStat("/usr/sbin/anacron", source.FileMeta{})
	})
	info := &models.CronInfo{}
	detectCronDaemon(context.Background(), info)
	if !info.DaemonActive || info.DaemonName != "crond" {
		t.Errorf("DaemonActive=%v DaemonName=%q, want true/crond", info.DaemonActive, info.DaemonName)
	}
	if !info.AnacronPresent {
		t.Error("AnacronPresent = false, want true")
	}
}

func TestDetectCronDaemon_NoDaemonNoAnacron(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "crond"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "cron"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "fcron"}, "inactive\n", 3)
		b.PutDir("/proc", []string{})
	})
	info := &models.CronInfo{}
	detectCronDaemon(context.Background(), info)
	if info.DaemonActive || info.AnacronPresent {
		t.Errorf("DaemonActive=%v AnacronPresent=%v, want both false", info.DaemonActive, info.AnacronPresent)
	}
}

func TestDetectCronDaemon_AnacronBinFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "crond"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "cron"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "fcron"}, "inactive\n", 3)
		b.PutDir("/proc", []string{})
		// /usr/sbin/anacron unseeded (absent); /usr/bin/anacron present.
		b.PutStat("/usr/bin/anacron", source.FileMeta{})
	})
	info := &models.CronInfo{}
	detectCronDaemon(context.Background(), info)
	if !info.AnacronPresent {
		t.Error("AnacronPresent = false, want true (fallback to /usr/bin/anacron)")
	}
}

func TestAnyProcessNamed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"320"})
		b.PutDir("/proc/320", []string{"comm"})
		b.PutFile("/proc/320/comm", []byte("crond\n"))
	})
	if !anyProcessNamed("crond", "cron", "fcron") {
		t.Error("anyProcessNamed() = false, want true")
	}
}

func TestAnyProcessNamed_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
	})
	if anyProcessNamed("crond", "cron", "fcron") {
		t.Error("anyProcessNamed() = true, want false")
	}
}

func TestScanCrontabQuality(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/cron.d", []string{"myjob"})
		b.PutFile("/etc/cron.d/myjob", []byte("30 3 * * 0 root foo --run\n"))
		b.PutDir("/etc/cron.daily", []string{})
		b.PutDir("/etc/cron.weekly", []string{})
		b.PutDir("/etc/cron.monthly", []string{})
		b.PutDir("/etc/cron.hourly", []string{})
		b.PutFile("/var/spool/cron/crontabs/root", []byte("MAILTO=root\nPATH=/bin\n0 2 * * * true\n"))
		b.PutDir("/var/spool/cron/crontabs", []string{"root", "alice"})
		b.PutFile("/var/spool/cron/crontabs/alice", []byte("0 4 * * * relcmd --run\n"))
	})
	issues := scanCrontabQuality()
	if len(issues) != 2 {
		t.Fatalf("issues = %+v, want 2 (myjob + alice; root crontab is clean)", issues)
	}
	sources := map[string]bool{}
	for _, i := range issues {
		sources[i.Source] = true
	}
	if !sources["/etc/cron.d/myjob"] || !sources["user:alice"] {
		t.Errorf("sources = %v, want /etc/cron.d/myjob and user:alice", sources)
	}
}

func TestScanCrontabQuality_NoDirsPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if issues := scanCrontabQuality(); issues != nil {
		t.Errorf("issues = %+v, want nil when no cron dirs/crontabs exist", issues)
	}
}

func TestScanCronFailures_JournalAndDedup(t *testing.T) {
	recentTS := time.Now().Format("Jan 2 15:04:05")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-u", "crond", "-u", "cron", "--since", "24 hours ago", "--no-pager", "-q", "--output=short"},
			recentTS+" host CRON[123]: (root) CMD (/usr/bin/backup.sh) failed\n"+
				recentTS+" host CRON[123]: (root) CMD (/usr/bin/backup.sh) failed\n", 0)
	})
	failures, ok := scanCronFailures(context.Background())
	if !ok {
		t.Fatal("scanOK = false, want true (journalctl succeeded)")
	}
	if len(failures) != 1 {
		t.Fatalf("failures = %+v, want 1 (deduplicated by job)", failures)
	}
	if failures[0].Job != "/usr/bin/backup.sh" {
		t.Errorf("Job = %q, want /usr/bin/backup.sh", failures[0].Job)
	}
}

func TestScanCronFailures_JournalFailsFallsBackToSyslog(t *testing.T) {
	recentTS := time.Now().Format("Jan 2 15:04:05")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-u", "crond", "-u", "cron", "--since", "24 hours ago", "--no-pager", "-q", "--output=short"})
		b.PutFile("/var/log/cron", []byte(recentTS+" host crond[1]: (root) CMD (/usr/bin/x) failed\n"))
	})
	failures, ok := scanCronFailures(context.Background())
	if !ok {
		t.Fatal("scanOK = false, want true (syslog file readable)")
	}
	if len(failures) != 1 || failures[0].Job != "/usr/bin/x" {
		t.Errorf("failures = %+v, want one /usr/bin/x failure", failures)
	}
}

func TestScanCronFailures_NeitherSourceAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-u", "crond", "-u", "cron", "--since", "24 hours ago", "--no-pager", "-q", "--output=short"})
	})
	failures, ok := scanCronFailures(context.Background())
	if ok || failures != nil {
		t.Errorf("scanCronFailures() = (%v,%v), want (nil,false)", failures, ok)
	}
}

func TestDeduplicateCronFailures(t *testing.T) {
	in := []models.CronFailure{
		{Job: "a", Message: "first"},
		{Job: "a", Message: "second"},
		{Job: "b", Message: "third"},
	}
	out := deduplicateCronFailures(in)
	if len(out) != 2 || out[0].Job != "a" || out[0].Message != "first" || out[1].Job != "b" {
		t.Errorf("deduplicateCronFailures() = %+v, want [a/first, b/third]", out)
	}
}

func TestDeduplicateCronFailures_Empty(t *testing.T) {
	if out := deduplicateCronFailures(nil); out != nil {
		t.Errorf("deduplicateCronFailures(nil) = %v, want nil", out)
	}
}

func TestCheckAnacronStaleness_OnScheduleAndOverdue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/spool/anacron/cron.daily", []byte(time.Now().Format("20060102")+"\n"))
		b.PutFile("/var/spool/anacron/cron.weekly", []byte(time.Now().Add(-20*24*time.Hour).Format("20060102")+"\n")) // overdue (>9d)
		// cron.monthly intentionally unseeded -> LastRunH = -1
	})
	jobs := checkAnacronStaleness()
	if len(jobs) != 3 {
		t.Fatalf("jobs = %+v, want 3 entries (daily/weekly/monthly)", jobs)
	}
	byName := map[string]models.AnacronJob{}
	for _, j := range jobs {
		byName[j.Name] = j
	}
	if byName["daily"].OverdueH != 0 {
		t.Errorf("daily.OverdueH = %d, want 0 (ran today)", byName["daily"].OverdueH)
	}
	if byName["weekly"].OverdueH == 0 {
		t.Error("weekly.OverdueH = 0, want >0 (20 days > 9-day threshold)")
	}
	if byName["monthly"].LastRunH != -1 {
		t.Errorf("monthly.LastRunH = %d, want -1 (file unreadable)", byName["monthly"].LastRunH)
	}
}

func TestCheckAnacronStaleness_UnparseableTimestamp(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/spool/anacron/cron.daily", []byte("not-a-date\n"))
	})
	jobs := checkAnacronStaleness()
	for _, j := range jobs {
		if j.Name == "daily" && j.LastRunH != -1 {
			t.Errorf("daily.LastRunH = %d, want -1 for an unparseable timestamp", j.LastRunH)
		}
	}
}

func TestCountSystemdTimers(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-timers", "--no-legend", "--no-pager"},
			"Mon 2026-07-08 00:00:00 UTC  1h  logrotate.timer\nMon 2026-07-08 01:00:00 UTC  2h  fstrim.timer\n", 0)
	})
	if n := countSystemdTimers(context.Background()); n != 2 {
		t.Errorf("countSystemdTimers() = %d, want 2", n)
	}
}

func TestCountSystemdTimers_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"list-timers", "--no-legend", "--no-pager"})
	})
	if n := countSystemdTimers(context.Background()); n != 0 {
		t.Errorf("countSystemdTimers() = %d, want 0", n)
	}
}

// TestCronCollector_Collect_NoDaemonFallsBackToSystemdTimers drives the entire
// Collect() pipeline through the "no cron daemon" branch, verifying
// SystemdTimers is populated instead (and AnacronJobs is skipped, since
// AnacronPresent is false).
func TestCronCollector_Collect_NoDaemonFallsBackToSystemdTimers(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "crond"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "cron"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "fcron"}, "inactive\n", 3)
		b.PutDir("/proc", []string{})
		b.PutCmd("journalctl", []string{"-u", "crond", "-u", "cron", "--since", "24 hours ago", "--no-pager", "-q", "--output=short"}, "", 0)
		b.PutCmd("systemctl", []string{"list-timers", "--no-legend", "--no-pager"}, "line1\nline2\nline3\n", 0)
	})

	c := NewCronCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CronInfo)
	if info.DaemonActive {
		t.Error("DaemonActive = true, want false")
	}
	if info.SystemdTimers != 3 {
		t.Errorf("SystemdTimers = %d, want 3", info.SystemdTimers)
	}
	if info.AnacronJobs != nil {
		t.Errorf("AnacronJobs = %+v, want nil (AnacronPresent is false)", info.AnacronJobs)
	}
	if !info.FailureScanOK {
		t.Error("FailureScanOK = false, want true (journalctl succeeded)")
	}
}

// TestCronCollector_Collect_DaemonActiveRunsAnacron drives Collect() through the
// daemon-active branch: SystemdTimers must NOT be probed, and AnacronJobs must
// be populated since AnacronPresent is true.
func TestCronCollector_Collect_DaemonActiveRunsAnacron(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "crond"}, "active\n", 0)
		b.PutStat("/usr/sbin/anacron", source.FileMeta{})
		b.PutCmd("journalctl", []string{"-u", "crond", "-u", "cron", "--since", "24 hours ago", "--no-pager", "-q", "--output=short"}, "", 0)
		b.PutFile("/var/spool/anacron/cron.daily", []byte(time.Now().Format("20060102")+"\n"))
		b.PutFile("/var/spool/anacron/cron.weekly", []byte(time.Now().Format("20060102")+"\n"))
		b.PutFile("/var/spool/anacron/cron.monthly", []byte(time.Now().Format("20060102")+"\n"))
	})

	c := NewCronCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CronInfo)
	if !info.DaemonActive || info.DaemonName != "crond" {
		t.Errorf("DaemonActive=%v DaemonName=%q, want true/crond", info.DaemonActive, info.DaemonName)
	}
	if info.SystemdTimers != 0 {
		t.Errorf("SystemdTimers = %d, want 0 (must not be probed when a daemon is active)", info.SystemdTimers)
	}
	if len(info.AnacronJobs) != 3 {
		t.Errorf("AnacronJobs = %+v, want 3 entries", info.AnacronJobs)
	}
}
