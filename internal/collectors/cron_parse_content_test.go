//go:build linux

package collectors

import (
	"fmt"
	"testing"
	"time"
)

// TestParseCronLogLine guards the syslog cron-line timestamp/job extraction —
// a pure function, no I/O.
func TestParseCronLogLine(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	line := fmt.Sprintf("%s hostname crond[123]: (root) CMD (/usr/local/bin/backup.sh)", recent.Format("Jan 2 15:04:05"))
	ts, job := parseCronLogLine(line)
	if job != "/usr/local/bin/backup.sh" {
		t.Errorf("job should be extracted from the CMD (...) pattern, got %q", job)
	}
	if ts.IsZero() {
		t.Error("a well-formed syslog timestamp should parse")
	}

	fallback := "May 19 10:00:01 hostname somejob without cmd pattern here"
	_, job2 := parseCronLogLine(fallback)
	if job2 != "without cmd pattern here" {
		t.Errorf("without a CMD(...) pattern, the tail of the message should be used as the job, got %q", job2)
	}

	if ts3, job3 := parseCronLogLine("too short"); !ts3.IsZero() || job3 != "" {
		t.Errorf("a line with too few fields should return zero values, got (%v, %q)", ts3, job3)
	}
}

// TestParseCronLogFailures guards the traditional /var/log/cron scan: only
// failures within the last 24h are kept, and non-failure lines are ignored.
func TestParseCronLogFailures(t *testing.T) {
	recent := time.Now().Add(-2 * time.Hour)
	old := time.Now().Add(-48 * time.Hour)
	content := fmt.Sprintf(
		"%s host crond[1]: (root) CMD (backup.sh) exit status 1 FAILED\n"+
			"%s host crond[1]: (root) CMD (ok.sh)\n"+ // no failure keyword
			"%s host crond[1]: (root) CMD (stale.sh) exit status 1 FAILED\n", // >24h old
		recent.Format("Jan 2 15:04:05"), recent.Format("Jan 2 15:04:05"), old.Format("Jan 2 15:04:05"),
	)
	failures := parseCronLogFailures(content)
	if len(failures) != 1 {
		t.Fatalf("expected exactly 1 recent failure, got %d: %+v", len(failures), failures)
	}
	if failures[0].Job != "backup.sh" {
		t.Errorf("the recent failure's job should be backup.sh, got %q", failures[0].Job)
	}
}

// TestParseCronJournalFailures guards the journalctl-output scan: FAILED/
// error/exit-status lines are kept, but daemon start/stop noise is filtered
// even though it might mention "stopping".
func TestParseCronJournalFailures(t *testing.T) {
	recent := time.Now().Add(-30 * time.Minute)
	out := fmt.Sprintf(
		"%s host cron[1]: Stopping periodic command scheduler...\n"+ // daemon noise, skip
			"%s host CRON[456]: (root) CMD (/etc/cron.daily/logrotate) exit status 1\n",
		recent.Format("Jan 2 15:04:05"), recent.Format("Jan 2 15:04:05"),
	)
	failures := parseCronJournalFailures(out)
	if len(failures) != 1 {
		t.Fatalf("expected exactly 1 real failure (daemon-noise line filtered), got %d: %+v", len(failures), failures)
	}
	if failures[0].Job != "/etc/cron.daily/logrotate" {
		t.Errorf("the failure's job should be logrotate, got %q", failures[0].Job)
	}
}

// TestParseCronJournalFailures_StartStopMentionsFailureKeyword guards the
// "started/stopping" skip when the daemon-lifecycle line ALSO happens to
// contain a failure keyword (e.g. "failed to start") — this line clears the
// first failed/error/exit-status gate, so the started/stopping skip must be
// the one that actually excludes it.
func TestParseCronJournalFailures_StartStopMentionsFailureKeyword(t *testing.T) {
	recent := time.Now().Add(-30 * time.Minute)
	out := fmt.Sprintf("%s host cron[1]: cron.service: Failed to start, stopping unit\n",
		recent.Format("Jan 2 15:04:05"))
	failures := parseCronJournalFailures(out)
	if len(failures) != 0 {
		t.Errorf("a start/stop lifecycle line must be skipped even if it mentions 'failed', got %+v", failures)
	}
}

// TestParseCronLogFailures_NoJobExtracted guards the job=="" skip: a line
// that passes the failure-keyword and recency checks but has no extractable
// job (parseCronLogLine's fallback needs >5 fields) must not be reported.
func TestParseCronLogFailures_NoJobExtracted(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour)
	content := recent.Format("Jan 2 15:04:05") + " failed\n" // <6 fields total
	if failures := parseCronLogFailures(content); len(failures) != 0 {
		t.Errorf("a line with no extractable job must be skipped, got %+v", failures)
	}
}
