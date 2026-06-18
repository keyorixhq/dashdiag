package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// cron/logs "scan failed → silent OK" closures (FALSE_OK_SWEEP #28/#29).

func TestCronFailureScanUnreadable(t *testing.T) {
	// Active daemon but the failure history could not be read → INFO, not silent clean.
	if got := checkCron(models.CronInfo{DaemonActive: true, FailureScanOK: false}); !hasInsightMsg(got, "INFO", "failure history not readable") {
		t.Errorf("unreadable cron failure scan must INFO, got %+v", got)
	}
	// Scan ran, no failures → clean.
	if got := checkCron(models.CronInfo{DaemonActive: true, FailureScanOK: true}); len(got) != 0 {
		t.Errorf("verified, no failures must be clean, got %+v", got)
	}
}

func TestJournalErrorCountUnverified(t *testing.T) {
	if got := checkJournalActivity(models.LogsInfo{ErrorCountUnverified: true}); !hasInsightMsg(got, "INFO", "could not read journal error counts") {
		t.Errorf("unverified error count must INFO, got %+v", got)
	}
	// Verified zero errors → clean.
	if got := checkJournalActivity(models.LogsInfo{ErrorCount: 0}); len(got) != 0 {
		t.Errorf("verified 0 errors must be clean, got %+v", got)
	}
}
