package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FailedLoginsUnreadable/PAMFailuresUnreadable "couldn't read → silent OK"
// closure: neither journald nor the auth-log file could be read at all, so
// FailedLogins/PAMModuleFailures silently read zero — indistinguishable from a
// genuinely clean host unless surfaced explicitly (found during the pve01
// root-vs-non-root validation pass on #744, PAM module-failure detection).

func TestFailedLoginsUnreadableIsInfo(t *testing.T) {
	if got := checkSecurity(models.SecurityInfo{FailedLoginsUnreadable: true}); !hasInsightMsg(got, "INFO", "SSH auth log not readable") {
		t.Errorf("unreadable SSH auth log must INFO, got %+v", got)
	}
	if got := checkSecurity(models.SecurityInfo{}); hasInsightMsg(got, "INFO", "SSH auth log not readable") {
		t.Errorf("readable auth log must not emit the INFO, got %+v", got)
	}
}

func TestPAMFailuresUnreadableIsInfo(t *testing.T) {
	if got := checkSecurity(models.SecurityInfo{PAMFailuresUnreadable: true}); !hasInsightMsg(got, "INFO", "PAM auth log not readable") {
		t.Errorf("unreadable PAM auth log must INFO, got %+v", got)
	}
	if got := checkSecurity(models.SecurityInfo{}); hasInsightMsg(got, "INFO", "PAM auth log not readable") {
		t.Errorf("readable PAM auth log must not emit the INFO, got %+v", got)
	}
}
