package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// MAC-denial / shadow "couldn't read → silent OK" closures (FALSE_OK_SWEEP #24/#25/#26).

func TestSELinuxDenialsUnverified(t *testing.T) {
	// enforcing + denials=-1 (source unreadable) → INFO "could NOT be verified".
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: -1}
	if got := checkSELinuxDenials(mac, defaultThresh); !hasInsightMsg(got, "INFO", "could NOT be verified") {
		t.Errorf("unverified SELinux denials must INFO, got %+v", got)
	}
}

func TestAppArmorDenialsUnverified(t *testing.T) {
	// enforcing + denials=-1 (log unreadable) → INFO.
	mac := models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce", AppArmorDenials: -1}
	if got := checkKernelSecurity(mac, defaultThresh); !hasInsightMsg(got, "INFO", "denial log could NOT be read") {
		t.Errorf("unverified AppArmor denials must INFO, got %+v", got)
	}
}

func TestShadowUnreadableIsInfo(t *testing.T) {
	if got := checkSecurity(models.SecurityInfo{ShadowUnreadable: true}); !hasInsightMsg(got, "INFO", "/etc/shadow not readable") {
		t.Errorf("unreadable /etc/shadow must INFO, got %+v", got)
	}
	if got := checkSecurity(models.SecurityInfo{}); hasInsightMsg(got, "INFO", "/etc/shadow not readable") {
		t.Errorf("readable shadow must not emit the INFO, got %+v", got)
	}
}
