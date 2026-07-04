package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Gap-fill from the prior net.go coverage pass: printResolverDoT and the
// printResolverAudit dispatcher were missed.

func TestPrintResolverDoT(t *testing.T) {
	off := captureStdout(t, func() { printResolverDoT(&models.ResolverAuditInfo{}) })
	if !strings.Contains(off, "off") {
		t.Errorf("no DoT status should read off, got:\n%s", off)
	}
	opportunistic := captureStdout(t, func() { printResolverDoT(&models.ResolverAuditInfo{DoTStatus: "opportunistic"}) })
	if !strings.Contains(opportunistic, "opportunistic") {
		t.Errorf("opportunistic DoT should say so, got:\n%s", opportunistic)
	}
	named := captureStdout(t, func() { printResolverDoT(&models.ResolverAuditInfo{DoTStatus: "yes"}) })
	if !strings.Contains(named, "yes") {
		t.Errorf("a named DoT status should be shown verbatim, got:\n%s", named)
	}
}

func TestPrintResolverAuditDispatch(t *testing.T) {
	// Active systemd-resolved: DNSSEC/DoT/DNSSEC-test sections render.
	resolved := captureStdout(t, func() {
		printResolverAudit(&models.ResolverAuditInfo{ResolverType: "systemd-resolved", ResolverActive: true, DNSSECConfigured: "yes"})
	})
	if !strings.Contains(resolved, "DNSSEC") {
		t.Errorf("active systemd-resolved should render the DNSSEC section, got:\n%s", resolved)
	}

	// Fallback path (NetworkManager, no resolved): a fallback note plus servers,
	// no DNSSEC/DoT section.
	fallback := captureStdout(t, func() {
		printResolverAudit(&models.ResolverAuditInfo{
			ResolverType: "NetworkManager", FallbackNote: "systemd-resolved not active — using NetworkManager",
			NMNameservers: []string{"1.1.1.1", "8.8.8.8"},
		})
	})
	if !strings.Contains(fallback, "1.1.1.1") {
		t.Errorf("the fallback path should list NM nameservers, got:\n%s", fallback)
	}
	if strings.Contains(fallback, "DNSSEC") {
		t.Errorf("the fallback path must not render the resolved-only DNSSEC section, got:\n%s", fallback)
	}
}
