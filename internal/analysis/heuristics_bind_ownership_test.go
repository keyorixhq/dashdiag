package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckBIND_OwnershipUnverifiedNotFalseWarn is a regression guard for the
// unprivileged `ss -tulpn` ownership blind spot (see collectors/bind_linux.go
// bindCheckPorts): a non-root run can see a :53 socket exists but be unable to
// attribute it to named specifically (ss -p only resolves ownership for the
// invoking UID without root). Before the fix, PortsChecked=true with
// Port53TCP/UDP=false unconditionally fired a WARN "not listening on port
// 53" — which is a false outage report for a perfectly healthy BIND server
// running under its own service account, the default on virtually every
// distro package. PortsOwnershipUnverified must downgrade this to an
// explicit "could not verify" INFO instead.
func TestCheckBIND_OwnershipUnverifiedNotFalseWarn(t *testing.T) {
	t.Parallel()
	base := models.BINDInfo{Detected: true, ServiceActive: true, ConfigOK: true,
		QueryTested: true, QueryOK: true, PortsChecked: true}

	t.Run("ownership unverified -> INFO, not WARN", func(t *testing.T) {
		t.Parallel()
		b := base
		b.PortsOwnershipUnverified = true // Port53TCP/UDP stay false (zero value)
		ins := checkBIND(b)
		if hasInsight(ins, "WARN", "not listening") {
			t.Errorf("must not WARN 'not listening' when ownership could not be verified: %+v", ins)
		}
		if !hasInsight(ins, "INFO", "could not verify") {
			t.Errorf("want INFO 'could not verify' when ss ownership is blind, got %+v", ins)
		}
	})

	t.Run("genuinely not listening (ownership verified) -> WARN", func(t *testing.T) {
		t.Parallel()
		b := base
		b.PortsOwnershipUnverified = false
		// Port53TCP/UDP false and verified — a real conflict/misconfiguration.
		if !hasInsight(checkBIND(b), "WARN", "not listening") {
			t.Error("want WARN when ports were actually verified not listening")
		}
	})

	t.Run("listening -> no port insight", func(t *testing.T) {
		t.Parallel()
		b := base
		b.Port53TCP = true
		b.Port53UDP = true
		ins := checkBIND(b)
		if hasInsight(ins, "WARN", "not listening") || hasInsight(ins, "INFO", "could not verify") {
			t.Errorf("healthy, verified BIND should emit no port insight, got %+v", ins)
		}
	})
}
