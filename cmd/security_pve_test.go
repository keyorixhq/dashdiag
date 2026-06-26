package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// BUG-016: PVE service ports 8006/3128/111 must not count as a security concern on
// a PVE host, but must on a non-PVE host. Now exercised through the shared verdict
// path (analysis.SecurityConcernCount → checkSecurity, BUG-072). SSHStrictModes is
// set so the StrictModes-default check doesn't add an unrelated concern. Note the
// non-PVE case is ONE concern: checkSecurity groups all unexpected ports into a
// single WARN (vs the old item tally that counted 3).
func TestSecurityConcernCountPVEPorts(t *testing.T) {
	ports := []models.PortEntry{
		{Port: 8006, Protocol: "tcp", Process: "pveproxy", Expected: false},
		{Port: 3128, Protocol: "tcp", Process: "spiceproxy", Expected: false},
		{Port: 111, Protocol: "tcp", Process: "systemd", Expected: false},
	}

	if got := analysis.SecurityConcernCount(models.SecurityInfo{SSHStrictModes: true, IsPVE: true, ListeningPorts: ports}); got != 0 {
		t.Errorf("PVE host: expected 0 concerns for 8006/3128/111, got %d", got)
	}
	if got := analysis.SecurityConcernCount(models.SecurityInfo{SSHStrictModes: true, IsPVE: false, ListeningPorts: ports}); got != 1 {
		t.Errorf("non-PVE host: expected 1 grouped concern for the unexpected ports, got %d", got)
	}
}
