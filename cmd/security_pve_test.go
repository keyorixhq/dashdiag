package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BUG-016 (renderer): PVE service ports 8006/3128/111 must not be counted as
// security concerns on a PVE host, but must still count on a non-PVE host.
func TestCountSecurityIssuesPVEPorts(t *testing.T) {
	ports := []models.PortEntry{
		{Port: 8006, Protocol: "tcp", Process: "pveproxy", Expected: false},
		{Port: 3128, Protocol: "tcp", Process: "spiceproxy", Expected: false},
		{Port: 111, Protocol: "tcp", Process: "systemd", Expected: false},
	}

	if got := countSecurityIssues(&models.SecurityInfo{IsPVE: true, ListeningPorts: ports}); got != 0 {
		t.Errorf("PVE host: expected 0 issues for 8006/3128/111, got %d", got)
	}
	if got := countSecurityIssues(&models.SecurityInfo{IsPVE: false, ListeningPorts: ports}); got != 3 {
		t.Errorf("non-PVE host: expected 3 issues for the same ports, got %d", got)
	}
}

func TestIsPVEServicePort(t *testing.T) {
	for _, p := range []int{8006, 3128, 111} {
		if !isPVEServicePort(p) {
			t.Errorf("port %d should be a PVE service port", p)
		}
	}
	for _, p := range []int{22, 80, 443, 9090} {
		if isPVEServicePort(p) {
			t.Errorf("port %d should not be a PVE service port", p)
		}
	}
}
