package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DD-COLLECTOR-GAPS-1 High #3: an Uncheckable scan directory that needs root is
// an Unverified WARN whose hint is "re-run with sudo", not an openssl command.
func TestCheckTLS_UncheckableNeedsRootHintsSudo(t *testing.T) {
	t.Parallel()
	got := checkTLS(models.TLSInfo{Uncheckable: []models.TLSUncheckable{
		{Path: "/etc/ssl/private", Error: "could not read directory: permission denied", NeedsRoot: true},
	}})
	if len(got) != 1 || !got[0].Unverified || got[0].Level != "WARN" {
		t.Fatalf("got %+v, want one Unverified WARN", got)
	}
	if len(got[0].Hints) == 0 || !strings.Contains(got[0].Hints[0], "sudo") {
		t.Errorf("hints = %v, want a sudo hint", got[0].Hints)
	}
}
