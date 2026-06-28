package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckRootFS(t *testing.T) {
	got := checkRootFS(models.RootFSInfo{UnexpectedReadOnly: true, RootFstype: "ext4"})
	if len(got) != 1 || got[0].Level != "CRIT" {
		t.Fatalf("unexpected ro root must CRIT, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "READ-ONLY") || !strings.Contains(got[0].Message, "ext4") {
		t.Errorf("message should name the read-only fault + fstype: %q", got[0].Message)
	}
	// Defensive: a non-fault struct stays quiet.
	if got := checkRootFS(models.RootFSInfo{UnexpectedReadOnly: false}); len(got) != 0 {
		t.Errorf("non-fault must be quiet, got %+v", got)
	}
}
