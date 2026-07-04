package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestHasCrit(t *testing.T) {
	if hasCrit(nil) {
		t.Error("hasCrit(nil) should be false")
	}
	if hasCrit([]models.Insight{{Level: "WARN"}, {Level: "INFO"}}) {
		t.Error("hasCrit with no CRIT insights should be false")
	}
	if !hasCrit([]models.Insight{{Level: "WARN"}, {Level: "CRIT"}}) {
		t.Error("hasCrit with a CRIT insight present should be true")
	}
}
