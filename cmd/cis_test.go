package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestCisIcon(t *testing.T) {
	// --plain must emit an ASCII token per status, not leak the human emoji.
	cases := []struct {
		status models.CISStatus
		want   string
	}{
		{models.CISPass, "OK"},
		{models.CISFail, "CRIT"},
		{models.CISManual, "INFO"},
		{models.CISSkipped, "SKIP"},
		{models.CISStatus("weird"), "-"},
	}
	for _, c := range cases {
		if got := strings.TrimSpace(cisIcon(c.status, output.ModePlain)); got != c.want {
			t.Errorf("cisIcon(%v) = %q, want %q", c.status, got, c.want)
		}
	}
}
