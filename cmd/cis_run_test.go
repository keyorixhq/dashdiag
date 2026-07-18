package cmd

// cis_run_test.go covers runCIS's real (read-only) SecurityCollector/
// KernelSecurityCollector wiring, following the same real-I/O precedent as
// security_run_test.go's TestRunSecurity, plus the colour helpers' "on=true"
// branch that cis_test.go's ModePlain-only golden tests never exercise.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// newBareCISCmd builds a bare cobra.Command with the flags runCIS reads.
func newBareCISCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.Int("level", 1, "")
	f.Bool("fail-only", false, "")
	f.Bool("stig", false, "")
	return c
}

func TestRunCISPlain(t *testing.T) {
	c := newBareCISCmd()
	_ = c.Flags().Set("plain", "true")
	out := captureStdout(t, func() {
		if err := runCIS(c, nil); err != nil {
			t.Fatalf("runCIS (plain): %v", err)
		}
	})
	if !strings.Contains(out, "Level 1") {
		t.Errorf("plain mode should render the CIS profile header, got: %q", out)
	}
}

func TestRunCISJSON(t *testing.T) {
	c := newBareCISCmd()
	_ = c.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runCIS(c, nil); err != nil {
			t.Fatalf("runCIS (json): %v", err)
		}
	})
	if !strings.Contains(out, "{") {
		t.Errorf("json mode should emit JSON, got: %q", out)
	}
}

func TestRunCISStigAndFailOnly(t *testing.T) {
	c := newBareCISCmd()
	_ = c.Flags().Set("plain", "true")
	_ = c.Flags().Set("stig", "true")
	_ = c.Flags().Set("fail-only", "true")
	_ = c.Flags().Set("level", "2")
	out := captureStdout(t, func() {
		if err := runCIS(c, nil); err != nil {
			t.Fatalf("runCIS (stig, fail-only, level 2): %v", err)
		}
	})
	if !strings.Contains(out, "DISA STIG Ubuntu 20.04 LTS Level 2") {
		t.Errorf("--stig --level 2 should render the STIG level-2 profile header, got: %q", out)
	}
}

// TestCISColourHelpersOn covers the "on=true" branch of the colour helpers —
// cis_test.go's golden tests only ever pass ModePlain (on=false).
func TestCISColourHelpersOn(t *testing.T) {
	t.Parallel()
	if resetColour(true) == "" {
		t.Error("resetColour(true) should emit an ANSI reset code")
	}
	if green(true) == "" {
		t.Error("green(true) should emit an ANSI colour code")
	}
	if red(true) == "" {
		t.Error("red(true) should emit an ANSI colour code")
	}
	if dim(true) == "" {
		t.Error("dim(true) should emit an ANSI colour code")
	}
	if bold(true) == "" {
		t.Error("bold(true) should emit an ANSI colour code")
	}
}

func TestColourForOn(t *testing.T) {
	t.Parallel()
	cases := []models.CISStatus{models.CISPass, models.CISFail, models.CISManual, models.CISStatus("weird")}
	for _, s := range cases {
		if got := colourFor(s, true); got == "" {
			t.Errorf("colourFor(%v, true) should emit an ANSI code, got empty", s)
		}
	}
	if got := colourFor(models.CISPass, false); got != "" {
		t.Errorf("colourFor(_, false) should be empty, got %q", got)
	}
}
