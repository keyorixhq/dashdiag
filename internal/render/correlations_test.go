package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// NOTE: none of these use t.Parallel() — captureStdout swaps the shared
// global os.Stdout for its duration, so concurrent callers race on it (see
// hints_test.go's captureStdout doc comment and health_mock_test.go's note).

// TestPrintCorrelationsEmpty covers the early-return guard: no correlations
// means no DIAGNOSIS block at all.
func TestPrintCorrelationsEmpty(t *testing.T) {
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.PrintCorrelations(nil) })
	if out != "" {
		t.Errorf("no correlations should print nothing, got %q", out)
	}
}

// TestPrintCorrelationsMachineModesNoOp covers the JSON/YAML no-op guard —
// correlations are folded into JSON output separately, never printed here.
func TestPrintCorrelationsMachineModesNoOp(t *testing.T) {
	corrs := []analysis.Correlation{{Name: "Memory Pressure Cascade", Level: "CRIT", Summary: "s", Action: "a"}}
	for _, mode := range []output.OutputMode{output.ModeJSON, output.ModeYAML} {
		r := NewRenderer(mode)
		out := captureStdout(t, func() { r.PrintCorrelations(corrs) })
		if out != "" {
			t.Errorf("mode %v should be a no-op, got %q", mode, out)
		}
	}
}

// TestPrintCorrelationsHumanMode covers the styled DIAGNOSIS block: header,
// per-correlation name/summary/action, all present.
func TestPrintCorrelationsHumanMode(t *testing.T) {
	corrs := []analysis.Correlation{
		{Name: "Memory Pressure Cascade", Level: "CRIT", Summary: "OOM killer active", Action: "add swap or RAM"},
		{Name: "Disk Saturation", Level: "WARN", Summary: "IO wait high", Action: "check for runaway writer"},
	}
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.PrintCorrelations(corrs) })

	for _, want := range []string{
		"DIAGNOSIS",
		"Memory Pressure Cascade", "OOM killer active", "add swap or RAM",
		"Disk Saturation", "IO wait high", "check for runaway writer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DIAGNOSIS block missing %q\n---\n%s", want, out)
		}
	}
}

// TestPrintCorrelations_StripsControlChars guards terminal escape injection:
// Name/Summary/Action are analysis-constructed strings that can splice in
// attacker-influenced data (e.g. an OOM-killed process's comm name via
// ruleRepeatedOOM in correlate.go), and must not carry raw control bytes to
// the terminal.
func TestPrintCorrelations_StripsControlChars(t *testing.T) {
	corrs := []analysis.Correlation{{
		Name:    "Repeated OOM Kill",
		Level:   "WARN",
		Summary: "evil\x1b]0;pwned\x07 was OOM-killed 5 times",
		Action:  "check evil\x1b]0;pwned\x07 memory growth",
	}}
	r := NewRenderer(output.ModeHuman)
	out := captureStdout(t, func() { r.PrintCorrelations(corrs) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("PrintCorrelations output still contains ESC byte: %q", out)
	}
	if !strings.Contains(out, "evil]0;pwned was OOM-killed") {
		t.Errorf("PrintCorrelations output missing sanitized summary: %q", out)
	}
}

// TestPrintCorrelationsPlainMode covers the unstyled (non-human) text path:
// "LEVEL: Name" header form instead of the styled icon+bold name.
func TestPrintCorrelationsPlainMode(t *testing.T) {
	corrs := []analysis.Correlation{{Name: "Swap Thrash", Level: "WARN", Summary: "swapping heavily", Action: "add RAM"}}
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() { r.PrintCorrelations(corrs) })

	for _, want := range []string{"DIAGNOSIS", "WARN: Swap Thrash", "swapping heavily", "add RAM"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain DIAGNOSIS block missing %q\n---\n%s", want, out)
		}
	}
}
