package output

import (
	"strings"
	"testing"
)

// ProLabel renders a tier badge differently per output mode: suppressed in
// machine-readable modes, bracketed in plain/report, styled in human mode.
func TestProLabel(t *testing.T) {
	// Machine-readable modes emit nothing (would corrupt JSON/YAML).
	if got := ProLabel("Pro", ModeJSON); got != "" {
		t.Errorf("ModeJSON = %q, want empty", got)
	}
	if got := ProLabel("Pro", ModeYAML); got != "" {
		t.Errorf("ModeYAML = %q, want empty", got)
	}

	// Plain and report modes use an unstyled bracketed label.
	if got := ProLabel("Pro", ModePlain); got != "  [Pro]" {
		t.Errorf("ModePlain = %q, want '  [Pro]'", got)
	}
	if got := ProLabel("Team", ModeReport); got != "  [Team]" {
		t.Errorf("ModeReport = %q, want '  [Team]'", got)
	}

	// Human mode keeps the tier text and the ◆ glyph (styling may add ANSI).
	human := ProLabel("Pro", ModeHuman)
	if !strings.Contains(human, "Pro") || !strings.Contains(human, "◆") {
		t.Errorf("ModeHuman = %q, want to contain 'Pro' and '◆'", human)
	}
}
