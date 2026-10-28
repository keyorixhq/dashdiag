package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/share"
)

// The share redactor treats "pass:" followed by whitespace as a password
// assignment and drops the rest of the line. The Not checked heading once ended
// in "this is not a pass:", so every shared report lost its first not-checked
// item to "[REDACTED]" and the reader never learned that check was not looked at.
func TestCoverageMarkdownSurvivesShareRedaction(t *testing.T) {
	var b strings.Builder
	writeCoverageMarkdown(&b, coverageView{
		Line: "2 checked · 3 not checked (needs root: 2, unverified: 1) · 0 not applicable",
		NotChecked: []NotCheckedItem{
			{Check: "CPU Load", Reason: "unverified"},
			{Check: "Firewall", Reason: "needs_root"},
			{Check: "Hardening", Reason: "needs_root"},
		},
	})
	md := b.String()

	red, counts := share.RedactText(md, "some-host", share.RedactOptions{})
	if strings.Contains(red, "[REDACTED]") || counts["secrets"] != 0 {
		t.Fatalf("share redaction ate part of the Coverage section (secrets=%d):\n%s", counts["secrets"], red)
	}
	for _, name := range []string{"CPU Load", "Firewall", "Hardening"} {
		if !strings.Contains(red, "`"+name+"`") {
			t.Errorf("not-checked item %q missing after share redaction:\n%s", name, red)
		}
	}
}
