package explain

import (
	"os"
	"strings"
	"testing"
)

// TestMarkdownDocInSync fails if docs/CHECKS.md drifts from the topic registry,
// so the committed reference can never go stale. To regenerate after changing
// topics: `dsd explain --markdown > docs/CHECKS.md`.
func TestMarkdownDocInSync(t *testing.T) {
	const docPath = "../../docs/CHECKS.md"
	committed, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("reading %s: %v", docPath, err)
	}
	got := Markdown()
	if string(committed) != got {
		t.Errorf("docs/CHECKS.md is out of date — regenerate with:\n"+
			"  dsd explain --markdown > docs/CHECKS.md\n"+
			"(committed %d bytes, generated %d)", len(committed), len(got))
	}
}

func TestMarkdownStructure(t *testing.T) {
	md := Markdown()
	// One H2 per topic, plus the generated-by marker and an entry per topic in TOC.
	if n := strings.Count(md, "\n## "); n != len(Topics()) {
		t.Errorf("expected %d H2 sections, found %d", len(Topics()), n)
	}
	if !strings.Contains(md, "Do not edit by hand") {
		t.Error("missing generated-by marker")
	}
	for _, must := range []string{"**What it checks:**", "**Why it matters:**", "**How dsd decides:**"} {
		if !strings.Contains(md, must) {
			t.Errorf("missing section label %q", must)
		}
	}
}
