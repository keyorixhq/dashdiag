package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoCallSitePassesWithoutCatchPanics is a completeness tripwire, same
// shape as internal/collectors' parsefloat_governance_test.go: internal/tui
// has no recover() and doesn't need one, because bubbletea's tea.NewProgram
// (select.go:84,186) already recovers from a panic in Update/View and
// restores the terminal before re-panicking. That safety net is silently
// defeated by passing tea.WithoutCatchPanics() to either call — this test
// fails if any non-test .go file in this package ever does.
func TestNoCallSitePassesWithoutCatchPanics(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) // #nosec G304 -- fixed glob over this package's own source
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(src), "WithoutCatchPanics") {
			t.Errorf("%s passes tea.WithoutCatchPanics — this disables bubbletea's built-in panic recovery, which internal/tui relies on instead of its own recover()", f)
		}
	}
}
