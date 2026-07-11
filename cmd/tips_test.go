package cmd

// tips_test.go covers tipsCmd's inline RunE (cmd/tips.go), which delegates to
// tips.PrintAllTips() — a static, no-I/O printer.

import (
	"strings"
	"testing"
)

// Not t.Parallel(): captureStdout swaps the shared os.Stdout.
func TestTipsCmdRunE(t *testing.T) {
	out := captureStdout(t, func() {
		if err := tipsCmd.RunE(tipsCmd, nil); err != nil {
			t.Fatalf("tipsCmd.RunE: %v", err)
		}
	})
	if !strings.Contains(out, "DashDiag Tips") {
		t.Errorf("expected the tips header, got: %q", out)
	}
	if !strings.Contains(out, "Try:") {
		t.Errorf("expected at least one tip with a 'Try:' command, got: %q", out)
	}
}
