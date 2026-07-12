package cmd

// examples_test.go covers runExamples (cmd/examples.go). Not t.Parallel():
// captureStdout swaps the shared os.Stdout.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newBareExamplesCmd() *cobra.Command {
	c := &cobra.Command{}
	c.Flags().Int("scenario", 0, "")
	return c
}

func TestRunExamples_All(t *testing.T) {
	c := newBareExamplesCmd()
	out := captureStdout(t, func() {
		if err := runExamples(c, nil); err != nil {
			t.Fatalf("runExamples: %v", err)
		}
	})
	if !strings.Contains(out, "1. Incident triage") || !strings.Contains(out, "9. Watch an incident unfold") {
		t.Errorf("scenario=0 should print every scenario, got: %q", out)
	}
}

func TestRunExamples_OneScenario(t *testing.T) {
	c := newBareExamplesCmd()
	_ = c.Flags().Set("scenario", "3")
	out := captureStdout(t, func() {
		if err := runExamples(c, nil); err != nil {
			t.Fatalf("runExamples: %v", err)
		}
	})
	if !strings.Contains(out, "3. Network investigation") {
		t.Errorf("scenario=3 should print scenario 3, got: %q", out)
	}
	if strings.Contains(out, "1. Incident triage") {
		t.Errorf("scenario=3 should NOT print scenario 1, got: %q", out)
	}
}

func TestRunExamples_OutOfRangeScenario(t *testing.T) {
	c := newBareExamplesCmd()
	_ = c.Flags().Set("scenario", "42")
	out := captureStdout(t, func() {
		if err := runExamples(c, nil); err != nil {
			t.Fatalf("runExamples: %v", err)
		}
	})
	if out != "" {
		t.Errorf("an out-of-range scenario should print nothing, got: %q", out)
	}
}
