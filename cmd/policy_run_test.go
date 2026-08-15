package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
)

// Golden-output / wiring tests for policy.go's two subcommand RunE closures
// (policyInitCmd, policyCheckCmd) — both 0% covered. No t.Parallel() on the
// captureStdout-based tests (shared os.Stdout swap).

func TestPolicyInitCmdPrintsTemplate(t *testing.T) {
	out := captureStdout(t, func() {
		if err := policyInitCmd.RunE(policyInitCmd, nil); err != nil {
			t.Fatalf("policy init: %v", err)
		}
	})
	if !strings.Contains(out, "deny") {
		t.Errorf("the starter template should include a deny key, got:\n%s", out)
	}
}

func TestPolicyCheckCmdValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	yaml := "deny:\n  - WARN\nram_crit_pct: 92\ndisk_crit_pct: 88\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		if err := policyCheckCmd.RunE(policyCheckCmd, []string{path}); err != nil {
			t.Fatalf("policy check on a valid file: %v", err)
		}
	})
	if !strings.Contains(out, "is valid") {
		t.Errorf("a valid policy file should say so, got:\n%s", out)
	}
	if !strings.Contains(out, "92%") {
		t.Errorf("a set ram_crit_pct should be echoed, got:\n%s", out)
	}
	if !strings.Contains(out, "88%") {
		t.Errorf("a set disk_crit_pct should be echoed, got:\n%s", out)
	}
}

// TestPolicyCheckCmdValidNoOptionalFields exercises the branch where
// RAMCritPct/DiskCritPct are left at their zero value (not printed).
func TestPolicyCheckCmdValidNoOptionalFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-min.yaml")
	if err := os.WriteFile(path, []byte("deny:\n  - CRIT\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		if err := policyCheckCmd.RunE(policyCheckCmd, []string{path}); err != nil {
			t.Fatalf("policy check: %v", err)
		}
	})
	if strings.Contains(out, "ram_crit_pct") || strings.Contains(out, "disk_crit_pct") {
		t.Errorf("unset thresholds should not be echoed, got:\n%s", out)
	}
}

// TestPrintPolicyCheckResult_StripsControlChars guards terminal escape
// injection: analysis.LoadPolicy normalizes Deny to WARN/CRIT today, but that
// guarantee lives in a different layer than this print function — %v on a
// []string does not escape control bytes, so the print site must sanitize
// independently rather than trust the loader's current validation.
func TestPrintPolicyCheckResult_StripsControlChars(t *testing.T) {
	evil := "\x1b[2Jscreen-clear evil"
	out := captureStdout(t, func() {
		printPolicyCheckResult("policy.yaml", &analysis.PolicyFile{Deny: []string{evil}})
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printPolicyCheckResult output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "[2Jscreen-clear evil") {
		t.Errorf("printPolicyCheckResult output missing sanitized-but-present evil text:\n%s", out)
	}
}

func TestPolicyCheckCmdInvalid(t *testing.T) {
	errOut := captureStderr(t, func() {
		err := policyCheckCmd.RunE(policyCheckCmd, []string{"/nonexistent/policy.yaml"})
		if err == nil {
			t.Fatal("policy check on a missing file should error")
		}
	})
	if !strings.Contains(errOut, "policy invalid") {
		t.Errorf("an invalid/missing policy file should report the error on stderr, got:\n%s", errOut)
	}
}
