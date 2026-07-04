package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Golden-output test for migrate.go's printMigrationReadiness (plain data, no
// I/O). No t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestPrintMigrationReadiness(t *testing.T) {
	clean := captureStdout(t, func() { printMigrationReadiness("/tmp/baseline.tar.gz", nil) })
	if !strings.Contains(clean, "clean source") {
		t.Errorf("no insights should read as a clean source, got:\n%s", clean)
	}

	warnOnly := captureStdout(t, func() {
		printMigrationReadiness("/tmp/baseline.tar.gz", []models.Insight{{Level: "WARN"}})
	})
	if !strings.Contains(warnOnly, "OK to migrate") {
		t.Errorf("warnings only (no critical) should still say OK to migrate, got:\n%s", warnOnly)
	}

	critical := captureStdout(t, func() {
		printMigrationReadiness("/tmp/baseline.tar.gz", []models.Insight{{Level: "CRIT"}, {Level: "WARN"}})
	})
	if !strings.Contains(critical, "1 critical, 1 warning") {
		t.Errorf("critical + warning counts should both be shown, got:\n%s", critical)
	}
	if !strings.Contains(critical, "Resolve the critical issues BEFORE migrating") {
		t.Errorf("a critical issue should recommend resolving it before migrating, got:\n%s", critical)
	}
}
