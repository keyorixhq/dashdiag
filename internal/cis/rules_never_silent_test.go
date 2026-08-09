package cis

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestHomeDirRulesNeverFalsePass is the regression guard for the CIS-side
// false-clean bug: a home-directory rule whose only candidate account's home
// directory could not be stat-ed must SKIP (nothing was verified), never PASS
// (a clean compliance result for zero accounts actually checked). Covers the
// two rules that were fixed (6.2.11, 6.2.12) alongside their siblings that
// already had the accessible-counter guard (6.2.13-6.2.16), so a future
// home-directory rule added without the same counter shows up here rather
// than silently reporting green.
//
// No t.Parallel(): mutates the package-level etcPasswdPath.
func TestHomeDirRulesNeverFalsePass(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	ruleIDs := []string{"6.2.11", "6.2.12", "6.2.13", "6.2.14", "6.2.15", "6.2.16"}

	for _, id := range ruleIDs {
		t.Run(id, func(t *testing.T) {
			p := filepath.Join(dir, fmt.Sprintf("passwd_nohome_%s", id))
			content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", filepath.Join(dir, "no_such_home_"+id))
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			etcPasswdPath = p

			rule := ruleByID(id)
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status == models.CISPass {
				t.Errorf("%s: home dir unreadable for the only candidate account must not PASS (nothing was verified), got Pass (%s)", id, got.Finding)
			}
			if got.Status != models.CISSkipped {
				t.Errorf("%s: want Skip when zero home directories were accessible, got %s (%s)", id, got.Status, got.Finding)
			}
		})
	}
}
