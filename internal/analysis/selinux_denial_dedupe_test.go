package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func countDenialInsights(insights []models.Insight, check string) (n int, idx int) {
	idx = -1
	for i, ins := range insights {
		if ins.Check == check &&
			strings.Contains(ins.Message, "SELinux denial") &&
			strings.Contains(ins.Message, "last hour") {
			n++
			idx = i
		}
	}
	return n, idx
}

// When `dsd health` produces both a KernelSec CRIT and a Hardening WARN for the
// same SELinux denials, the post-pass keeps the authoritative KernelSec verdict,
// folds the Hardening insight's grouped fix-hints into it, and drops the
// duplicate. (Before: both lines shipped — a CRIT and a WARN for one event.)
func TestDedupeSELinuxDenialsCollapsesToKernelSec(t *testing.T) {
	in := []models.Insight{
		{Level: "OK", Check: "Memory", Message: "fine"},
		{
			Level: "CRIT", Check: "KernelSec",
			Message: "12 SELinux denial(s) in the last hour (mode: enforcing)",
			Hints:   []string{"to inspect: ausearch -m avc -ts recent"},
		},
		{
			Level: "WARN", Check: "Hardening",
			Message: "12 SELinux denials in the last hour (mode: enforcing)",
			Hints: []string{
				"to inspect: ausearch -m avc -ts recent", // dup — must not double
				"  httpd_t → shadow_t [file] ×7  fix: setsebool -P httpd_read_user_content on",
			},
		},
	}
	out := dedupeSELinuxDenials(in)

	if n, _ := countDenialInsights(out, "Hardening"); n != 0 {
		t.Errorf("Hardening SELinux-denial insight must be dropped, found %d", n)
	}
	n, idx := countDenialInsights(out, "KernelSec")
	if n != 1 {
		t.Fatalf("expected exactly 1 KernelSec denial insight, got %d", n)
	}
	k := out[idx]
	if k.Level != "CRIT" {
		t.Errorf("KernelSec severity must be preserved as CRIT, got %s", k.Level)
	}
	// The unique grouped fix must be folded in; the duplicate inspect line must not.
	var grouped, inspectCount int
	for _, h := range k.Hints {
		if strings.Contains(h, "setsebool -P httpd_read_user_content") {
			grouped++
		}
		if h == "to inspect: ausearch -m avc -ts recent" {
			inspectCount++
		}
	}
	if grouped != 1 {
		t.Errorf("Hardening grouped fix-hint must be folded into KernelSec exactly once, got %d", grouped)
	}
	if inspectCount != 1 {
		t.Errorf("duplicate hint must not be re-added, appeared %d times", inspectCount)
	}
}

// Standalone-like inputs (only one of the two checks present) must pass through
// untouched — the dedup must never drop a lone denial insight.
func TestDedupeSELinuxDenialsLeavesSingletons(t *testing.T) {
	onlyHardening := []models.Insight{{
		Level: "WARN", Check: "Hardening",
		Message: "12 SELinux denials in the last hour (mode: enforcing)",
	}}
	if out := dedupeSELinuxDenials(onlyHardening); len(out) != 1 {
		t.Errorf("lone Hardening denial must survive, got %d insights", len(out))
	}

	onlyKernelSec := []models.Insight{{
		Level: "CRIT", Check: "KernelSec",
		Message: "12 SELinux denial(s) in the last hour (mode: enforcing)",
	}}
	if out := dedupeSELinuxDenials(onlyKernelSec); len(out) != 1 {
		t.Errorf("lone KernelSec denial must survive, got %d insights", len(out))
	}
}

// The KernelSec "enforcing — dontaudit may suppress" INFO and the "could NOT be
// verified" INFO mention denials but are NOT the denial verdict — they must never
// be matched/dropped.
func TestDedupeSELinuxDenialsIgnoresInfoLines(t *testing.T) {
	in := []models.Insight{
		{Level: "INFO", Check: "KernelSec", Message: "SELinux enforcing — if services fail unexpectedly, dontaudit rules may suppress denials silently"},
		{Level: "WARN", Check: "Hardening", Message: "12 SELinux denials in the last hour (mode: enforcing)"},
	}
	out := dedupeSELinuxDenials(in)
	if len(out) != 2 {
		t.Errorf("no KernelSec denial verdict present (only an INFO) — nothing should be dropped, got %d", len(out))
	}
}
