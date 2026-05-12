package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

// ── LoadPolicy ────────────────────────────────────────────────────────────────

func TestLoadPolicy_Valid(t *testing.T) {
	dir := t.TempDir()
	content := `
ram_warn_pct: 70
ram_crit_pct: 90
disk_warn_pct: 75
deny:
  - CRIT
  - WARN
`
	path := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(path, []byte(content), 0644)

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.RAMWarnPct != 70 {
		t.Errorf("ram_warn_pct = %.0f, want 70", p.RAMWarnPct)
	}
	if p.RAMCritPct != 90 {
		t.Errorf("ram_crit_pct = %.0f, want 90", p.RAMCritPct)
	}
	if len(p.Deny) != 2 {
		t.Errorf("deny len = %d, want 2", len(p.Deny))
	}
}

func TestLoadPolicy_MissingFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	_ = os.WriteFile(path, []byte("ram_warn_pct: [invalid"), 0644)
	_, err := LoadPolicy(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// ── ApplyPolicy ───────────────────────────────────────────────────────────────

func TestApplyPolicy_NilNoChange(t *testing.T) {
	base := DefaultThresholds(0)
	result := ApplyPolicy(base, nil)
	if result.RAMCritPct != base.RAMCritPct {
		t.Errorf("nil policy should not change thresholds")
	}
}

func TestApplyPolicy_OverridesNonZero(t *testing.T) {
	base := DefaultThresholds(0)
	p := &PolicyFile{
		RAMWarnPct:  60,
		DiskCritPct: 85,
	}
	result := ApplyPolicy(base, p)
	if result.RAMWarnPct != 60 {
		t.Errorf("ram_warn_pct = %.0f, want 60", result.RAMWarnPct)
	}
	if result.DiskCritPct != 85 {
		t.Errorf("disk_crit_pct = %.0f, want 85", result.DiskCritPct)
	}
	// Non-overridden field should stay at default
	if result.RAMCritPct != base.RAMCritPct {
		t.Errorf("ram_crit_pct should stay at default %.0f, got %.0f", base.RAMCritPct, result.RAMCritPct)
	}
}

func TestApplyPolicy_ZeroFieldsIgnored(t *testing.T) {
	base := DefaultThresholds(0)
	p := &PolicyFile{
		RAMWarnPct: 0, // zero — should not override
		RAMCritPct: 85,
	}
	result := ApplyPolicy(base, p)
	if result.RAMWarnPct != base.RAMWarnPct {
		t.Errorf("zero field should not override default, got %.0f", result.RAMWarnPct)
	}
	if result.RAMCritPct != 85 {
		t.Errorf("non-zero field should override, got %.0f", result.RAMCritPct)
	}
}

// ── PolicyDeniesLevel ─────────────────────────────────────────────────────────

func TestPolicyDeniesLevel_NilDefaultCritOnly(t *testing.T) {
	if !PolicyDeniesLevel(nil, "CRIT") {
		t.Error("nil policy should deny CRIT")
	}
	if PolicyDeniesLevel(nil, "WARN") {
		t.Error("nil policy should not deny WARN")
	}
	if PolicyDeniesLevel(nil, "OK") {
		t.Error("nil policy should not deny OK")
	}
}

func TestPolicyDeniesLevel_EmptyDenyDefaultsCrit(t *testing.T) {
	p := &PolicyFile{Deny: []string{}}
	if !PolicyDeniesLevel(p, "CRIT") {
		t.Error("empty deny should default to denying CRIT")
	}
	if PolicyDeniesLevel(p, "WARN") {
		t.Error("empty deny should not deny WARN")
	}
}

func TestPolicyDeniesLevel_DenyWarnAndCrit(t *testing.T) {
	p := &PolicyFile{Deny: []string{"WARN", "CRIT"}}
	if !PolicyDeniesLevel(p, "WARN") {
		t.Error("should deny WARN")
	}
	if !PolicyDeniesLevel(p, "CRIT") {
		t.Error("should deny CRIT")
	}
	if PolicyDeniesLevel(p, "OK") {
		t.Error("should not deny OK")
	}
}

func TestPolicyDeniesLevel_DenyCritOnly(t *testing.T) {
	p := &PolicyFile{Deny: []string{"CRIT"}}
	if PolicyDeniesLevel(p, "WARN") {
		t.Error("CRIT-only deny should not deny WARN")
	}
	if !PolicyDeniesLevel(p, "CRIT") {
		t.Error("CRIT-only deny should deny CRIT")
	}
}
