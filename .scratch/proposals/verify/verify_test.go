package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	patched "github.com/keyorixhq/dashdiag/.scratch/proposals/verify/config"
	prod "github.com/keyorixhq/dashdiag/internal/config"
)

// writeConfig writes an explicit --config file of approximately size bytes.
func writeConfig(t *testing.T, size int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "big.yaml")
	// Many bare scalars on their own lines: >1 MiB, and invalid YAML so the
	// UNPATCHED prod.Load rejects it fast (as a parse error, NOT a size error) —
	// keeping this verification quick while still exercising both code paths.
	var b strings.Builder
	for b.Len() < size {
		b.WriteString("scalarline\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestF1SizeCapRejectsOversizeExplicit is the red/green proof for the proposal.
// GREEN (patched): a >1 MiB explicit --config is rejected with the size-cap
// error, and Load returns defaults. RED/contrast (prod): the SAME file is NOT
// rejected on size (prod has no explicit cap — it reads/parses it, failing for a
// different reason or not at all). This demonstrates the patch adds the missing
// bound without changing small-config behavior.
func TestF1SizeCapRejectsOversizeExplicit(t *testing.T) {
	big := writeConfig(t, 2<<20) // 2 MiB

	// GREEN: patched Load rejects on size.
	cfg, err := patched.Load(big)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("patched.Load: want size-cap error, got cfg=%v err=%v", cfg != nil, err)
	}
	if cfg == nil {
		t.Fatalf("patched.Load: want defaults returned alongside the error, got nil cfg")
	}

	// CONTRAST: prod Load does NOT produce a size-cap error (no explicit cap).
	_, perr := prod.Load(big)
	if perr != nil && strings.Contains(perr.Error(), "exceeds maximum size") {
		t.Fatalf("prod.Load unexpectedly rejected on size — the gap the patch closes is already closed?")
	}
	t.Logf("GREEN patched rejects oversize (%v); prod does not size-reject (prod err=%v)", err, perr)
}

// TestF1SizeCapAllowsSmallConfig: a normal small --config still loads fine under
// the patch (no behavior change for real configs).
func TestF1SizeCapAllowsSmallConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(p, []byte("thresholds:\n  disk_warn_pct: 42\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := patched.Load(p)
	if err != nil {
		t.Fatalf("patched.Load small config: unexpected err %v", err)
	}
	if cfg.Thresholds.DiskWarnPct != 42 {
		t.Fatalf("patched.Load small config: want disk_warn_pct=42, got %v", cfg.Thresholds.DiskWarnPct)
	}
}
