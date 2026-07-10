//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── scanAllViaPackageManager dispatch order ─────────────────────────────────
//
// TestScanAllViaPackageManagerNoPM (cve_stale_metadata_test.go) already covers
// the "nothing on PATH" fallthrough. These cover the other four dispatch
// branches (zypper/dnf/apt/pacman/tdnf), each driven to fail fast so the test
// stays deterministic without a real package manager installed.

func TestScanAllViaPackageManager_DispatchesToZypper(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"zypper": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"})
	})
	res := scanAllViaPackageManager(context.Background())
	if res.PackageManager != "zypper" {
		t.Fatalf("expected dispatch to zypper, got PackageManager=%q", res.PackageManager)
	}
}

func TestScanAllViaPackageManager_DispatchesToDNF(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dnf": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})
	res := scanAllViaPackageManager(context.Background())
	if res.PackageManager != "dnf" {
		t.Fatalf("expected dispatch to dnf, got PackageManager=%q", res.PackageManager)
	}
}

func TestScanAllViaPackageManager_DispatchesToApt(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"apt-get": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("apt-get", []string{"--simulate", "upgrade"})
		b.PutCmdNotFound("apt-get", []string{"--simulate", "dist-upgrade"})
	})
	res := scanAllViaPackageManager(context.Background())
	if res.PackageManager != "apt" {
		t.Fatalf("expected dispatch to apt, got PackageManager=%q", res.PackageManager)
	}
}

func TestScanAllViaPackageManager_DispatchesToPacman(t *testing.T) {
	// zypper/dnf/apt-get all absent, pacman present but arch-audit absent —
	// scanAllPacman returns fast with ScanFailed (already covered by
	// TestScanAllPacman_NotInstalled; here we only assert the DISPATCH itself).
	withLookPathFixture(t, map[string]bool{"pacman": true}, func(b *source.Bundle) {})
	res := scanAllViaPackageManager(context.Background())
	if res.PackageManager != "pacman" {
		t.Fatalf("expected dispatch to pacman, got PackageManager=%q", res.PackageManager)
	}
	// pacman's branch deliberately skips markCVEStaleMetadata (no cached-index
	// age concept) — a real finding-free pacman result must not be silently
	// downgraded by a call this dispatch branch never makes.
}

func TestScanAllViaPackageManager_DispatchesToTDNF(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"tdnf": true}, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	res := scanAllViaPackageManager(context.Background())
	if res.PackageManager != "tdnf" {
		t.Fatalf("expected dispatch to tdnf, got PackageManager=%q", res.PackageManager)
	}
}

// ── ScanAllCVEs ──────────────────────────────────────────────────────────────

// TestScanAllCVEs_PackageManagerPresent_NeverFallsBackToOVAL guards the
// primary-source rule from the doc comment: when a package manager IS present,
// ScanAllCVEs must return its result directly and must never consult OVAL —
// even if a (garbage/incidental) OVAL-looking file happens to be discoverable.
func TestScanAllCVEs_PackageManagerPresent_NeverFallsBackToOVAL(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"zypper": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("zypper", []string{"--non-interactive", "--no-color", "list-patches", "--category", "security"})
	})
	res := ScanAllCVEs(context.Background())
	if res.PackageManager != "zypper" {
		t.Fatalf("expected the zypper result (no OVAL fallback attempted), got PackageManager=%q", res.PackageManager)
	}
}

// TestScanAllCVEs_NoPackageManagerStagedOVAL_ReturnsOVALResult guards the
// remaining ScanAllCVEs branch: no package manager present AND a staged OVAL
// feed that DOES resolve to a non-nil result — ScanAllCVEs must return that
// OVAL-derived result rather than falling through to the generic "NOT
// verified" package-manager result the sibling test below exercises.
func TestScanAllCVEs_NoPackageManagerStagedOVAL_ReturnsOVALResult(t *testing.T) {
	home := isolateCVEHome(t)
	writeStagedOVAL(t, home, ubuntuOVALWithRealPkg)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})

	res := ScanAllCVEs(context.Background())
	if res == nil {
		t.Fatal("expected a non-nil result")
	}
	if !strings.HasPrefix(res.PackageManager, "oval:") {
		t.Errorf("PackageManager = %q, want an oval: prefix (the OVAL fallback result)", res.PackageManager)
	}
	if res.Total != 1 {
		t.Errorf("Total = %d, want 1 (from the staged OVAL feed)", res.Total)
	}
}

// TestScanAllCVEs_NoPackageManagerNoOVAL_ReturnsUnverifiedPMResult guards the
// worst-case path: no package manager AND no staged OVAL feed anywhere on the
// (isolated) HOME/system paths — ScanAllCVEs must still return a non-nil,
// clearly "NOT verified" result rather than nil or a silent false-OK.
func TestScanAllCVEs_NoPackageManagerNoOVAL_ReturnsUnverifiedPMResult(t *testing.T) {
	isolateCVEHome(t) // no OVAL dir under the fresh HOME, no /etc/os-release seeded
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})

	res := ScanAllCVEs(context.Background())
	if res == nil {
		t.Fatal("expected a non-nil result")
	}
	if !res.ScanFailed {
		t.Errorf("expected ScanFailed=true, got %+v", res)
	}
	if !strings.Contains(res.StatusReason, "NOT verified") {
		t.Errorf("StatusReason = %q, want NOT verified", res.StatusReason)
	}
}
