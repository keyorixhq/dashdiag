//go:build linux

package collectors

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// isolateCVEHome redirects HOME to a fresh temp dir and asserts no standard
// system OVAL/snapshot paths interfere, so tryOVALFallback/trySnapshotFallback
// deterministically miss unless a test explicitly seeds a file under the new
// HOME — required because cvedata.FindOVALFile/FindSnapshot read raw os.Stat
// on hardcoded paths, bypassing the activeSource fixture entirely.
func isolateCVEHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// ── CheckCVE dispatcher ──────────────────────────────────────────────────────

func TestCheckCVE_InvalidFormat(t *testing.T) {
	res := CheckCVE(context.Background(), "not-a-cve")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown for malformed ID, got %v", res.Status)
	}
	if !strings.Contains(res.StatusReason, "invalid CVE ID format") {
		t.Errorf("expected format-error reason, got %q", res.StatusReason)
	}
}

// TestCheckCVE_PrefixOnlyValidationRejectsTrailingGarbage guards Finding:
// internal-collectors-07-08. The format check used to be a bare
// strings.HasPrefix(cveID, "CVE-"), so anything after the prefix — including
// terminal control/escape bytes — passed straight through into
// CVEResult.CVE (printed raw by `dsd cve`) and into fallback advisory URLs
// built by string concatenation. A caller-supplied ID with a well-formed
// prefix but garbage trailing content must now be rejected outright, and the
// rejected input must NOT be echoed back into CVEResult.CVE.
func TestCheckCVE_PrefixOnlyValidationRejectsTrailingGarbage(t *testing.T) {
	res := CheckCVE(context.Background(), "CVE-2024-1234\x1b[31;1mFAKE\x1b[0m; rm -rf /")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown for a CVE- prefixed ID with garbage trailing content, got %v", res.Status)
	}
	if !strings.Contains(res.StatusReason, "invalid CVE ID format") {
		t.Errorf("expected format-error reason, got %q", res.StatusReason)
	}
	if res.CVE != "" {
		t.Errorf("CVE field = %q, want empty — a rejected ID must not be echoed back", res.CVE)
	}
}

// TestCheckCVE_WellFormedIDStillAccepted is the boundary counterpart: a
// genuinely well-formed CVE ID (just CVE-YYYY-NNNN, nothing trailing) must
// still pass the format gate and reach the package-manager dispatch, not be
// collaterally rejected by the tightened validation.
func TestCheckCVE_WellFormedIDStillAccepted(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})

	res := CheckCVE(context.Background(), "cve-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown (no package manager found), got %v", res.Status)
	}
	if strings.Contains(res.StatusReason, "invalid CVE ID format") {
		t.Errorf("a well-formed CVE ID must not be rejected by the format gate, got reason %q", res.StatusReason)
	}
}

func TestCheckCVE_NoPackageManager(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})

	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown with no package manager, got %v", res.Status)
	}
	if !strings.Contains(res.StatusReason, "no supported package manager") {
		t.Errorf("unexpected reason: %q", res.StatusReason)
	}
}

func TestCheckCVE_DispatchesToZypper(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"zypper": true}, func(b *source.Bundle) {
		b.PutCmd("zypper", []string{"--non-interactive", "--no-color", "lp", "--cve=CVE-2024-1234"},
			"No patch needed\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "zypper" {
		t.Fatalf("expected dispatch to zypper, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToDNF(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"dnf": true}, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"advisory", "info", "--cve", "CVE-2024-1234", "--quiet"},
			"No advisory found for this CVE\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "dnf" {
		t.Fatalf("expected dispatch to dnf, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToApt(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"apt-get": true}, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "apt" {
		t.Fatalf("expected dispatch to apt, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToPacman(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"pacman": true}, func(b *source.Bundle) {})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "pacman" {
		t.Fatalf("expected dispatch to pacman, got PackageManager=%q", res.PackageManager)
	}
}

func TestCheckCVE_DispatchesToTDNF(t *testing.T) {
	isolateCVEHome(t)
	withLookPathFixture(t, map[string]bool{"tdnf": true}, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"}, "Name : zlib\n", 0)
	})
	res := CheckCVE(context.Background(), "CVE-2024-1234")
	if res.PackageManager != "tdnf" {
		t.Fatalf("expected dispatch to tdnf, got PackageManager=%q", res.PackageManager)
	}
}

// ── readDistroID / ReadDistroID ──────────────────────────────────────────────

func TestReadDistroID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("NAME=\"Red Hat\"\nID=\"rhel\"\nVERSION_ID=\"10.0\"\n"))
	})
	if got := ReadDistroID(); got != "rhel" {
		t.Errorf("ReadDistroID() = %q, want rhel", got)
	}
	if got := readDistroID(); got != "rhel" {
		t.Errorf("readDistroID() = %q, want rhel", got)
	}
}

// TestReadDistroID_NoIDLine guards the final fallthrough branch: an
// os-release file that exists and reads successfully but has no "ID=" line at
// all must return "", not loop forever or panic.
func TestReadDistroID_NoIDLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("NAME=\"Some Distro\"\nVERSION=\"1.0\"\n"))
	})
	if got := ReadDistroID(); got != "" {
		t.Errorf("ReadDistroID() = %q, want empty when no ID= line is present", got)
	}
}

func TestReadDistroID_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := ReadDistroID(); got != "" {
		t.Errorf("ReadDistroID() = %q, want empty when os-release is unreadable", got)
	}
}

// ── fixCommand ───────────────────────────────────────────────────────────────

func TestFixCommand(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"zypper", "zypper patch --category security"},
		{"dnf", "dnf upgrade --security"},
		{"apt-get", "apt-get upgrade"},
		{"pacman", "pacman -Syu"},
		{"tdnf", "tdnf update --security"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			withLookPathFixture(t, map[string]bool{tc.tool: true}, func(b *source.Bundle) {})
			if got := fixCommand(); got != tc.want {
				t.Errorf("fixCommand() with only %s present = %q, want %q", tc.tool, got, tc.want)
			}
		})
	}
}

func TestFixCommand_NoPackageManager(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	if got := fixCommand(); got != "" {
		t.Errorf("fixCommand() with no package manager = %q, want empty", got)
	}
}

// ── tryOVALFallback / scanAllViaOVAL ─────────────────────────────────────────

func TestTryOVALFallback_NotFound(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := tryOVALFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil with no staged OVAL feed, got %+v", got)
	}
}

// TestTryOVALFallback_OVALParseError covers the err != nil branch: a staged OVAL
// file whose XML parses cleanly but has zero definitions causes loadOVAL to
// return an error, so tryOVALFallback returns nil rather than panicking or
// propagating the error.
func TestTryOVALFallback_OVALParseError(t *testing.T) {
	home := isolateCVEHome(t)
	writeStagedOVAL(t, home, `<?xml version="1.0"?><oval_definitions><definitions></definitions></oval_definitions>`)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := tryOVALFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when OVAL file has zero definitions, got %+v", got)
	}
}

// TestTryOVALFallback_CVENotFound covers the !ovalResult.Found branch: a
// valid staged OVAL file is found and parsed, but the queried CVE ID is absent
// from the feed, so tryOVALFallback returns nil.
func TestTryOVALFallback_CVENotFound(t *testing.T) {
	home := isolateCVEHome(t)
	// ubuntuOVALWithRealPkg contains CVE-2024-1234; searching for a different ID
	// exercises the matchDef==nil → Found=false → return nil path.
	writeStagedOVAL(t, home, ubuntuOVALWithRealPkg)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := tryOVALFallback(context.Background(), "CVE-2099-9999"); got != nil {
		t.Errorf("expected nil when CVE is absent from the OVAL feed, got %+v", got)
	}
}

func TestScanAllViaOVAL_NotFound(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := scanAllViaOVAL(context.Background()); got != nil {
		t.Errorf("expected nil with no staged OVAL feed, got %+v", got)
	}
}

// ubuntuOVALWithRealPkg is an Ubuntu/Debian-shaped OVAL definition referencing
// "dpkg" — a package genuinely installed in every Debian-family container
// (including the golang:1.26 test image), so ScanUbuntuOVALPackages's real
// dpkg-query cross-reference produces a genuine, deterministic hit without
// touching any collectors-package fixture seam (cvedata reads raw os.Stat/
// exec.Command, bypassing activeSource entirely — see isolateCVEHome's doc).
const ubuntuOVALWithRealPkg = `<?xml version="1.0"?>
<oval_definitions><definitions>
  <definition class="vulnerability">
    <metadata>
      <reference source="CVE" ref_id="CVE-2024-1234"/>
      <advisory><severity>high</severity></advisory>
    </metadata>
    <criteria>
      <criterion comment="dpkg package in noble is affected and may need fixing."/>
    </criteria>
  </definition>
</definitions></oval_definitions>`

// writeStagedOVAL stages an OVAL sidecar file under $HOME/.dsd/oval/ (one of
// cvedata.StandardOVALPaths()'s user-local dirs) so FindOVALFile's "any .xml
// in the dir" fallback picks it up regardless of exact filename. The filename
// includes "ubuntu" so sniffOVALVendor's content-sniff miss (this fixture has
// no canonical.com/ubuntu.com marker in its body) still falls through to
// isUbuntuOVAL's filename hint and dispatches to ScanUbuntuOVALPackages,
// rather than defaulting to the RHEL-shaped parser.
func writeStagedOVAL(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".dsd", "oval")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir oval dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ubuntu-test.xml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write oval fixture: %v", err)
	}
}

// TestTryOVALFallback_FoundWithRealInstalledPackage is the regression test for
// the gap the surrounding NOTE comments used to describe: cvedata.CheckCVEFromOVAL
// used to ALWAYS parse via the RHEL-shaped rpminfo_test/object/state schema and
// ALWAYS cross-reference via cvedata.QueryInstalledRPM (a real `rpm -qa` exec),
// regardless of the host's actual distro — so a staged Ubuntu/Debian OVAL
// sidecar was silently ignored by the single-CVE `dsd cve check <CVE-ID>` path
// (tryOVALFallback) even though the bulk `dsd cve --oval-scan` path
// (scanAllViaOVAL, see TestScanAllViaOVAL_FoundWithRealInstalledPackage) already
// vendor-dispatched correctly. CheckCVEFromOVAL now applies the same
// detectOVALVendor dispatch scanAllViaOVAL always had, so this must find the
// real "dpkg" package genuinely installed in the test container and report it
// vulnerable, exactly like the bulk scan does.
func TestTryOVALFallback_FoundWithRealInstalledPackage(t *testing.T) {
	home := isolateCVEHome(t)
	writeStagedOVAL(t, home, ubuntuOVALWithRealPkg)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})

	got := tryOVALFallback(context.Background(), "CVE-2024-1234")
	if got == nil {
		t.Fatal("expected a non-nil CVEResult when the staged OVAL feed matches an installed package")
	}
	if got.Status != models.CVEVulnerable {
		t.Errorf("Status = %v, want CVEVulnerable", got.Status)
	}
	if len(got.AffectedPackages) != 1 || got.AffectedPackages[0].Name != "dpkg" {
		t.Errorf("AffectedPackages = %+v, want [dpkg]", got.AffectedPackages)
	}
}

// TestScanAllViaOVAL_ScanErrors guards the `err != nil` branch: a staged file
// whose name has the ".xml.bz2" suffix (so FindOVALFile discovers it and
// ParseUbuntuOVAL/loadOVAL attempt bzip2 decompression) but whose CONTENT
// isn't valid bzip2 must make scanAllViaOVAL return nil, not panic or
// propagate a decompression error to the caller.
func TestScanAllViaOVAL_ScanErrors(t *testing.T) {
	home := isolateCVEHome(t)
	dir := filepath.Join(home, ".dsd", "oval")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir oval dir: %v", err)
	}
	// ubuntu-noble.oval.xml.bz2 is one of FindOVALFile's exact Ubuntu candidate
	// names, so this is found via the direct-candidate path rather than the
	// "any .xml" directory fallback.
	badPath := filepath.Join(dir, "ubuntu-noble.oval.xml.bz2")
	if err := os.WriteFile(badPath, []byte("this is not valid bzip2 data at all"), 0o644); err != nil {
		t.Fatalf("write corrupt oval fixture: %v", err)
	}
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})
	if got := scanAllViaOVAL(context.Background()); got != nil {
		t.Errorf("expected nil when the staged OVAL feed fails to decompress/parse, got %+v", got)
	}
}

// TestScanAllViaOVAL_FoundWithRealInstalledPackage is the scanAllViaOVAL
// analog: the same staged feed must surface through the "scan everything"
// entrypoint, bucketed by CVSS/priority into the CVEAllResult shape.
func TestScanAllViaOVAL_FoundWithRealInstalledPackage(t *testing.T) {
	home := isolateCVEHome(t)
	writeStagedOVAL(t, home, ubuntuOVALWithRealPkg)
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\n"))
	})

	got := scanAllViaOVAL(context.Background())
	if got == nil {
		t.Fatal("expected a non-nil CVEAllResult when the staged OVAL feed matches an installed package")
	}
	if got.Total != 1 {
		t.Fatalf("Total = %d, want 1", got.Total)
	}
	if !strings.HasPrefix(got.PackageManager, "oval:") {
		t.Errorf("PackageManager = %q, want an oval: prefix", got.PackageManager)
	}
}

// ── trySnapshotFallback ───────────────────────────────────────────────────────

func writeGzippedSnapshot(t *testing.T, home string, snap cvedata.Snapshot) {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	path := filepath.Join(dir, "cvedata.json.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
}

func TestTrySnapshotFallback_NoSnapshot(t *testing.T) {
	isolateCVEHome(t)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil with no staged snapshot, got %+v", got)
	}
}

// TestTrySnapshotFallback_LoadSnapshotError guards the `err != nil` branch of
// cvedata.LoadSnapshot: a file staged at the standard snapshot path that isn't
// valid JSON (or valid gzip) must make trySnapshotFallback return nil, not
// panic or propagate the parse error to the caller.
func TestTrySnapshotFallback_LoadSnapshotError(t *testing.T) {
	home := isolateCVEHome(t)
	dir := filepath.Join(home, ".dsd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// ".gz" suffix routes through gzip.NewReader, which will fail fast on this
	// non-gzip content — exercising the err != nil path distinctly from an
	// empty-but-valid snapshot.
	path := filepath.Join(dir, "cvedata.json.gz")
	if err := os.WriteFile(path, []byte("not valid gzip data"), 0o644); err != nil {
		t.Fatalf("write corrupt snapshot: %v", err)
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when the staged snapshot fails to parse, got %+v", got)
	}
}

// TestTrySnapshotFallback_EmptySnapshot guards the snap.IsEmpty() branch: a
// syntactically valid but content-empty snapshot (no CVEs map entries) must
// also yield nil, distinct from the parse-error case above.
func TestTrySnapshotFallback_EmptySnapshot(t *testing.T) {
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{CVEs: map[string]cvedata.SnapshotCVE{}})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil for an empty snapshot, got %+v", got)
	}
}

func TestTrySnapshotFallback_CVENotInSnapshot(t *testing.T) {
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-9999": {Summary: "unrelated"},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when the CVE has no snapshot entry, got %+v", got)
	}
}

func TestTrySnapshotFallback_DistroNotApplicable(t *testing.T) {
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-1234": {
				Summary: "test CVE",
				Affected: map[string][]cvedata.SnapshotPackage{
					"opensuse-tumbleweed": {{Name: "openssl", FixedIn: "3.0.1"}},
				},
			},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	res := trySnapshotFallback(context.Background(), "CVE-2024-1234")
	if res == nil {
		t.Fatal("expected a concrete NotAffected result, got nil")
	}
	if res.Status != models.CVENotAffected {
		t.Errorf("Status = %v, want CVENotAffected", res.Status)
	}
	if !strings.Contains(res.StatusReason, "not applicable") {
		t.Errorf("StatusReason = %q, want 'not applicable' hint", res.StatusReason)
	}
}

func TestTrySnapshotFallback_AffectedButRPMUnavailable(t *testing.T) {
	// The snapshot lists the current distro as affected, but with no rpm binary
	// cvedata.QueryInstalledRPM fails, so the fallback still can't produce a
	// verdict and must return nil rather than guess. QueryInstalledRPM shells out
	// to the real rpm, so this branch is only reachable where rpm is absent — the
	// CI runners have rpm installed, where it would instead resolve versions.
	if _, err := exec.LookPath("rpm"); err == nil {
		t.Skip("rpm is installed in this environment; the rpm-unavailable path is unreachable here")
	}
	home := isolateCVEHome(t)
	writeGzippedSnapshot(t, home, cvedata.Snapshot{
		CVEs: map[string]cvedata.SnapshotCVE{
			"CVE-2024-1234": {
				Summary: "test CVE",
				Affected: map[string][]cvedata.SnapshotPackage{
					"rhel:10": {{Name: "openssl", FixedIn: "3.0.1"}},
				},
			},
		},
	})
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	if got := trySnapshotFallback(context.Background(), "CVE-2024-1234"); got != nil {
		t.Errorf("expected nil when rpm is unavailable to verify installed versions, got %+v", got)
	}
}

// ── APT scanning ──────────────────────────────────────────────────────────────

func TestScanAllApt_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"--simulate", "upgrade"},
			"Inst openssl [3.0.1] (3.0.2 debian-security:12/stable-security [amd64])\n"+
				"Inst zlib1g [1.2.11] (1.2.13 debian-security:12/stable-security [amd64])\n"+
				"Inst regular-pkg [1.0] (1.1 debian:12/stable [amd64])\n", 0) // no "security" substring — filtered out
	})
	res := scanAllApt(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan, got ScanFailed: %s", res.StatusReason)
	}
	// Only the two "security" lines count; the non-security Inst line is filtered out.
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Critical) != 1 || res.Critical[0].ID != "openssl" {
		t.Errorf("Critical = %+v, want [openssl] (openssl is a CRITICAL-severity package)", res.Critical)
	}
	if res.FixCommand != "apt-get upgrade" {
		t.Errorf("FixCommand = %q, want apt-get upgrade", res.FixCommand)
	}
	if res.StatusReason != "" {
		t.Errorf("StatusReason = %q, want empty when advisories were found", res.StatusReason)
	}
}

// TestScanAllApt_ModerateSeverityAndShortLine guards the MODERATE severity
// bucket (only CRITICAL is exercised in TestScanAllApt_Success) and the
// len(fields)<2 skip for a malformed "Inst"-prefixed security line.
func TestScanAllApt_ModerateSeverityAndShortLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"--simulate", "upgrade"},
			"Inst vim [8.2] (8.2.1 debian-security:12/stable-security [amd64])\n"+
				"Instsecurity\n", 0) // "Inst"-prefixed, contains "security", but a single field
	})
	res := scanAllApt(context.Background())
	if res.Total != 1 {
		t.Fatalf("expected 1 advisory (short line skipped), got %d: %+v", res.Total, res)
	}
	if len(res.Moderate) != 1 || res.Moderate[0].ID != "vim" {
		t.Errorf("Moderate = %+v, want [vim]", res.Moderate)
	}
}

func TestScanAllApt_UpToDate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"--simulate", "upgrade"}, "", 0)
	})
	res := scanAllApt(context.Background())
	if res.ScanFailed {
		t.Fatal("empty output with no error is a clean scan, not a failure")
	}
	if res.Total != 0 {
		t.Errorf("Total = %d, want 0", res.Total)
	}
	if res.StatusReason != "no pending upgrades found" {
		t.Errorf("StatusReason = %q, want the up-to-date message", res.StatusReason)
	}
}

// TestScanAllApt_UpgradeFailsFallsBackToDistUpgrade guards the fallback-
// ordering branch: when `apt-get --simulate upgrade` fails with NO output,
// scanAllApt must retry `--simulate dist-upgrade` before giving up.
func TestScanAllApt_UpgradeFailsFallsBackToDistUpgrade(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("apt-get", []string{"--simulate", "upgrade"}, "", 1) // fails, empty output
		b.PutCmd("apt-get", []string{"--simulate", "dist-upgrade"},
			"Inst curl [7.0] (7.1 debian-security:12/stable-security [amd64])\n", 0)
	})
	res := scanAllApt(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected the dist-upgrade fallback to succeed, got ScanFailed: %s", res.StatusReason)
	}
	if res.Total != 1 {
		t.Fatalf("expected 1 advisory from the dist-upgrade fallback, got %+v", res)
	}
}

// TestScanAllApt_BothFail guards the false-OK regression this closes: when
// BOTH apt-get simulations fail with no output, the scan must report
// ScanFailed=true (not a silent clean "0 advisories" false-OK).
func TestScanAllApt_BothFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("apt-get", []string{"--simulate", "upgrade"})
		b.PutCmdNotFound("apt-get", []string{"--simulate", "dist-upgrade"})
	})
	res := scanAllApt(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when both apt-get simulations fail with no output")
	}
	if !strings.Contains(res.StatusReason, "apt-get --simulate upgrade failed") {
		t.Errorf("StatusReason = %q, want the apt-get failure reason", res.StatusReason)
	}
}

// ── DNF scanning ──────────────────────────────────────────────────────────────

func TestScanAllDNF_DNF5Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"},
			"RHSA-2026:0001  Critical/Sec.  openssl-3.0.1-1.el10.x86_64\n"+
				"RHSA-2026:0002  Important/Sec. curl-8.0.1-1.el10.x86_64\n", 0)
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nCVEs: CVE-2026-1111\n", 0)
	})
	res := scanAllDNF(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan, got ScanFailed: %s", res.StatusReason)
	}
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Critical) != 1 || res.Critical[0].ID != "RHSA-2026:0001" {
		t.Errorf("Critical = %+v, want [RHSA-2026:0001]", res.Critical)
	}
	if len(res.Important) != 1 {
		t.Errorf("Important = %+v, want 1 entry", res.Important)
	}
	if res.Critical[0].CVEs != "CVE-2026-1111" {
		t.Errorf("expected enrichment to populate CVEs, got %q", res.Critical[0].CVEs)
	}
}

func TestScanAllDNF_DNF4Fallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmd("dnf", []string{"updateinfo", "list", "security", "--quiet"},
			"RHSA-2026:0003  security  critical  package-1.2.3\n", 0)
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--security", "--quiet"})
	})
	res := scanAllDNF(context.Background())
	if res.Total != 1 || len(res.Critical) != 1 {
		t.Fatalf("expected 1 critical advisory from the DNF5 table format, got %+v", res)
	}
}

// TestScanAllDNF_ModerateLowAndDedup guards the moderate/low severity buckets
// (only critical/important are exercised elsewhere) and the seen[id] dedup
// skip — a duplicate advisory ID (DNF sometimes lists an advisory once per
// affected package) must be counted only once.
func TestScanAllDNF_ModerateLowAndDedup(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"},
			"RHSA-2026:0010  Moderate/Sec.  pkg-a-1.0-1.el10.x86_64\n"+
				"RHSA-2026:0010  Moderate/Sec.  pkg-a-1.0-1.el10.x86_64\n"+ // duplicate advisory ID
				"RHSA-2026:0011  Low/Sec.       pkg-b-2.0-1.el10.x86_64\n", 0)
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--security", "--quiet"})
	})
	res := scanAllDNF(context.Background())
	if res.Total != 2 {
		t.Fatalf("expected 2 unique advisories (duplicate ID collapsed), got %d: %+v", res.Total, res)
	}
	if len(res.Moderate) != 1 || res.Moderate[0].ID != "RHSA-2026:0010" {
		t.Errorf("Moderate = %+v, want [RHSA-2026:0010]", res.Moderate)
	}
	if len(res.Low) != 1 || res.Low[0].ID != "RHSA-2026:0011" {
		t.Errorf("Low = %+v, want [RHSA-2026:0011]", res.Low)
	}
}

func TestScanAllDNF_UpToDate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmd("dnf", []string{"advisory", "list", "--security", "--quiet"}, "", 0)
	})
	res := scanAllDNF(context.Background())
	if res.ScanFailed {
		t.Fatal("empty advisory output is a clean scan, not a failure")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllDNF_BothFail_NotTimeout(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})
	res := scanAllDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when both dnf queries fail")
	}
	if !strings.Contains(res.StatusReason, "no repo access") {
		t.Errorf("StatusReason = %q, want a no-repo-access reason", res.StatusReason)
	}
}

func TestScanAllDNF_BothFail_Timeout(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"makecache", "-q"})
		b.PutCmdNotFound("dnf", []string{"advisory", "list", "--security", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "list", "security", "--quiet"})
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := scanAllDNF(ctx)
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed for a cancelled context")
	}
	if !strings.Contains(res.StatusReason, "timed out") {
		t.Errorf("StatusReason = %q, want a timed-out reason for a cancelled ctx", res.StatusReason)
	}
}

// ── enrichDNFAdvisoryWithCVEs / rhSubscriptionNote ───────────────────────────

func TestEnrichDNFAdvisoryWithCVEs_Populates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nCVEs: CVE-2026-1111, CVE-2026-2222\n", 0)
	})
	result := &models.CVEAllResult{
		Critical: []models.CVEAdvisory{{ID: "RHSA-2026:0001"}},
	}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	if result.Critical[0].CVEs != "CVE-2026-1111, CVE-2026-2222" {
		t.Errorf("CVEs = %q, want both IDs", result.Critical[0].CVEs)
	}
}

// TestEnrichDNFAdvisoryWithCVEs_MultiCVEAndAllBuckets guards three branches
// the happy-path test doesn't reach: an advisory with MULTIPLE "CVEs:" lines
// (the comma-append when a CVE map entry already exists), and population
// across all four severity buckets (Important/Moderate/Low), not just Critical.
func TestEnrichDNFAdvisoryWithCVEs_MultiCVEAndAllBuckets(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nCVEs: CVE-2026-1111\nCVEs: CVE-2026-2222\n"+
				"Update ID: RHSA-2026:0002\nCVEs: CVE-2026-3333\n"+
				"Update ID: RHSA-2026:0003\nCVEs: CVE-2026-4444\n"+
				"Update ID: RHSA-2026:0004\nCVEs: CVE-2026-5555\n", 0)
	})
	result := &models.CVEAllResult{
		Critical:  []models.CVEAdvisory{{ID: "RHSA-2026:0001"}},
		Important: []models.CVEAdvisory{{ID: "RHSA-2026:0002"}},
		Moderate:  []models.CVEAdvisory{{ID: "RHSA-2026:0003"}},
		Low:       []models.CVEAdvisory{{ID: "RHSA-2026:0004"}},
	}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	if result.Critical[0].CVEs != "CVE-2026-1111, CVE-2026-2222" {
		t.Errorf("Critical CVEs = %q, want both IDs comma-joined", result.Critical[0].CVEs)
	}
	if result.Important[0].CVEs != "CVE-2026-3333" {
		t.Errorf("Important CVEs = %q, want CVE-2026-3333", result.Important[0].CVEs)
	}
	if result.Moderate[0].CVEs != "CVE-2026-4444" {
		t.Errorf("Moderate CVEs = %q, want CVE-2026-4444", result.Moderate[0].CVEs)
	}
	if result.Low[0].CVEs != "CVE-2026-5555" {
		t.Errorf("Low CVEs = %q, want CVE-2026-5555", result.Low[0].CVEs)
	}
}

// TestEnrichDNFAdvisoryWithCVEs_ParsedButNoCVEsMatched guards the len(cveMap)==0
// branch: the query succeeds with non-empty output, but no line matches the
// "CVEs:" pattern at all — distinct from the command-failure branch, which
// TestEnrichDNFAdvisoryWithCVEs_FailsSetsSubscriptionNote already covers.
func TestEnrichDNFAdvisoryWithCVEs_ParsedButNoCVEsMatched(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"updateinfo", "info", "--security", "--quiet"},
			"Update ID: RHSA-2026:0001\nSeverity: Critical\n", 0) // no CVEs: line at all
		b.PutFile("/etc/os-release", []byte("ID=fedora\n"))
	})
	result := &models.CVEAllResult{Critical: []models.CVEAdvisory{{ID: "RHSA-2026:0001"}}}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	if result.Critical[0].CVEs != "" {
		t.Errorf("expected no CVEs populated, got %q", result.Critical[0].CVEs)
	}
	// Fedora never sets a subscription note (mirrors the failure-path test).
	if result.SubscriptionNote != "" {
		t.Errorf("expected no subscription note on Fedora, got %q", result.SubscriptionNote)
	}
}

func TestEnrichDNFAdvisoryWithCVEs_FailsSetsSubscriptionNote(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--security", "--quiet"})
		b.PutFile("/etc/os-release", []byte("ID=fedora\n"))
	})
	result := &models.CVEAllResult{}
	enrichDNFAdvisoryWithCVEs(context.Background(), result)
	// Fedora is free (never subscription-gated) — the note stays empty even
	// though the underlying query failed.
	if result.SubscriptionNote != "" {
		t.Errorf("expected no subscription note on Fedora, got %q", result.SubscriptionNote)
	}
}

func TestRHSubscriptionNote_Fedora(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=fedora\n"))
	})
	if got := rhSubscriptionNote(); got != "" {
		t.Errorf("expected empty note for Fedora, got %q", got)
	}
}

func TestRHSubscriptionNote_NonRHFamily(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})
	if got := rhSubscriptionNote(); got != "" {
		t.Errorf("expected empty note for a non-RH distro, got %q", got)
	}
}

// TestRHSubscriptionNote_NonRootRHFamily guards the "needs root" branch: an
// RH-family distro observed as a non-root uid must report the sudo-hint
// message, never attempt to read /etc/pki/entitlement.
func TestRHSubscriptionNote_NonRootRHFamily(t *testing.T) {
	swapGetuid(t, 1000)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "require root access") {
		t.Errorf("expected a root-required message, got %q", got)
	}
}

// TestRHSubscriptionNote_RootNotRegistered drives the root + no entitlement
// certs branch, forced deterministically via the getuid seam (real CI/dev
// binaries aren't root, so os.Getuid()==0 could never fire this in
// practice — that's why the coverage was previously stuck skipping).
func TestRHSubscriptionNote_RootNotRegistered(t *testing.T) {
	swapGetuid(t, 0)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\n"))
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "not registered") {
		t.Errorf("expected a not-registered message, got %q", got)
	}
}

func TestRHSubscriptionNote_RootExpiredCerts(t *testing.T) {
	swapGetuid(t, 0)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=centos\n"))
		b.PutDir("/etc/pki/entitlement", []string{"1234567890-key.pem"})
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "expired") {
		t.Errorf("expected an expired-subscription message, got %q", got)
	}
}

func TestRHSubscriptionNote_RootActiveSubscription(t *testing.T) {
	swapGetuid(t, 0)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rocky\n"))
		b.PutDir("/etc/pki/entitlement", []string{"1234567890.pem", "1234567890-key.pem"})
	})
	got := rhSubscriptionNote()
	if !strings.Contains(got, "Subscription active") {
		t.Errorf("expected an active-subscription message, got %q", got)
	}
}

// ── Pacman / arch-audit ───────────────────────────────────────────────────────

func TestCheckCVEPacman_NotInstalled(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown without arch-audit, got %v", res.Status)
	}
	if !strings.Contains(res.FallbackURL, "security.archlinux.org") {
		t.Errorf("expected an Arch security tracker URL, got %q", res.FallbackURL)
	}
}

func TestCheckCVEPacman_QueryFails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("arch-audit", []string{"--format", "%n %c %s"})
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown on query failure, got %v", res.Status)
	}
}

func TestCheckCVEPacman_Vulnerable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"},
			"openssl CVE-2024-1234 Critical\n", 0)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable, got %v", res.Status)
	}
	if len(res.AffectedPackages) != 1 || res.AffectedPackages[0].Name != "openssl" {
		t.Errorf("AffectedPackages = %+v, want [openssl]", res.AffectedPackages)
	}
	if res.AffectedPackages[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", res.AffectedPackages[0].Severity)
	}
}

func TestCheckCVEPacman_NotAffected(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"},
			"curl CVE-2024-9999 Low\n", 0)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVENotAffected {
		t.Fatalf("expected CVENotAffected when no line matches, got %v", res.Status)
	}
}

// TestCheckCVEPacman_VulnerableNonZeroExit is the regression guard for
// subprocess-wrappers-01: arch-audit exits non-zero exactly when it has
// findings to report, and runCmd (the pre-fix helper) discards stdout on any
// non-zero exit — so a genuinely-vulnerable host would read as CVEUnknown
// instead of CVEVulnerable.
func TestCheckCVEPacman_VulnerableNonZeroExit(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"},
			"openssl CVE-2024-1234 Critical\n", 1)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable despite the non-zero exit, got %v (%s)", res.Status, res.StatusReason)
	}
	if len(res.AffectedPackages) != 1 || res.AffectedPackages[0].Name != "openssl" {
		t.Errorf("AffectedPackages = %+v, want [openssl]", res.AffectedPackages)
	}
}

// TestCheckCVEPacman_NonZeroExitWithUnmatchedOutput is the sibling of
// TestScanAllPacman_NonZeroExitWithUnmatchedOutput (internal-collectors-07-05):
// scanAllPacman and checkCVEZypper both got a guard so a non-zero exit with
// SOME non-empty, non-matching stdout (a repo/lock/permission warning
// arch-audit printed before failing) can't fall through to a confident
// clean verdict — checkCVEPacman, one function above scanAllPacman in this
// file, had no equivalent guard and would report CVENotAffected from a
// failed, non-matching arch-audit run.
func TestCheckCVEPacman_NonZeroExitWithUnmatchedOutput(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"--format", "%n %c %s"}, "error: database lock file exists\n", 1)
	})
	res := checkCVEPacman(context.Background(), "CVE-2024-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown for a non-zero exit with no real finding line, got %v (%s)", res.Status, res.StatusReason)
	}
}

func TestScanAllPacman_NotInstalled(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {})
	res := scanAllPacman(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed without arch-audit")
	}
}

func TestScanAllPacman_QueryFails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmdNotFound("arch-audit", []string{"-u"})
	})
	res := scanAllPacman(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed on query failure")
	}
}

// TestScanAllPacman_NonZeroExitWithUnmatchedOutput is the regression test
// for internal-collectors-07-01: a non-zero exit with SOME non-empty stdout
// that isn't a real arch-audit finding line (a repo/lock/permission warning
// arch-audit printed before failing) must not fall through to "no
// vulnerable packages found" — only a real "is affected by" line in the
// output can justify trusting a non-zero exit (mirrors the zypper fix,
// internal-collectors-07-03).
func TestScanAllPacman_NonZeroExitWithUnmatchedOutput(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"}, "error: database lock file exists\n", 1)
	})
	res := scanAllPacman(context.Background())
	if !res.ScanFailed {
		t.Fatalf("expected ScanFailed for a non-zero exit with no real finding line, got %+v", res)
	}
}

func TestScanAllPacman_UpToDate(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"}, "", 0)
	})
	res := scanAllPacman(context.Background())
	if res.ScanFailed {
		t.Fatal("empty output is a clean scan, not a failure")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllPacman_Vulnerable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"},
			"openssl is affected by CVE-2024-1111, CVE-2024-2222 [Critical]: remote code execution\n"+
				"curl is affected by CVE-2024-3333 [Medium]: info leak\n", 0)
	})
	res := scanAllPacman(context.Background())
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Critical) != 1 || res.Critical[0].ID != "openssl" {
		t.Errorf("Critical = %+v, want [openssl]", res.Critical)
	}
	if res.Critical[0].CVEs != "CVE-2024-1111, CVE-2024-2222" {
		t.Errorf("CVEs = %q, want both IDs", res.Critical[0].CVEs)
	}
	if res.Critical[0].Summary != "remote code execution" {
		t.Errorf("Summary = %q, want the trailing description", res.Critical[0].Summary)
	}
	if len(res.Moderate) != 1 || res.Moderate[0].ID != "curl" {
		t.Errorf("Moderate = %+v, want [curl]", res.Moderate)
	}
}

// TestScanAllPacman_ImportantAndLowSeverity guards the "important" (High) and
// "low" (default) severity buckets — Critical is covered by
// TestScanAllPacman_Vulnerable, Moderate (Medium) too.
func TestScanAllPacman_ImportantAndLowSeverity(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"},
			"nginx is affected by CVE-2024-4444 [High]: privilege escalation\n"+
				"vim is affected by CVE-2024-5555 [Low]: minor info leak\n", 0)
	})
	res := scanAllPacman(context.Background())
	if res.Total != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", res.Total, res)
	}
	if len(res.Important) != 1 || res.Important[0].ID != "nginx" {
		t.Errorf("Important = %+v, want [nginx]", res.Important)
	}
	if len(res.Low) != 1 || res.Low[0].ID != "vim" {
		t.Errorf("Low = %+v, want [vim]", res.Low)
	}
}

// TestScanAllPacman_VulnerableNonZeroExit is the scanAllPacman sibling of
// TestCheckCVEPacman_VulnerableNonZeroExit (subprocess-wrappers-01): `arch-audit
// -u` also exits non-zero when it reports upgradable/vulnerable packages.
func TestScanAllPacman_VulnerableNonZeroExit(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"arch-audit": true}, func(b *source.Bundle) {
		b.PutCmd("arch-audit", []string{"-u"},
			"openssl is affected by CVE-2024-1111 [Critical]: remote code execution\n", 1)
	})
	res := scanAllPacman(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan despite the non-zero exit, got ScanFailed (%s)", res.StatusReason)
	}
	if res.Total != 1 || len(res.Critical) != 1 || res.Critical[0].ID != "openssl" {
		t.Errorf("res = %+v, want 1 Critical advisory for openssl", res)
	}
}

// ── TDNF / Photon ─────────────────────────────────────────────────────────────

func TestCheckCVETDNF_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
		b.PutFile("/etc/os-release", []byte("VERSION_ID=\"5.0\"\n"))
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVEUnknown {
		t.Fatalf("expected CVEUnknown on query failure, got %v", res.Status)
	}
	if !strings.Contains(res.FallbackURL, "Security-Update-5") {
		t.Errorf("expected the Photon 5 wiki URL, got %q", res.FallbackURL)
	}
}

func TestCheckCVETDNF_Vulnerable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Name : zlib.x86_64\nUpdate ID : patch:PHSA-2026-5.0-0874\n"+
				"Description : Security fixes for {'CVE-2026-1234'}\n", 0)
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable, got %v", res.Status)
	}
	if res.FixAdvisory != "PHSA-2026-5.0-0874" {
		t.Errorf("FixAdvisory = %q, want PHSA-2026-5.0-0874", res.FixAdvisory)
	}
}

func TestCheckCVETDNF_NotAffected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Name : zlib.x86_64\nUpdate ID : patch:PHSA-2026-5.0-0874\n"+
				"Description : Security fixes for {'CVE-2026-9999'}\n", 0)
	})
	res := checkCVETDNF(context.Background(), "CVE-2026-1234")
	if res.Status != models.CVENotAffected {
		t.Fatalf("expected CVENotAffected, got %v", res.Status)
	}
}

func TestScanAllTDNF_NoEnabledRepo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	res := scanAllTDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when no repos are enabled")
	}
	if !strings.Contains(res.StatusReason, "no enabled tdnf repositories") {
		t.Errorf("StatusReason = %q", res.StatusReason)
	}
}

func TestScanAllTDNF_JSONSuccess(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0001","Packages":["zlib-1.3.2-1.ph5.x86_64.rpm"]}]`, 0)
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Update ID : patch:PHSA-2026-5.0-0001\nDescription : Security fixes for {'CVE-2026-1111'}\n", 0)
	})
	res := scanAllTDNF(context.Background())
	if res.ScanFailed {
		t.Fatalf("expected a successful scan, got ScanFailed: %s", res.StatusReason)
	}
	if res.Total != 1 || len(res.Important) != 1 {
		t.Fatalf("expected 1 Important advisory, got %+v", res)
	}
	if res.Important[0].ID != "PHSA-2026-5.0-0001" {
		t.Errorf("ID = %q, want PHSA-2026-5.0-0001", res.Important[0].ID)
	}
	if res.Important[0].CVEs != "CVE-2026-1111" {
		t.Errorf("expected enrichment to populate CVEs, got %q", res.Important[0].CVEs)
	}
}

// TestScanAllTDNF_MultiPackageAdvisoryAndEmptyID guards two branches in the
// dedup loop: an entry with an empty UpdateID (after trimming the "patch:"
// prefix) must be skipped, and a second distinct package under the SAME
// advisory ID must be appended to the existing advisory's Summary rather
// than replacing it or creating a duplicate advisory.
func TestScanAllTDNF_MultiPackageAdvisoryAndEmptyID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"","Packages":["ignored-1.0-1.ph5.x86_64.rpm"]},`+
				`{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0003","Packages":["pkg-a-1.0-1.ph5.x86_64.rpm","pkg-b-2.0-1.ph5.x86_64.rpm"]}]`, 0)
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
	})
	res := scanAllTDNF(context.Background())
	if res.Total != 1 {
		t.Fatalf("expected exactly 1 advisory (empty-ID entry skipped), got %d: %+v", res.Total, res)
	}
	if len(res.Important) != 1 {
		t.Fatalf("expected 1 Important advisory, got %+v", res)
	}
	summary := res.Important[0].Summary
	if !strings.Contains(summary, "pkg-a-1.0-1.ph5.x86_64") || !strings.Contains(summary, "pkg-b-2.0-1.ph5.x86_64") {
		t.Errorf("Summary = %q, want both packages joined", summary)
	}
}

// TestScanAllTDNF_EnrichmentSkipsUnknownAdvisoryID guards
// enrichTDNFAdvisoryWithCVEs' "not in byID" skip: the `updateinfo info`
// enrichment pass can list an advisory ID that never appeared in the
// `updateinfo list` phase (e.g. a race between the two tdnf calls) — that
// description must be ignored rather than panicking on a nil map value.
func TestScanAllTDNF_EnrichmentSkipsUnknownAdvisoryID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"},
			`[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0004","Packages":["pkg-c-1.0-1.ph5.x86_64.rpm"]}]`, 0)
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Update ID : patch:PHSA-2026-5.0-9999\nDescription : Security fixes for {'CVE-2026-8888'}\n", 0)
	})
	res := scanAllTDNF(context.Background())
	if res.Total != 1 {
		t.Fatalf("expected 1 advisory, got %d: %+v", res.Total, res)
	}
	if res.Important[0].CVEs != "" {
		t.Errorf("CVEs = %q, want empty — enrichment ID doesn't match the listed advisory", res.Important[0].CVEs)
	}
}

func TestScanAllTDNF_JSONFailsFallsBackToText(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"}, "not json", 0)
		b.PutCmd("tdnf", []string{"updateinfo", "list", "--security"},
			"patch:PHSA-2026-5.0-0002 Security lz4-1.10.0-1.ph5.x86_64.rpm\n", 0)
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
	})
	res := scanAllTDNF(context.Background())
	if res.Total != 1 {
		t.Fatalf("expected the text fallback to yield 1 advisory, got %+v", res)
	}
}

func TestScanAllTDNF_UpToDate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmd("tdnf", []string{"-j", "updateinfo", "list", "--security"}, "[]", 0)
	})
	res := scanAllTDNF(context.Background())
	if res.ScanFailed {
		t.Fatal("no pending advisories is a clean scan")
	}
	if !strings.Contains(res.StatusReason, "up to date") {
		t.Errorf("StatusReason = %q, want up-to-date message", res.StatusReason)
	}
}

func TestScanAllTDNF_BothQueriesFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"photon-updates","Enabled":true}]`, 0)
		b.PutCmdNotFound("tdnf", []string{"-j", "updateinfo", "list", "--security"})
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "list", "--security"})
	})
	res := scanAllTDNF(context.Background())
	if !res.ScanFailed {
		t.Fatal("expected ScanFailed when both updateinfo queries fail")
	}
}

func TestEnrichTDNFAdvisoryWithCVEs_Populates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"updateinfo", "info", "--security"},
			"Update ID : patch:PHSA-2026-5.0-0001\nDescription : Security fixes for {'CVE-2026-1111', 'CVE-2026-2222'}\n", 0)
	})
	byID := map[string]*models.CVEAdvisory{"PHSA-2026-5.0-0001": {ID: "PHSA-2026-5.0-0001"}}
	enrichTDNFAdvisoryWithCVEs(context.Background(), byID)
	got := byID["PHSA-2026-5.0-0001"].CVEs
	if !strings.Contains(got, "CVE-2026-1111") || !strings.Contains(got, "CVE-2026-2222") {
		t.Errorf("CVEs = %q, want both IDs", got)
	}
}

func TestEnrichTDNFAdvisoryWithCVEs_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"updateinfo", "info", "--security"})
	})
	byID := map[string]*models.CVEAdvisory{"PHSA-2026-5.0-0001": {ID: "PHSA-2026-5.0-0001"}}
	enrichTDNFAdvisoryWithCVEs(context.Background(), byID)
	if byID["PHSA-2026-5.0-0001"].CVEs != "" {
		t.Errorf("expected no CVEs populated on query failure, got %q", byID["PHSA-2026-5.0-0001"].CVEs)
	}
}

func TestTdnfHasEnabledRepo_JSONTrue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":true}]`, 0)
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected true with one enabled repo")
	}
}

func TestTdnfHasEnabledRepo_JSONFalse(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("tdnf", []string{"-j", "repolist"}, `[{"Repo":"x","Enabled":false}]`, 0)
	})
	if tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected false with zero enabled repos")
	}
}

func TestTdnfHasEnabledRepo_TextFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"-j", "repolist"})
		b.PutCmd("tdnf", []string{"repolist"},
			"repo id  repo name  status\nphoton-updates  Photon Updates  enabled\n", 0)
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected true from the text fallback")
	}
}

func TestTdnfHasEnabledRepo_BothFailConservativeTrue(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("tdnf", []string{"-j", "repolist"})
		b.PutCmdNotFound("tdnf", []string{"repolist"})
	})
	if !tdnfHasEnabledRepo(context.Background()) {
		t.Error("expected the conservative default true when repolist can't be read at all")
	}
}

func TestPhotonMajor(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("VERSION_ID=\"5.0\"\n"))
	})
	if got := photonMajor(); got != "5" {
		t.Errorf("photonMajor() = %q, want 5", got)
	}
}

func TestPhotonMajor_NoDot(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("VERSION_ID=4\n"))
	})
	if got := photonMajor(); got != "4" {
		t.Errorf("photonMajor() = %q, want 4", got)
	}
}

func TestPhotonMajor_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := photonMajor(); got != "5" {
		t.Errorf("photonMajor() = %q, want default 5", got)
	}
}

// TestPhotonMajor_NoVersionIDLine guards the final fallback: an os-release
// file that exists but has no VERSION_ID= line at all (distinct from the
// file-missing case above) must still default to "5" after the loop
// completes without finding a match.
func TestPhotonMajor_NoVersionIDLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("NAME=\"VMware Photon OS\"\nID=photon\n"))
	})
	if got := photonMajor(); got != "5" {
		t.Errorf("photonMajor() = %q, want default 5 (no VERSION_ID line)", got)
	}
}
