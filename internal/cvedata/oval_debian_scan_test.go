//go:build linux

package cvedata

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestQueryInstalledDPKG_RealSystem runs the real dpkg-query against this
// container's package database (dpkg-query is present — unlike rpm, which
// these Debian-family containers/CI runners don't ship). Asserting only that
// a well-known always-installed package ("bash") appears keeps this
// deterministic without depending on the full package list's exact contents.
func TestQueryInstalledDPKG_RealSystem(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	pkgs, err := QueryInstalledDPKG(context.Background())
	if err != nil {
		t.Fatalf("QueryInstalledDPKG: %v", err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "bash" {
			found = true
			if p.EVR == "" {
				t.Error("bash entry has empty EVR")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected bash in installed package list (%d packages returned)", len(pkgs))
	}
}

// TestScanUbuntuOVALPackages_RealSystem exercises the full parse + cross-
// reference pipeline against the real dpkg database, using a synthetic OVAL
// fixture pointing at "bash" (always installed on a Debian/Ubuntu base).
func TestScanUbuntuOVALPackages_RealSystem(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-9999"/>
        <advisory><severity>critical</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="bash package in noble is affected and may need fixing."/>
        <criterion comment="some-nonexistent-pkg-xyz package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	path := writeFixture(t, "ubuntu-real.xml", feed)
	results, err := ScanUbuntuOVALPackages(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 1 || results[0].CVEID != "CVE-2030-9999" {
		t.Fatalf("results = %+v, want 1 hit for CVE-2030-9999", results)
	}
	if len(results[0].Components) != 2 {
		t.Errorf("Components = %v, want 2 (both criterion matches, installed or not)", results[0].Components)
	}
	if len(results[0].Installed) != 1 || results[0].Installed[0] != "bash" {
		t.Errorf("Installed = %v, want [bash] (the nonexistent package must not appear)", results[0].Installed)
	}
}

// TestScanUbuntuOVALPackages_ParseError confirms a bad OVAL path/content
// short-circuits before any dpkg query.
func TestScanUbuntuOVALPackages_ParseError(t *testing.T) {
	t.Parallel()
	if _, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "bad.xml", "<broken")); err == nil {
		t.Error("expected error for malformed OVAL XML")
	}
}

// TestScanUbuntuOVALPackages_RejectsOversizedFeed covers the same
// maxDecompressedFeedBytes cap as ParseUbuntuOVAL (ScanUbuntuOVALPackages is
// a separate parse path through parseUbuntuOVALVersionAware, not covered by
// a distinct finding ID but sharing the identical unbounded-decode bug
// pattern). Fails during XML decode, before any dpkg query, so it doesn't
// depend on dpkg-query being installed. Not t.Parallel(): shrinks a package
// global via withShrunkFeedCap.
func TestScanUbuntuOVALPackages_RejectsOversizedFeed(t *testing.T) {
	withShrunkFeedCap(t, 50) // ubuntuOVAL (oval_test.go) is well past this
	if _, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu-scan-big.xml", ubuntuOVAL)); err == nil {
		t.Error("expected ScanUbuntuOVALPackages to reject a feed exceeding the decompressed size cap")
	}
}

// withResolveDpkgQuery swaps resolveDpkgQuery for the duration of the test,
// restoring the original on cleanup. Since internal-cvedata-01-05,
// QueryInstalledDPKG resolves "dpkg-query" via platform.ResolveTrustedTool
// (trusted system dirs, never $PATH), so a fake binary on a PATH-shadowed
// directory no longer reaches exec — tests that need QueryInstalledDPKG to
// see a specific (possibly nonexistent) binary path go through this seam
// instead.
//
// Callers MUST NOT also call t.Parallel(): mutates a package-level var.
func withResolveDpkgQuery(t *testing.T, fn func(string) string) {
	t.Helper()
	orig := resolveDpkgQuery
	resolveDpkgQuery = fn
	t.Cleanup(func() { resolveDpkgQuery = orig })
}

// TestQueryInstalledDPKG_NotAvailable exercises the "dpkg-query failed" error
// branch via a resolveDpkgQuery override pointing at a path that doesn't
// exist — mirrors the rpmUnavailable pattern used for the RHEL/SUSE
// scanners.
func TestQueryInstalledDPKG_NotAvailable(t *testing.T) {
	// Not t.Parallel(): withResolveDpkgQuery mutates a package-level var.
	withResolveDpkgQuery(t, func(string) string {
		return filepath.Join(t.TempDir(), "no-such-dpkg-query")
	})
	if _, err := QueryInstalledDPKG(context.Background()); err == nil {
		t.Error("expected error when dpkg-query cannot be resolved")
	}
}

// TestScanUbuntuOVALPackages_QueryInstalledDPKGFails confirms the dpkg-query
// failure from QueryInstalledDPKG propagates out of the higher-level scan
// (the OVAL parse itself succeeds first).
func TestScanUbuntuOVALPackages_QueryInstalledDPKGFails(t *testing.T) {
	// Not t.Parallel(): withResolveDpkgQuery mutates a package-level var.
	withResolveDpkgQuery(t, func(string) string {
		return filepath.Join(t.TempDir(), "no-such-dpkg-query")
	})
	path := writeFixture(t, "ubuntu-nodpkg.xml", sniffableUbuntuOVAL)
	if _, err := ScanUbuntuOVALPackages(context.Background(), path); err == nil {
		t.Error("expected error when dpkg-query is unavailable to query installed packages")
	}
}

// TestQueryInstalledDPKG_SkipsEmptyPackageName exercises the
// "len(fields) < 1 || fields[0] == \"\" { continue }" guard
// (oval_debian.go:185-186) via a fake dpkg-query pointed to directly through
// resolveDpkgQuery (not PATH — see internal-cvedata-01-05): a blank line
// between two real entries (QueryInstalledDPKG only strings.TrimSpace's the
// whole blob, so an interior blank line survives the split) yields a single
// empty field, which must be dropped rather than producing a package with an
// empty name.
func TestQueryInstalledDPKG_SkipsEmptyPackageName(t *testing.T) {
	// Not t.Parallel(): withResolveDpkgQuery mutates a package-level var.
	dir := t.TempDir()
	path := filepath.Join(dir, "dpkg-query")
	script := "#!/bin/sh\n" +
		"echo 'bash\t5.2.15-2'\n" +
		"echo ''\n" +
		"echo 'coreutils\t9.4-3'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake dpkg-query: %v", err)
	}
	withResolveDpkgQuery(t, func(string) string { return path })
	pkgs, err := QueryInstalledDPKG(context.Background())
	if err != nil {
		t.Fatalf("QueryInstalledDPKG: %v", err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "bash" || pkgs[1].Name != "coreutils" {
		t.Fatalf("pkgs = %+v, want exactly [bash, coreutils] — the interior blank line must be skipped", pkgs)
	}
}

// TestQueryInstalledDPKG_IgnoresPATHHijack is the regression guard for
// internal-cvedata-01-05: with the production resolveDpkgQuery
// (platform.ResolveTrustedTool) in effect, a malicious "dpkg-query" placed in a
// directory that is the ONLY entry on $PATH must never run — the real
// /usr/bin/dpkg-query (present in this container per
// TestQueryInstalledDPKG_RealSystem's own comment) must win regardless of
// $PATH, since ResolveTrustedTool searches fixed trusted directories, not the
// inherited environment.
func TestQueryInstalledDPKG_IgnoresPATHHijack(t *testing.T) {
	// Not t.Parallel(): t.Setenv is incompatible with parallel subtests.
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	fake := filepath.Join(dir, "dpkg-query")
	// /bin/sh and /usr/bin/touch by absolute path: PATH below is restricted to
	// `dir` only, so this script can't rely on PATH resolving its own commands.
	script := "#!/bin/sh\n/usr/bin/touch " + marker + "\necho 'evil\t1.0'\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake dpkg-query: %v", err)
	}
	// Only the malicious directory on PATH — no real dpkg-query reachable via
	// $PATH search, isolating what production resolveDpkgQuery actually does.
	t.Setenv("PATH", dir)

	_, _ = QueryInstalledDPKG(context.Background()) // return value isn't the point — the marker file is

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("QueryInstalledDPKG ran a dpkg-query resolved via $PATH — production resolveDpkgQuery must ignore $PATH")
	}
}

// TestScanUbuntuOVALPackages_OpenError exercises the "opening OVAL" error
// branch (oval_debian.go:349-351): a nonexistent path must return an error.
func TestScanUbuntuOVALPackages_OpenError(t *testing.T) {
	t.Parallel()
	if _, err := ScanUbuntuOVALPackages(context.Background(), "/nonexistent/path/ubuntu.xml"); err == nil {
		t.Error("expected error for nonexistent OVAL path")
	}
}

// TestScanUbuntuOVALPackages_BZ2SuffixUsesBzip2Reader exercises the ".bz2"
// reader-selection branch (oval_debian.go:355-357). Go's stdlib
// compress/bzip2 is decode-only, so real compressed content cannot be
// produced here, but a .bz2-suffixed file with non-bzip2 bytes still
// exercises bzip2.NewReader construction — the subsequent decode error is
// the expected outcome.
func TestScanUbuntuOVALPackages_BZ2SuffixUsesBzip2Reader(t *testing.T) {
	t.Parallel()
	if _, err := ScanUbuntuOVALPackages(context.Background(), writeFixture(t, "ubuntu.xml.bz2", "not real bzip2 data")); err == nil {
		t.Error("expected decode error for non-bzip2 content under .xml.bz2 suffix")
	}
}

// TestScanUbuntuOVALPackages_NoInstalledMatches exercises the "components
// found in OVAL but none are installed" skip branch: the OVAL feed names a
// package that's guaranteed absent from any real system's dpkg database.
func TestScanUbuntuOVALPackages_NoInstalledMatches(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available on this host")
	}
	const feed = `<?xml version="1.0"?>
<oval_definitions>
  <definitions>
    <definition class="vulnerability">
      <metadata>
        <reference source="CVE" ref_id="CVE-2030-4444"/>
        <advisory><severity>high</severity></advisory>
      </metadata>
      <criteria>
        <criterion comment="some-nonexistent-pkg-abc123 package in noble is affected and may need fixing."/>
      </criteria>
    </definition>
  </definitions>
</oval_definitions>`
	path := writeFixture(t, "no-match.xml", feed)
	results, err := ScanUbuntuOVALPackages(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanUbuntuOVALPackages: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %+v, want empty (no installed match for the named package)", results)
	}
}
