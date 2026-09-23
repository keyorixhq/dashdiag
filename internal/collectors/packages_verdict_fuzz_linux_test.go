//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fuzzes the pure parsers behind dashdiag's security-update verdict — the
// apt and tdnf paths that increment PackagesInfo.SecurityUpdates. These run on
// attacker-controlled tool output whenever `dsd replay` serves a crafted
// bundle's recorded apt/tdnf stdout (Replay.Run). No trust decision is made, so
// the property is not a rejection oracle: it is "never panics; a malformed line
// or advisory blob is skipped, not fatal." Guaranteed reachability (pure
// functions, no source/precondition plumbing) — the complement to the
// collectDNF replay harness, which covers the inline DNF parse loop.

// FuzzAptAccumulateUpdate fuzzes the per-line apt updater — the whole apt branch
// of the SecurityUpdates verdict. criticalPkgs only gates severity, so any map
// exercises the path.
func FuzzAptAccumulateUpdate(f *testing.F) {
	f.Add("openssl/jammy-security 3.0.2-0ubuntu1 amd64 [upgradable from: 3.0.1]")
	f.Add("Inst linux-image-generic [5.15.0.1] (5.15.0.2 Ubuntu:22.04/jammy-security [amd64])")
	f.Add("curl/jammy-updates 7.81.0 amd64")
	f.Add("")
	f.Add("a b")
	f.Add("many\t\t\tfields   with\ttabs\t\t")
	criticalPkgs := map[string]bool{"linux": true, "openssl": true, "openssh": true, "glibc": true, "curl": true}
	f.Fuzz(func(t *testing.T, line string) {
		info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
		aptAccumulateUpdate(info, criticalPkgs, line) // must not panic
	})
}

// FuzzParseTDNFUpdateInfo fuzzes both the JSON and text tdnf updateinfo parsers
// (Photon OS security advisories → SecurityUpdates).
func FuzzParseTDNFUpdateInfo(f *testing.F) {
	f.Add(`[{"UpdateID":"PHSA-2024-0001","Packages":["openssl-1.1.1w.rpm"]}]`)
	f.Add("PHSA-2024-0001  Important  openssl-1.1.1w\n")
	f.Add("")
	f.Add("not json {[}")
	f.Add("only-one-field\n")
	f.Fuzz(func(t *testing.T, out string) {
		_, _, _ = parseTDNFUpdateInfoJSON(out)
		_ = parseTDNFUpdateInfoText(out) // must not panic
	})
}

// FuzzParseTDNFEnabledRepos fuzzes both tdnf repolist parsers (the enabled-repo
// gate that decides "could not verify" vs a real scan).
func FuzzParseTDNFEnabledRepos(f *testing.F) {
	f.Add(`[{"Name":"photon-updates","Enabled":true}]`)
	f.Add("photon-updates   Photon Updates   enabled\n")
	f.Add("")
	f.Add("{bad json")
	f.Fuzz(func(t *testing.T, out string) {
		_, _ = parseTDNFEnabledReposJSON(out)
		_ = parseTDNFEnabledReposText(out) // must not panic
	})
}
