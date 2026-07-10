//go:build linux

package collectors

import (
	"strings"
	"testing"
)

// Captured verbatim from `tdnf -j updateinfo list --security` on VMware Photon OS
// 5.0 (PhotonOS-001, 2026-06-27). One JSON record per affected package; several
// share an UpdateID (a PHSA advisory).
const tdnfUpdateInfoJSONFixture = `[{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0874","Packages":["zlib-1.3.2-1.ph5.x86_64.rpm"]},{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0830","Packages":["xz-libs-5.4.0-6.ph5.x86_64.rpm"]},{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0830","Packages":["xz-5.4.0-6.ph5.x86_64.rpm"]},{"Type":"Security","UpdateID":"patch:PHSA-2026-5.0-0801","Packages":["nss-3.78-12.ph5.x86_64.rpm"]}]`

// Captured verbatim from `tdnf updateinfo list --security` (plain text).
const tdnfUpdateInfoTextFixture = `patch:PHSA-2026-5.0-0874 Security zlib-1.3.2-1.ph5.x86_64.rpm
patch:PHSA-2026-5.0-0830 Security xz-libs-5.4.0-6.ph5.x86_64.rpm
patch:PHSA-2026-5.0-0830 Security xz-5.4.0-6.ph5.x86_64.rpm
patch:PHSA-2025-5.0-0677 Security lz4-1.10.0-1.ph5.x86_64.rpm`

func TestParseTDNFUpdateInfoJSON(t *testing.T) {
	entries, ok := parseTDNFUpdateInfoJSON(tdnfUpdateInfoJSONFixture)
	if !ok {
		t.Fatal("expected JSON to parse")
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d", len(entries))
	}
	if entries[0].UpdateID != "patch:PHSA-2026-5.0-0874" || entries[0].Packages[0] != "zlib-1.3.2-1.ph5.x86_64.rpm" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
}

// tdnf may print a metadata-refresh line before the JSON array — the parser must
// isolate the array rather than choke on the prefix.
func TestParseTDNFUpdateInfoJSON_RefreshNoisePrefix(t *testing.T) {
	noisy := "Refreshing metadata for: 'VMware Photon Linux 5.0 (x86_64) Updates'\n" + tdnfUpdateInfoJSONFixture
	entries, ok := parseTDNFUpdateInfoJSON(noisy)
	if !ok || len(entries) != 4 {
		t.Fatalf("want 4 entries past refresh noise, ok=%v got %d", ok, len(entries))
	}
}

func TestParseTDNFUpdateInfoJSON_NotJSON(t *testing.T) {
	if _, ok := parseTDNFUpdateInfoJSON("0 Security notice(s)"); ok {
		t.Error("non-JSON output must report parsed=false so the caller falls back to text")
	}
}

// TestParseTDNFUpdateInfoJSON_BracketsPresentButInvalidJSON guards the
// json.Unmarshal error branch specifically: output that DOES contain a
// '['...']' span (so the bracket-index early return doesn't fire) but whose
// content isn't valid JSON must still report parsed=false.
func TestParseTDNFUpdateInfoJSON_BracketsPresentButInvalidJSON(t *testing.T) {
	if _, ok := parseTDNFUpdateInfoJSON("some text [not, valid, json} more text]"); ok {
		t.Error("malformed JSON between brackets must report parsed=false")
	}
}

func TestParseTDNFUpdateInfoText(t *testing.T) {
	entries := parseTDNFUpdateInfoText(tdnfUpdateInfoTextFixture)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries, got %d", len(entries))
	}
	if entries[3].UpdateID != "patch:PHSA-2025-5.0-0677" || entries[3].Packages[0] != "lz4-1.10.0-1.ph5.x86_64.rpm" {
		t.Errorf("unexpected last entry: %+v", entries[3])
	}
	// Non-advisory lines (no "patch:" prefix) must be skipped.
	if got := parseTDNFUpdateInfoText("Refreshing metadata\n\nrandom noise"); len(got) != 0 {
		t.Errorf("non-patch lines must be skipped, got %d entries", len(got))
	}
}

func TestTdnfTrimPatchPrefix(t *testing.T) {
	if got := tdnfTrimPatchPrefix("patch:PHSA-2026-5.0-0874"); got != "PHSA-2026-5.0-0874" {
		t.Errorf("want bare PHSA id, got %q", got)
	}
	if got := tdnfTrimPatchPrefix("PHSA-2026-5.0-0874"); got != "PHSA-2026-5.0-0874" {
		t.Errorf("already-bare id must pass through, got %q", got)
	}
}

// The captured `tdnf updateinfo info --security` Description carries the CVE IDs.
// Confirm the regex used by enrichment/checkCVETDNF extracts them.
func TestTDNFDescriptionCVEExtraction(t *testing.T) {
	desc := "Description : Security fixes for {'CVE-2026-11822', 'CVE-2026-11824'}"
	got := cveIDPattern.FindAllString(desc, -1)
	if len(got) != 2 || !strings.Contains(strings.Join(got, ","), "CVE-2026-11824") {
		t.Errorf("want both CVEs extracted, got %v", got)
	}
}

// Captured verbatim from `tdnf -j repolist` on VMware Photon OS 5.0.
const tdnfRepolistJSONFixture = `[{"Repo":"photon-updates","RepoName":"VMware Photon Linux 5.0 (x86_64) Updates","Enabled":true}]`

func TestParseTDNFEnabledReposJSON(t *testing.T) {
	n, ok := parseTDNFEnabledReposJSON(tdnfRepolistJSONFixture)
	if !ok || n != 1 {
		t.Fatalf("want 1 enabled repo, got n=%d ok=%v", n, ok)
	}
	// All repos disabled → 0 (the false-OK condition the gate guards).
	if n, ok := parseTDNFEnabledReposJSON(`[{"Repo":"x","RepoName":"X","Enabled":false}]`); !ok || n != 0 {
		t.Errorf("disabled-only must be 0 enabled, got n=%d ok=%v", n, ok)
	}
	// Empty repo set → 0.
	if n, ok := parseTDNFEnabledReposJSON(`[]`); !ok || n != 0 {
		t.Errorf("empty repolist must be 0, got n=%d ok=%v", n, ok)
	}
	// Garbage → ok=false so the caller falls back to text.
	if _, ok := parseTDNFEnabledReposJSON("not json"); ok {
		t.Error("non-JSON must report ok=false")
	}
}

func TestParseTDNFEnabledReposText(t *testing.T) {
	const out = "repo id             repo name                                status\n" +
		"photon-updates      VMware Photon Linux 5.0 (x86_64) Updates enabled\n"
	if got := parseTDNFEnabledReposText(out); got != 1 {
		t.Fatalf("want 1 enabled repo from text, got %d", got)
	}
	// Header-only (no enabled repos) → 0.
	if got := parseTDNFEnabledReposText("repo id  repo name  status\n"); got != 0 {
		t.Errorf("header-only must be 0, got %d", got)
	}
}
