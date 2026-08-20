package cvedata

// wontfix_spec_test.go — specification test for a finding closed WONT_FIX in
// the adversarial review (VERIFICATION-2026-08.md §8, re-framed for release
// in RELEASE-DECISIONS-v1.md). Pins a DECIDED behaviour, not a bug hunt. If
// it fails, either the behaviour drifted or the decision changed — revisit
// the decision before "fixing" the code.
//
// The other half of this finding — that a KEV match unconditionally
// escalates to CRIT, outranking the package manager's own severity — is
// already asserted by TestCheckCVEHealthKEVFiresCrit in
// internal/analysis/heuristics_cve_test.go. Not duplicated here.

import (
	"testing"
)

// implausibleKEV is deliberately NOT the shape a real CISA feed would ever
// have (a date far in the future, a vulnerability name naming a product that
// doesn't exist) — standing in for a fabricated or tampered catalog. Nothing
// about LoadKEV's contract says this should be rejected; that's the point.
const implausibleKEV = `{
  "title": "fabricated catalog — not a real CISA export",
  "catalogVersion": "9999.99.99",
  "dateReleased": "2099-01-01T00:00:00.0000Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2099-00001",
      "vendorProject": "NoSuchVendor",
      "product": "NoSuchProduct",
      "vulnerabilityName": "entirely made up",
      "dateAdded": "2099-01-01",
      "dueDate": "2099-01-02",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}`

// TestSpec_InternalCvedata0106_LoadKEVPerformsNoIntegrityCheck:
// internal-cvedata-01-06 was closed WONT_FIX because closing it needs a
// key-distribution/signing decision (where does a verification key live, how
// is it rotated) that's a product/security-architecture call beyond a
// mechanical remediation pass — see RELEASE-DECISIONS-v1.md's Option C. The
// realistic attacker precondition (local write access to the sidecar path)
// already implies more access than the finding grants, which is why Option A
// ("do nothing") was judged fine for v1. Pending any future decision, LoadKEV
// deliberately performs zero checksum, signature, or plausibility check — a
// file that is merely well-formed JSON is fully trusted, no matter how
// implausible its content. This test documents that: it must NOT start
// silently rejecting oddly-shaped-but-well-formed catalogs (a future
// Option B plausibility check) without the decision being revisited — that
// would be a real behaviour change (operators with legitimately unusual
// catalog files would start losing KEV cross-referencing) hiding inside what
// looks like a routine change.
func TestSpec_InternalCvedata0106_LoadKEVPerformsNoIntegrityCheck(t *testing.T) {
	t.Parallel()
	cat, err := LoadKEV(writeKEV(t, implausibleKEV))
	if err != nil {
		t.Fatalf("LoadKEV rejected a fabricated-but-well-formed catalog: %v — if LoadKEV now "+
			"performs a plausibility/integrity check, internal-cvedata-01-06 may actually be "+
			"fixed (Option B/C); revisit the decision doc rather than just loosening this test", err)
	}
	if cat.Count() != 1 {
		t.Fatalf("Count() = %d, want 1 — the fabricated entry should be indexed exactly like a genuine one", cat.Count())
	}
	if !cat.Contains("CVE-2099-00001") {
		t.Error("Contains(fabricated CVE ID) = false, want true — LoadKEV trusts whatever the file " +
			"says with no independent corroboration")
	}
}
