# FINDING: tdnf/networkctl JSON parsers silently accept a schema-mismatched payload, hiding real advisories/link failures

**Date:** 2026-09-23
**Severity:** Medium (a diagnostic tool producing a false "no pending security
advisories" / false "no failed links" verdict — silent under-reporting, not a
crash or data exposure)
**Status:** fixed, tests added, same branch
**Component:** `internal/collectors/cve_linux.go` (`parseTDNFUpdateInfoJSON`,
`scanAllTDNF`), `internal/collectors/packages_linux.go` (`collectTDNF`),
`internal/collectors/networkd_config_linux.go` (`parseNetworkctlLinksJSON`)

## Summary

Both `dsd cve --all` (Photon OS, via `tdnf`) and the networkd link-health
check (via `networkctl`) prefer a JSON tool invocation and fall back to
parsing the tool's plain-text output when the JSON call fails. The fallback
decision was gated ONLY on "did `json.Unmarshal` return an error" — never on
whether the successfully-decoded JSON was structurally usable. A tdnf/systemd
version that renamed, dropped, or omitted a field (a schema drift, not a
syntax error) produced a syntactically valid JSON array that unmarshalled
into zero-value struct fields. Both call sites treated that as success and
never consulted the text form, so a host with real pending security
advisories (tdnf) or a real failed network link (networkctl) could report
**zero findings** — a false-negative on exactly the classes of finding these
collectors exist to surface.

### tdnf (`parseTDNFUpdateInfoJSON`, `internal/collectors/cve_linux.go:1443`)

```go
func parseTDNFUpdateInfoJSON(out string) (entries []tdnfUpdateInfoEntry, parsed bool) {
	start := strings.Index(out, "[")
	end := strings.LastIndex(out, "]")
	if start < 0 || end <= start {
		return nil, false
	}
	if err := json.Unmarshal([]byte(out[start:end+1]), &entries); err != nil {
		return nil, false
	}
	return entries, true // <-- no structural validation
}
```

A payload like `[{"Type":"Security","AdvisoryID":"patch:PHSA-...","Packages":[...]}]`
(the real key `UpdateID` renamed to `AdvisoryID`) unmarshals cleanly —
`json.Unmarshal` leaves unknown target fields at their zero value rather than
erroring — so every entry gets `UpdateID: ""`. `scanAllTDNF`'s dedup loop
(cve_linux.go:1409) already special-cased `id == ""` to skip an entry
(originally meant for a single occasionally-blank advisory), but with a
renamed key ALL entries hit that skip, `scanAllTDNF` never falls back to
text, and the result is "no pending security advisories — system is up to
date" while the text form of the identical state shows real ones.

### networkctl (`parseNetworkctlLinksJSON`, `internal/collectors/networkd_config_linux.go:137`)

Same shape: `AdministrativeState` renamed/dropped left every link's `Setup`
field `""`, which never matches `"failed"` or `"configuring"` in
`classifyNetworkdLinks`, so a genuinely failed link produced zero `FailedLinks`
and no WARN — while `collectNetworkdLinks` never fell back to the text
`networkctl list` output because the JSON parse still returned a non-nil
result.

## Evidence

Found via a differential fuzz harness comparing dashdiag's JSON and text
parsers of the same rendered state
(`internal/collectors/fuzz_tdnf_differential_linux_test.go`,
`internal/collectors/fuzz_networkd_differential_linux_test.go`). Minimized
repros (pre-fix):

- tdnf: `spec="PHSA-2026-5.0-0874|Security|zlib-1.3.2-1.ph5.x86_64.rpm"`,
  variant=renamed-`UpdateID`-key → JSON path reports 0 advisories, text path
  reports 1.
- networkctl: `spec="eth0|no-carrier|failed"`, variant=renamed-
  `AdministrativeState`-key → JSON path reports 0 failed links, text path
  reports 1.

Deterministic regression tests (post-fix, all pass):
`TestParseTDNFUpdateInfoJSON_SchemaValidity`,
`TestScanAllTDNF_JSONMissingFieldFallsBackToText`,
`TestScanAllTDNF_RenamedKeyJSONSameVerdictAsTextAlone`,
`TestParseNetworkctlLinksJSON_SchemaValidity`. Both fuzz harnesses now carry
the renamed-key case as a permanent seed.

Also validated against a real, non-empty capture from a live Photon 5.0 host
(29 raw entries / 21 deduped advisories,
`testdata/differential/tdnf/photon5.0-vm-20260923.json`): the fix does not
regress a well-formed real payload — `TestTDNFDifferentialRealPairs` asserts
`parsed == true` (JSON path genuinely used, no spurious fallback) and the
same 21 advisories as before.

## Fix

`parseTDNFUpdateInfoJSON` and `parseNetworkctlLinksJSON` now validate every
element of a non-empty array against the fields the verdict (and the text
parser) actually needs — tdnf: `UpdateID`, `Type`, non-empty `Packages`;
networkctl: `Name`, `OperationalState`, `AdministrativeState`. Any single
element missing a required field distrusts the WHOLE payload (no partial
acceptance — a schema change affects every element the same way, so keeping
the elements that happen to look fine is not safer), and the caller falls
back to text. A genuinely **empty** array is unaffected and stays trusted
with no fallback — that's tdnf/networkctl's correct "nothing to report"
answer, not a schema mismatch, and must not be treated as one (an earlier
draft of the fuzz harness conflated the two; the harness's renderer no longer
fabricates that impossible state).

`scanAllTDNF` now logs one `debug.Log` line naming the missing field when it
falls back for this reason (`internal/debug`, stderr-only, `--debug`-gated),
so an operator can tell a tdnf schema change happened rather than assuming a
transient parse failure.

### Behavior change

`TestScanAllTDNF_MultiPackageAdvisoryAndEmptyID` previously asserted that a
lone entry with an empty `UpdateID`, mixed into an otherwise-valid array, was
skipped while the rest of the array was still trusted. That was the exact gap
this finding closes — an empty `UpdateID` is indistinguishable from a
renamed/dropped key from the parser's side, so it can no longer be
partially tolerated. That scenario moved to
`TestScanAllTDNF_JSONMissingFieldFallsBackToText`, which now asserts the
correct behavior: the whole JSON payload is distrusted and the advisory is
recovered from the text fallback instead.

## Tracking

Fix and tests are in this same branch/PR. `collectTDNF`
(`internal/collectors/packages_linux.go`, the `dsd packages`/security-update
count path) shares `parseTDNFUpdateInfoJSON` and gets the same correctness
fix automatically; it was not given its own debug-log line since only
`scanAllTDNF`'s CVE path was asked to log.
