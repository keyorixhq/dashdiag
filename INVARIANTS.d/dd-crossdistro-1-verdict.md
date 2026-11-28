# INVARIANTS — DD-CROSSDISTRO-1: cross-distribution package-update verdict

Target: `internal/analysis` · `FuzzPackagesCrossDistroVerdictDifferential`
(packages_crossdistro_verdict_differential_fuzz_linux_test.go, `//go:build linux`).

Scope: the security-update VERDICT must depend on the logical facts (how many
pending security updates, of what severity), NOT on which distribution's package
manager spelled them. The same abstract fact set — N pending security updates of a
NON-CRITICAL severity class — is rendered into FOUR real package-manager dialects
(dnf DNF4 table, apt `apt-get -s upgrade`, zypper `list-patches` pipe table, tdnf
`-j updateinfo` JSON), each driven through the REAL exported collector
(`collectors.PackagesCollector.Collect`, distro chosen via the replay
`<tool> --version` detection seam) and the REAL analyzer (`ApplyThresholds`). No
second parser; no hand-written expected verdict — the oracle is agreement between
four independent production parsers + the one production analyzer on equivalent
input. This is the first target to (a) include **tdnf** in the cross-distro
comparison and (b) compare at the **analysis/verdict** layer, not just collector
fields (the sibling `collectors.FuzzSecurityUpdatesCrossDistroDifferential`
compares dnf/apt/zypper fields only — it cannot reach analysis from `package
collectors` without an import cycle).

- **O1 COUNT (4-way, LOAD-BEARING).** `SecurityUpdates` is equal across
  dnf/apt/zypper/tdnf for the same N. Primary oracle = cross-distro equality; a
  vacuity guard pins dnf to N so `0==0==0==0` cannot pass trivially.
- **O2 VERDICT CLASS (4-way, LOAD-BEARING).** The security-update verdict class
  (worst level among the security-update insights, or "none") is equal across all
  four, and for the chosen non-critical set is WARN when N>0 / "none" when N==0.
- **O3 INSIGHT COUNT (4-way, LOAD-BEARING).** The number of security-update
  insights is equal across all four (exactly 1 when N>0, 0 when N==0).

Oracle direction: only EQUALITY between distributions (and a non-vacuity guard) —
never "must be healthy" — so a correct implementation cannot false-positive. Each
oracle was shown RED under a planted per-distro parser defect and GREEN on shipped
code before being trusted:
- O2 RED: dnf maps Moderate→Critical ("severity one level off") → dnf verdict CRIT
  while apt/zypper/tdnf WARN.
- O1 RED: zypper drops the last record → zypper count N-1.
- O1 RED: apt counts each Inst line twice ("record over-counted") → apt count 2N.
Each reverted; shipped tree GREEN.

Excluded by construction (one dialect cannot express it — listed, not asserted):
- **Critical severity.** apt and tdnf publish no per-advisory CVSS, so
  `securityUpdateInsight` folds every apt/tdnf security update to WARN while
  dnf/zypper escalate Critical→CRIT. A critical update is therefore an EXPECTED
  cross-distro verdict difference, not a bug; the abstract set is non-critical only.
- **DB-health / stale-metadata insights.** Different facts (DB corruption; metadata
  freshness), seeded clean and excluded from the oracle scope (the "security
  update" message predicate), so they can neither mask nor manufacture a divergence.

Does NOT verify: sub-threshold miscounts that keep the same class AND insight count
(e.g. 3 vs 4 non-critical updates — O1 and the field-level 3-way differential own
those); critical-severity verdicts (excluded above); malformed/hostile tool output
(the per-parser replay fuzzers own that); real tool-output DRIFT across tool
versions, LOCALE, or text ENCODINGS (the writers emit one canonical C/UTF-8 byte
shape per dialect); tdnf's text-format fallback and its JSON-vs-text agreement
(owned by `FuzzTDNFUpdateInfoJSONTextDifferential`); exact insight message text;
package-DB health; ESM accounting. A defect in the SHARED analyzer that treats all
four managers identically while keeping class=WARN and count=1 (e.g. a wrong number
in the message text) is invisible to this cross-distro differential by design — it
is not a divergence.
