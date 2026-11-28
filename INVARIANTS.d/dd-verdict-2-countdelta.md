# INVARIANTS — DD-VERDICT-2 Part A/B: whole-bundle replay "+1" count delta

Targets: `cmd` · `FuzzWholeBundleReplayCountDelta`
(`cmd/replay_wholebundle_countdelta_fuzz_test.go`) — oracle 4 for the whole-bundle
replay fuzzer, the POSITIVE half of the metamorphic pair whose NEUTRAL half is
`FuzzWholeBundleReplayVerdictFlip` (oracle 3). Same fixed baseline bundle
(`buildBundleFrom(seamDefaults())`), same no-second-implementation discipline.

Scope: from the fixed benign baseline bundle, add EXACTLY ONE well-formed record to a
seam, decoded from fuzz bytes within a grammar that is VALID BY CONSTRUCTION (the
fuzz bytes fill a NON-counted free slot via `sanitizeCountToken`; the counted quantity
is fixed), and assert the seam's reported count rises by EXACTLY ONE, and the overall
verdict class never DECREASES.

Seams and the exact parse lines the +1 relies on:

- **D1 dnf (`PackagesInfo.SecurityUpdates`, LOAD-BEARING).** One DNF4 advisory line
  `FUZZ-<f> <sev>/Sec. pkg-<g>`. `packages_linux.go:364` `Fields()` → 3 fields;
  `:365` len<3 skip does not fire; `:373` DNF4 branch (fields[1] contains "/"); `:397`
  `SecurityUpdates++` runs unconditionally per non-skipped advisory → +1 for any
  severity the fuzz byte selects.
- **D2 edac-ce (`MemoryInfo.CorrectedErrors`, LOAD-BEARING).** One controller
  `mcf<suffix>` ce_count=1, ue_count=0. `edac_linux.go:37` HasPrefix "mc" (the "mcf"
  prefix is never mc0/mc1 → a new controller); `:43` fileExists ce_count; `:47-48`
  readEDACCounter; `:53` `corrected += 1`.
- **D3 edac-ue (`MemoryInfo.UncorrectedErrors`, LOAD-BEARING).** One controller
  `mcu<suffix>` ce_count=0, ue_count=1. ce_count=0 is a readable counter (`:47-51` do
  NOT skip it as unreadable), contributing 0 corrected; `:54` `uncorrected += 1`.
  Baseline UncorrectedErrors is legitimately 0 — "produced" is `EDACAvailable` (the
  seam ran), so the zero-baseline +1 is non-vacuous.
- **D4 smart (`sum DiskInfo.Drives[].SMART.MediaErrors`, LOAD-BEARING).** One SATA
  failure-attribute line, NAME contains `offline_uncorrectable`, RAW_VALUE=1 last of
  >=10 fields. `disk_linux.go:343` isSATAFailureAttr; `:263` len>=10 (the fixed
  "F"-prefixed id keeps column 0 non-empty); `:264-265` `MediaErrors += 1`.

Positive control (run once, before `f.Fuzz`): the baseline verdict is non-trivial
(WARN, headroom to escalate) AND every seam produces its countable observable, so
"+1" can never pass vacuously. A per-iteration vacuity guard re-checks after each
mutation (a mutation that broke collection fails rather than trivially "not +1"-ing).

Red/green (throwaway, never committed): a per-record OVERCOUNT (`SecurityUpdates`
doubled) and a DROPPED-RECORD miscount (collapse consecutive same-severity advisories)
in `collectDNF` each made the dnf +1 oracle go RED (got base+2 / base+0); an EDAC
`uncorrected += ue` double made edac-ue go RED. GREEN with the shipped parsers.

Does NOT verify: constant-offset miscounts — a defect that adds the SAME error to BOTH
the baseline and the baseline+1 run (e.g. "always miscount by one", "drop a fixed
position") is a pure offset the DELTA oracle cannot see; that class is for the
per-collector parser fuzzers, not this harness. Also NOT verified: per-severity bucket
accounting (only aggregate `SecurityUpdates`); NVMe media errors (the colon/value
assignment branch, not the SATA sum); insight TEXT / rendered prose; that the verdict
class is EXACTLY right (only that adding a record never lowers it); and "+N" for N>1
(each mutation adds exactly one record by construction).
