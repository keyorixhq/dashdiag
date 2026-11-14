# DS1: reachability-first fuzzing for DashDiag (2026-11-14)

Branch `fuzz/reachability-ds1` from `096ef46a` (origin/main). Test and tooling
code only; no production file changed, nothing ships.

Status: campaign complete (101 min on the committed targets, plus 31 min
fuzzing the candidate fixes); final checks at the end of this file.

## Readings taken (nobody to ask)

- No report path was given, so the report lives here, next to the other
  `docs/findings/` reports; reproducers are in `docs/findings/ds1-reproducers/`.
- There is no CLAUDE.md, INVARIANTS.md, `scripts/fuzzing/targets.d/` or
  `changelog.d/` in this repo. Fuzz targets are discovered by
  `scripts/fuzz-discover.sh` and guarded by `fuzz_coverage_test.go`, so no conf
  file is needed. Nothing ships, so no CHANGELOG entry.
- `internal/yamlsafe` does not exist on main. It is the proposed hardening on
  branch `chore/yaml-go-yaml-in` (`cb9cc021`, PR #1179). To fuzz "the
  duplicate-key hardening path" I copied its body verbatim into a test-only
  file (`internal/analysis/yamlsafe_copy_test.go`) that runs on the same library
  (`go.yaml.in/yaml/v3` v3.0.5, already in this module's graph; its `decode.go`
  is byte-identical to the v3.0.6 the branch pins). If #1179 merges, delete the
  copy and point the target at the real package.
- Platform: macOS arm64 host. The five new targets are in untagged files so
  they fuzz natively. Linux semantics (shadow-utils, overmounts) were checked
  in local Docker containers (`debian:stable-slim`, `--network none`).
- "Known defect" properties (the ones that fail on today's code) are gated
  behind `DSD_KNOWN_DEFECTS=1`, so the seed corpus stays green in CI and a fix
  can be proven by flipping one env var. No assertion was weakened: gating
  either skips the whole property or skips a documented input domain.
- Importing `go.yaml.in/yaml/v3` from a test file makes `go mod tidy` want to
  promote it from `// indirect` to direct. I left go.mod untouched (no CI tidy
  check exists); `go.work.sum` gained three checksum lines.
- `go run github.com/JetBrains/go-modern-guidelines@v0.1.1 list` worked (from
  the module cache); its rules were followed in the new files.

## 1. What DashDiag really parses (reachscan)

`scripts/reachscan` (offline, `go/types` with the source importer, no
`x/tools`) lists every function that takes `string`, `[]byte`, `[]string`,
`io.Reader`, `*bufio.Scanner` or `*bufio.Reader` and whose name or body looks
like parsing, ranks by production call sites, and classifies Fuzz reach:
direct (named from a fuzz file), transitive (reached in the static call graph
from something a fuzz file calls), or none.

Run: `go run ./scripts/reachscan -goos linux -top 40`.

GOOS=linux, origin/main: **400 parser candidates; 73 fuzzed directly, 269 only
transitively (inside whole-bundle replay or the taint sweep), 58 not reached at
all.** Library calls on non-constant text: `strconv.Atoi` 176 sites,
`encoding/json.Unmarshal` 84, `strconv.ParseInt` 49, `strconv.ParseUint` 39,
`regexp.FindStringSubmatch` 37, `strconv.ParseFloat` 29, `regexp.MatchString`
24, `time.Parse` 24, `encoding/xml.NewDecoder` 4, `gopkg.in/yaml.v3.Unmarshal`
3, `encoding/xml.Unmarshal` 2, gopsutil `disk.UsageWithContext` 1.

Top 40 parsers without a direct Fuzz target (before this branch):

| # | function | calls | prims | reach | where |
|---|---|---|---|---|---|
| 1 | `cis.checkMountOption` | 19 | 3 | none | internal/cis/rules.go:5652 |
| 2 | `cis.checkAuditRule` | 15 | 4 | none | internal/cis/rules.go:5755 |
| 3 | `cis.checkModuleDisabled` | 14 | 6 | none | internal/cis/rules.go:5616 |
| 4 | `cmd.loadBundle` | 14 | 0 | none | cmd/replay.go:94 |
| 5 | `collectors.parseInt64` | 8 | 2 | transitive | internal/collectors/nvme_linux.go:280 |
| 6 | `cis.checkSysctlGE` | 7 | 3 | none | internal/cis/rules.go:5505 |
| 7 | `cis.checkLoginDefsField` | 6 | 5 | none | internal/cis/rules.go:5460 |
| 8 | `collectors.extractAAField` | 5 | 4 | transitive | internal/collectors/security_linux.go:1299 |
| 9 | `collectors.parseCrontabFileChecked` | 4 | 11 | transitive | internal/collectors/cron_linux.go:213 |
| 10 | `collectors.readJournaldConfig` | 4 | 5 | transitive | internal/collectors/logs_linux.go:784 |
| 11 | `render.logoDataURI` | 4 | 5 | none | internal/render/brand.go:54 |
| 12 | `collectors.readSysfsHexIntOK` | 4 | 4 | transitive | internal/collectors/hba_linux.go:105 |
| 13 | `collectors.naAtoi` | 4 | 3 | transitive | internal/collectors/gpu_linux.go:227 |
| 14 | `collectors.parseLeadingInt` | 4 | 2 | transitive | internal/collectors/vmware_linux.go:301 |
| 15 | `cis.checkRemovableMediaOption` | 3 | 7 | none | internal/cis/rules.go:5693 |
| 16 | `collectors.procUser` | 3 | 5 | transitive | internal/collectors/proc_linux.go:293 |
| 17 | `selfupdate.isCleanRelease` | 3 | 4 | none | internal/selfupdate/selfupdate.go:189 |
| 18 | `collectors.parseMemcachedStats` | 3 | 3 | transitive | internal/collectors/memcached_linux.go:203 |
| 19 | `collectors.countLinesWithPrefix` | 3 | 2 | transitive | internal/collectors/k8s.go:672 |
| 20 | `collectors.parseInt` | 3 | 2 | transitive | internal/collectors/nvme_linux.go:267 |
| 21 | `cvedata.parseEpoch` | 3 | 2 | transitive | internal/cvedata/version.go:60 |
| 22 | `collectors.parseNFTRuleset` | 2 | 10 | transitive | internal/collectors/firewall_linux.go:302 |
| 23 | `collectors.kvmParseBytes` | 2 | 9 | transitive | internal/collectors/kvm_linux.go:476 |
| 24 | `collectors.parseCPURangeCount` | 2 | 9 | transitive | internal/collectors/cpu_topology_linux.go:12 |
| 25 | `collectors.parseIPTList` | 2 | 9 | transitive | internal/collectors/firewall_linux.go:608 |
| 26 | `collectors.parseSSHFileContent` | 2 | 9 | transitive | internal/collectors/security_linux.go:204 |
| 27 | `collectors.bindParseZoneFile` | 2 | 7 | transitive | internal/collectors/bind_linux.go:305 |
| 28 | `collectors.cgroupScopeIn` | 2 | 7 | transitive | internal/collectors/health_deep_linux.go:986 |
| 29 | `collectors.parseProcCPUInfo` | 2 | 7 | transitive | internal/collectors/cpuinfo.go:28 |
| 30 | `collectors.rancherDeployReady` | 2 | 5 | transitive | internal/collectors/rancher_collector.go:55 |
| 31 | `collectors.cumulativeStealPctChecked` | 2 | 4 | transitive | internal/collectors/kvmguest_linux.go:192 |
| 32 | `collectors.firewallBlocksPorts` | 2 | 4 | transitive | internal/collectors/steamos_parse.go:336 |
| 33 | `collectors.ociServiceState` | 2 | 4 | transitive | internal/collectors/oci_linux.go:133 |
| 34 | `collectors.readCgroupMem` | 2 | 4 | transitive | internal/collectors/health_deep_linux.go:882 |
| 35 | `collectors.containerdContainerCountChecked` | 2 | 3 | transitive | internal/collectors/containerd_linux.go:241 |
| 36 | `collectors.containerdNamespacesChecked` | 2 | 3 | transitive | internal/collectors/containerd_linux.go:199 |
| 37 | `collectors.hexToAddr` | 2 | 3 | transitive | internal/collectors/proc_linux.go:438 |
| 38 | `collectors.parseCronLogLine` | 2 | 3 | transitive | internal/collectors/cron_linux.go:413 |
| 39 | `collectors.parsePortRange` | 2 | 3 | transitive | internal/collectors/firewall_linux.go:535 |
| 40 | `collectors.readCgroupCPUStat` | 2 | 3 | transitive | internal/collectors/health_deep_linux.go:848 |

Outside the top 40 but also unreached: `analysis.LoadPolicy` (policy YAML),
`baseline.parseProcStart` / `parseBootTime` (/proc), `store.parseStoreLine`
(history store), `cmd.strictUnmarshal` (capture YAML), `cmd.parseSinceDuration`.

Slide version: *DashDiag has ~400 functions that turn untrusted text into
verdicts. 18% are fuzzed directly, two thirds only ride along inside two
whole-bundle fuzzers, and the most-called unfuzzed ones are the CIS compliance
checks, the code whose PASS a customer shows an auditor.*

After this branch: 77 direct, 276 transitive, 47 none. The scanner's own
blind spot showed up on first contact: the CIS targets reach the checks
through `ruleByID(id).Check(...)`, a func value in the `CISRules` registry, so
the first version still reported them "none". reachscan now adds registry
edges (reading a package-level variable reaches whoever assigns it; naming a
function as a value reaches it); re-run on origin/main this changes nothing
(73/269/58), on this branch it moves the CIS checks to "transitive". It also
marks `checkAuditRule` transitive although no target feeds audit rules: the
registry edge over-approximates. macOS (`-goos darwin`): 171 candidates, 41
direct, 76 transitive, 54 none; the same CIS helpers top that list.

What reachscan does NOT verify: real taint (a parser fed only constants still
ranks), interface method calls, func values passed through parameters, the
precision of the registry approximation (shared variables over-approximate),
name-based fuzz coverage (collisions overstate), one GOOS per run, and it skips
`scripts/` and `internal/testutil`.

## 2. Targets promoted (five)

Chosen from the ranking for: top call-site count with no reach (CIS), the
required duplicate-key path (policy YAML), and three unreached parsers whose
output decides something user-visible (history store, /proc start time).

| target | file | live caller | oracles |
|---|---|---|---|
| `FuzzCISMountRulesMetamorphic` | internal/cis/fuzz_mounts_logindefs_metamorphic_test.go | `dsd cis` -> `cis.Evaluate` (cmd/cis.go:107) -> `Rule.Check` -> checkMountOption / checkSeparateMountPoint / checkRemovableMediaOption | metamorphic x6 + gated overmount |
| `FuzzCISLoginDefsMetamorphic` | same file | `dsd cis` -> rules 5.4.1/5.4.3/5.4.4/5.4.6, V-238380/382/383 -> checkLoginDefsField | metamorphic x2 + gated reference + gated last-wins |
| `FuzzPolicyYAMLDupKeyDifferential` | internal/analysis/policy_yaml_dupkey_fuzz_test.go (+ yamlsafe_copy_test.go) | `dsd health --policy` (cmd/health.go:155 loadPolicyIfSet) and `dsd policy` (cmd/policy.go:42) -> `LoadPolicy` | bounded work (pair count, alloc cap), 3-way differential |
| `FuzzStoreLineDifferential` | internal/store/fuzz_parse_line_differential_test.go | `dsd history` (cmd/history.go:75), `dsd diff` (cmd/diff.go:105), `dsd health --persist` (cmd/health.go:232/245) | differential ReadAll vs parseStoreLine, determinism, round trip |
| `FuzzProcStartDifferential` | internal/baseline/fuzz_procstart_differential_test.go | `dsd health --since-deploy` (cmd/health.go:194) -> RunSinceDeployDiff -> newestProcStart -> parseProcStart | proc(5) reference differential, sanity bound, metamorphic comm, btime round trip |

### Oracles and what each does NOT verify

(Full text is in each target's doc comment; summarised here.)

**FuzzCISMountRulesMetamorphic** — verdicts of all 17 /proc/mounts rules must
not change under: tab- and multi-space-separated fields; reversed option lists;
CRLF; an unrelated mount appended / prepended; (gated, F2) an earlier shadowed
entry for a rule mount point. *Does NOT verify* that a verdict is the right CIS
answer (only that equivalent inputs agree), `\040` escapes, bind mounts or
propagation, or a live /proc/mounts.

**FuzzCISLoginDefsMetamorphic** — comments/blank lines inserted and tab
separation keep every verdict; (gated, F4) a PASS must rest on a strict
in-range integer on the deciding line; (gated, F3) appending non-compliant
lines (the ones shadow-utils applies) must remove every PASS. *Does NOT
verify* hex/octal spellings (shadow parses with base 0; see F4 note),
`/etc/login.defs.d`, PAM overrides, or the CIS thresholds themselves.

**FuzzPolicyYAMLDupKeyDifferential** — (1) when the yamlsafe pre-check
accepts, the library's quadratic duplicate scan must report no more pairs
than the document has keys (PolicyFile and `any` targets); (2) the hardened
path allocates at most 256 KiB + 1 KiB/byte; (3) gopkg.in/yaml.v3 and
go.yaml.in/yaml/v3 agree on accept/reject (after validatePolicy) and value,
and `LoadPolicy` agrees with its library path; (4) yamlsafe accepts what the
library accepts and decodes the same policy, except its own stricter
duplicate error (counted as EXPECTED-DIFFERENCE). Every input is also checked
as "first line repeated 6x as a key". *Does NOT verify* inputs over 2 KiB
(the real cap is 1 MiB; absolute cost is pinned by
TestYamlsafeCopy_QuadraticBypassShapes), error line numbers, ApplyPolicy /
the health gate, the real yamlsafe package (a copy pinned to cb9cc021), or
documents after the first.

**FuzzStoreLineDifferential** — ReadAll on a one-line file returns one entry
iff parseStoreLine accepts, with an identical entry; eight repeated parses
agree; an accepted entry survives json.Marshal -> parse unchanged. *Does NOT
verify* multi-line files, ordering and the n window (FuzzReadAll), lines over
1 MiB, Prune's rewrite and locking, or the vocabulary rules themselves.

**FuzzProcStartDifferential** — against a proc(5) reference (comm to the last
")", field 22 unsigned decimal ticks, USER_HZ 100) the result must match;
an accepted start time is never before boot (overflow domain gated, F6);
swapping comm keeps the start time; btime round trips. *Does NOT verify*
tails containing ")", USER_HZ other than 100, the age filter / newest pick,
or name sanitising on output.

### Red proofs (planted in a scratch copy, never committed)

Driver `.scratch/redproof.sh` copies the tree to `.scratch/rp`, applies one
perl substitution to one file, runs the target's seed corpus there, restores.
Unmodified copy: all five targets green.

| plant | oracle | result |
|---|---|---|
| m-ws: checkMountOption splits on " " | mounts: tab fields | FIRED |
| m-order: option must not be last | mounts: reversed options | FIRED |
| m-crlf: skip lines ending in \r | mounts: CRLF | FIRED |
| m-prepend: stop at the first proc line | mounts: unrelated prepended | FIRED |
| (unmodified, DSD_KNOWN_DEFECTS=1) | mounts: overmount | FIRED (= finding F2) |
| l-comment: no "#" skip, Contains match | login.defs: comments | FIRED |
| l-tab: Split on " " | login.defs: tab fields | FIRED |
| l-range: 5.4.4 accepts 0 | login.defs: reference range | FIRED |
| (unmodified, DSD_KNOWN_DEFECTS=1) | login.defs: last wins | FIRED (= finding F3) |
| p-pairs: pre-check never reports | policy: pair count | FIRED (also re-run after the F1 gate) |
| p-alloc: 8 MiB allocation in yamlsafe | policy: alloc cap | FIRED |
| p-migr: library drops both duplicate checks (replace directive to a patched go.yaml.in copy) | policy: migration differential | FIRED |
| p-live: LoadPolicy skips validatePolicy | policy: LoadPolicy vs library | FIRED |
| p-hard: yamlsafe rejects >=3 keys | policy: hardened vs library | FIRED |
| (unmodified, DSD_KNOWN_DEFECTS=1) | policy: bypass shapes test | FIRED (= finding F1) |
| p-gate: p-pairs again after the F1 shape gate was added | policy: pair count | FIRED (gate does not hide plain duplicates) |
| s-diff: parseStoreLine skips validateEntry | store: differential | FIRED |
| s-det: alternate Hostname suffix | store: determinism | FIRED |
| s-rt: append "_" to Hostname | store: round trip | FIRED |
| b-diff: field 21 instead of 22 | procstart: reference | FIRED |
| b-meta: first ")" instead of last | procstart: reference/comm | FIRED |
| b-sanity: subtract instead of add | procstart: before-boot bound | FIRED |
| b-btime: off by one second | procstart: btime | FIRED |

Green half for the findings (the gated properties fail on today's code and
must pass once fixed): with `proposed-fixes.diff` applied in the scratch copy
and `DSD_KNOWN_DEFECTS=1`, `TestCISKnownFalsePass` (F2, F3, F4),
`TestParseStoreLine_SanitizedCheckKeyCollisionIsDeterministic` (F5),
`TestParseProcStart_StarttimeOverflow` (F6), `TestYamlsafeCopy_QuadraticBypassShapes`
(F1) and the seed corpora of all five targets pass. On the first try the
gated last-wins property still failed on rule 5.4.3 (ENCRYPT_METHOD), which
has the same first-match shape inline and was not yet in the candidate fix,
so the oracle caught the incomplete fix; the patch now covers 5.4.3 too.

## 3. Fuzz campaign (GOMAXPROCS=3, -parallel 2, nice 10, foreground 9-minute chunks)

| target | chunk | real time | execs | result |
|---|---|---|---|---|
| FuzzCISLoginDefsMetamorphic | 0 | 1 s | 615 | F4 found (`PASS_MIN_DAYS 1A0`) |
| FuzzCISLoginDefsMetamorphic | 1 | 9 m | 912 k | clean |
| FuzzPolicyYAMLDupKeyDifferential | 1 | 9 m | 768 k | clean (byte mutation never built 4 equal keys) |
| FuzzStoreLineDifferential | 1 | 9 m | 5.32 M | clean (F5 not rediscovered, see below) |
| FuzzCISMountRulesMetamorphic | 1 | 9 m | 178 k | clean |
| FuzzProcStartDifferential | 0 | 1.3 s | 29 k | F6 found (starttime 1.2e13) |
| FuzzProcStartDifferential | 0b | 112 s | ~1.5 M | harness bug (skip helper ignored ")" in tail), fixed |
| FuzzProcStartDifferential | 1 | 9 m | 8.77 M | clean |
| FuzzPolicyYAMLDupKeyDifferential | 2 (with repeated-key amplification) | 1 s | - | F1 found (`[]` key) |
| FuzzPolicyYAMLDupKeyDifferential | 2b | 9 m | 679 k | clean (no fourth bypass shape) |
| FuzzCISLoginDefsMetamorphic | 2 | 9 m | 787 k | clean |
| FuzzCISMountRulesMetamorphic | 2 | 9 m | 186 k | clean |
| FuzzStoreLineDifferential | 2 | 9 m | 4.31 M | clean |
| FuzzProcStartDifferential | 2 | 9 m | 11.0 M | clean |
| FuzzPolicyYAMLDupKeyDifferential | 3 | 9 m | 689 k | clean |

Totals on the committed targets: **99 minutes of clean chunks plus ~2 minutes
of runs that ended in a hit**, per target: policy 27 min, login.defs 18,
mounts 18, store 18, procstart 18 (+2 min harness-bug run). Each chunk was
`go test ./<pkg> -run '^$' -fuzz '^<Target>$' -fuzztime 9m -parallel 2`
under `GOMAXPROCS=3 nice -n 10`, one at a time, in the foreground; the
GOCACHE corpus carried over between chunks. Mounts is slow (17 rules x 7
variants x a file write per input).

Fix validation in the scratch copy (DSD_KNOWN_DEFECTS=1, so every gated
property is live; fixes = `docs/findings/ds1-reproducers/proposed-fixes.diff`):

| target | real time | execs | result |
|---|---|---|---|
| FuzzPolicyYAMLDupKeyDifferential, with the P1 yamlsafe fix | 9 m | 541 k | clean: the fix closes F1 and introduces no rejection the library would not make |
| FuzzCISMountRulesMetamorphic, with the P2 fix | 5 m | 83 k | clean, overmount property included |
| FuzzCISLoginDefsMetamorphic, with the P3 fix (incl. 5.4.3) | 7.9 m | - | hit: `PASS_MAX_DAYS 0400`; the fix reads octal 256 (shadow-utils does too), the oracle read decimal 400. ARTIFACT: oracle premise error, reference corrected to C strtol base 0 |
| FuzzCISLoginDefsMetamorphic, with the P3 fix, corrected oracle | 9 m | 462 k | clean |

Re-proof after the oracle correction: planting "5.4.4 accepts 0" on top of
the fixed copy fires both gated login.defs oracles; removing the plant is
green, and the `0400` input replays green 3/3.

## 4. Findings

Replays: every fuzzer hit was replayed 3 times from its corpus file (3/3
fail); hand-found ones were replayed 3 times through their pinned test.

| id | class | summary | found by | reproducer | reach |
|---|---|---|---|---|---|
| DS1-F1 | SECURITY-DEFECT (in proposed #1179, not on main) | yamlsafe pre-check is bypassed by NaN keys, merge keys and non-scalar keys: the library still runs its quadratic duplicate scan. 36 KB -> 1.2 GB and ~2 s; the 1 MiB cap allows ~30x the keys | code reading, then confirmed; fuzzer rediscovered the non-scalar shape in 1 s once the repeated-key form was added | `docs/findings/ds1-reproducers/FuzzPolicyYAMLDupKeyDifferential/F1-nonscalar-key-bypass`; `TestYamlsafeCopy_QuadraticBypassShapes` | branch only: LoadPolicy -> yamlsafe.Unmarshal (cb9cc021) <- `dsd health --policy`, `dsd policy` |
| DS1-F2 | SECURITY-DEFECT | CIS 1.1.3-1.1.5, 1.1.14-16, 1.1.29-32 take the FIRST /proc/mounts entry; after an overmount the kernel uses the LAST. Confirmed live: noexec tmpfs overmounted by a plain tmpfs, both listed, binary executed, dsd reports PASS | oracle design (gated property), confirmed in privileged Debian container | `TestCISKnownFalsePass/F2_overmount_hides_noexec` | `dsd cis` -> cis.Evaluate -> checkMountOption |
| DS1-F3 | SECURITY-DEFECT | login.defs: checkLoginDefsField and 5.4.3 take the FIRST assignment; shadow-utils def_load keeps the LAST. `PASS_MAX_DAYS 60` then `PASS_MAX_DAYS 99999` -> dsd PASS, useradd applies 99999 | oracle design, confirmed with shadow-utils 4.17.4 | `TestCISKnownFalsePass/F3_*` | `dsd cis` -> rules 5.4.1/5.4.4/5.4.6/V-2383xx |
| DS1-F4 | SECURITY-DEFECT | `fmt.Sscanf("%d")` accepts a numeric prefix: `PASS_MIN_DAYS 1A0`, `PASS_WARN_AGE 7days`, `PASS_MAX_DAYS 60x` PASS; shadow-utils rejects them ("configuration error - cannot parse") and applies no aging. `PASS_MAX_DAYS -1` (no expiry) also PASSES 5.4.1 and V-238380 | fuzzer, < 1 s | `docs/findings/ds1-reproducers/FuzzCISLoginDefsMetamorphic/F4-trailing-garbage-1A0`; `TestCISKnownFalsePass/F4_*` | same as F3 |
| DS1-F5 | DEFECT | validateEntry strips control characters from Checks keys after decoding, so `disk` and `disk\a` collapse and the surviving status depends on map order: one store line reads back disk=OK on one run, CRIT on the next | code reading (the determinism oracle catches it; 5.3 M fuzz execs did not build the collision) | `TestParseStoreLine_SanitizedCheckKeyCollisionIsDeterministic` | ReadAll <- `dsd history`, `dsd diff`, `dsd health --persist` |
| DS1-F6 | HARDENING | parseProcStart guards NaN/Inf/negative but not size: starttime 1.2e13 ticks overflows time.Duration and yields 1734 (arm64). A real kernel cannot produce it (~292 years uptime); same float->int class as #727 | fuzzer, 1.3 s | `docs/findings/ds1-reproducers/FuzzProcStartDifferential/F6-starttime-overflow`; `TestParseProcStart_StarttimeOverflow` | `dsd health --since-deploy` -> newestProcStart (live /proc only) |
| DS1-F7 | CANDIDATE (SECURITY-DEFECT if confirmed) | sshd_config: parseSSHFileContent lets later lines overwrite earlier ones and the non-root fallback parses sshd_config then drop-ins in glob order; sshd_config(5) says the FIRST obtained value is used. 50-cloud-init.conf `PasswordAuthentication yes` + 99-hardening.conf `no` -> sshd allows passwords, dsd reports disabled | code reading while auditing the F2/F3 class; red in a linux container 3/3; not checked against a live sshd (no openssh-server image offline) | `TestParseSSHFileContent_FirstObtainedValueWins` (linux, gated) | `dsd health` / `dsd cis` non-root -> SecurityCollector -> parseSSHConfig fallback -> parseSSHFileContent |
| DS1-E1 | EXPECTED-DIFFERENCE (doc defect in #1179) | yamlsafe rejects `1: a` / `0x1: b` (decoded keys equal) that the library accepts; its doc says it compares "as they do in the library", but the library compares raw spellings (decode.go mapping(): `ni.Value == nj.Value`) | reading + oracle 4 tally | `"1: a\n0x1: b\n"` seed | branch only |

Not a finding: on main, `LoadPolicy` calls `yaml.Unmarshal` directly, so the
plain duplicate-key quadratic cost (#1179's motivation) is live there today;
#1179 fixes the common shape, F1 is what it misses.

## 5. Issue-ready proposals (no production change made)

Candidate code for P1, P2, P3 (password aging and 5.4.3), P4 and P5 is in
`docs/findings/ds1-reproducers/proposed-fixes.diff` (`git apply --check`
clean against this branch). It was only ever applied in the scratch copy;
P1 patches the test-local yamlsafe copy, so it must be ported to
`internal/yamlsafe/yamlsafe.go` on the #1179 branch.

**P1 (F1) yamlsafe: close the three bypass shapes before #1179 merges.**
In `CheckDuplicateKeys`, (a) key NaN by its canonical string (e.g. `"!!float:nan"`)
instead of the float value; (b) do not skip `<<`: count merge keys like any
scalar (the library rejects two `<<` in one mapping anyway); (c) for non-scalar
keys, either reject them outright for policy files (PolicyFile has no use for
them) or key them by `Kind`+`Value`, exactly what the library compares.
Simplest sound rule: mirror the library's own comparison (`Kind`, `Value`) in
the hash set, then add decoded-value collisions on top. Proof:
`DSD_KNOWN_DEFECTS=1 go test ./internal/analysis -run TestYamlsafeCopy_QuadraticBypassShapes`
goes green; also fix the doc sentence (E1).

**P2 (F2) CIS mount rules: use the last /proc/mounts entry for a mount point.**
In checkMountOption (and checkRemovableMediaOption per mount point), keep
scanning and evaluate the last matching line; checkSeparateMountPoint is
unaffected. Better still, read /proc/self/mountinfo and pick the entry not
covered by a later one. Proof: `TestCISKnownFalsePass/F2*` and the gated
overmount property of FuzzCISMountRulesMetamorphic.

**P3 (F3, F4) login.defs: parse like shadow-utils.** Last assignment wins;
parse the value as a whole token with C strtol base-0 semantics (0x3c is 60,
010 is 8; reject Go-only spellings such as `1_0`, `0o7`); an unparseable
value is "not set" -> FAIL with "invalid value"; `PASS_MAX_DAYS` < 1 (incl.
-1) is non-compliant. Side effect worth noting: today `PASS_MAX_DAYS 0x3c`
reads as 0 and FAILs, and `0400` reads as 400 and FAILs 5.4.1 although
shadow applies 256, so the fix also removes false alarms.
Proof: `TestCISKnownFalsePass/F3*`, `F4*`, and the gated oracles of
FuzzCISLoginDefsMetamorphic. The same first-match shape exists in 5.4.3,
5.4.5 and 5.4.7 (`/etc/default/useradd`); worth auditing together.

**P6 (F7) sshd_config fallback: first obtained value wins.** Track which
keywords have been set and ignore later assignments, across the main file
and the drop-ins; better, follow the `Include` line where it appears in
sshd_config instead of appending drop-ins after it. Confirm first with
`sshd -T` on a host carrying the 50/99 drop-in pair. Proof:
`DSD_KNOWN_DEFECTS=1 go test ./internal/collectors -run TestParseSSHFileContent_FirstObtainedValueWins`
(linux; `make test-linux`-style container).

**P7 (class) add "consumer-semantics precedence" to DEFECT-CLASSES.md.** F2,
F3 and F7 are one class: dsd reads a config with a different precedence
rule from the program that consumes it (kernel mount stack: last on top;
shadow-utils: last assignment; sshd: first obtained). Every config parser
should name its consumer's rule and carry a test with a duplicated key.
Other parsers worth the same check: `/etc/default/useradd` (5.4.5, 5.4.7),
sysctl.d, journald.conf (`readJournaldConfig`), modprobe.d (`checkModuleDisabled`).

**P4 (F5) store: make key sanitising deterministic.** When two Checks keys
collapse to the same sanitised name, keep the worst status (CRIT > WARN >
PENDING > INFO > OK) or reject the line. Proof:
`TestParseStoreLine_SanitizedCheckKeyCollisionIsDeterministic`.

**P5 (F6) since-deploy: bound starttime.** Reject `startTicks/100 >
math.MaxInt64/1e9` (or parse field 22 with `strconv.ParseUint` and compare
in integers). Proof: `TestParseProcStart_StarttimeOverflow`.

## Talk material

DashDiag has about 400 functions that turn untrusted text into verdicts, and
an offline go/types scan shows only 18% are fuzzed directly, with the CIS
compliance checks the most-called of the rest. Crash-only fuzzing would have
found nothing here, because every bug is a parser returning a confident wrong
answer, so each target asks a semantic question instead: does the same fact
written differently change the verdict, does a second parse path agree, does
the work stay linear. The strongest oracles encoded the real consumer's
precedence rule (the kernel's mount stack, shadow-utils' last assignment,
sshd's first value), and a local Docker container confirmed the first two
false PASS verdicts in minutes. Plain byte mutation never built the repeated
keys that break the proposed YAML hardening, until one structured
amplification found the bypass in a second. Red proofs on planted defects
kept the harness honest, and three harness bugs were fixed in the harness
without loosening any assertion, one of them exposed by fuzzing the proposed
fix.

## Final checks (18:58Z)

- `gofmt -l internal scripts cmd`: clean.
- `go vet` on analysis, cis, store, baseline, scripts/reachscan (darwin) and on
  collectors, cis, analysis, store, baseline (linux container): clean.
- `go build ./...`: ok.
- `go test` of analysis, cis, store, baseline and the module root
  (`fuzz_coverage_test.go`: discovery sees all five new targets): ok on darwin;
  seed corpora of all five targets plus the gated tests (skipping) also ok in
  a linux container.
- `golangci-lint run` on the touched packages: 0 issues. `make lint-linux`
  was not run (the dashdiag-dev image is not present locally); the one
  linux-tagged file was vetted in the golang:1.27 container instead.
- Production code: unchanged. Outside test files, docs and
  `scripts/reachscan/`, the branch only adds three checksum lines to
  `go.work.sum`.
- No background processes were started; all fuzzing ran in the foreground.
  `.scratch/` (gitignored) holds logs, the scratch copy and the plant files.

## Files on this branch

- `scripts/reachscan/main.go` — the reachability scan.
- `internal/cis/fuzz_mounts_logindefs_metamorphic_test.go` — two CIS targets, `TestCISKnownFalsePass`.
- `internal/analysis/policy_yaml_dupkey_fuzz_test.go`, `internal/analysis/yamlsafe_copy_test.go` — policy target, yamlsafe copy, `TestYamlsafeCopy_QuadraticBypassShapes`.
- `internal/store/fuzz_parse_line_differential_test.go`, `internal/store/known_defect_checks_collision_test.go`.
- `internal/baseline/fuzz_procstart_differential_test.go`.
- `internal/collectors/ssh_firstmatch_known_defect_linux_test.go`.
- `docs/findings/ds1-reproducers/` — minimised fuzzer reproducers (kept out of
  `testdata/` so seed runs stay green) and `proposed-fixes.diff`.

Run every gated property: `DSD_KNOWN_DEFECTS=1 go test ./internal/cis ./internal/analysis ./internal/store ./internal/baseline`
(fails today, by design) and, on linux, `./internal/collectors -run TestParseSSHFileContent_FirstObtainedValueWins`.
