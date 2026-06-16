# Work Queue — Open items by subsystem

Forward-looking index. BUGS.md stays the per-platform discovery log; this file
groups everything *open* by shared code surface + shared test target, so one
branch closes one class with one deploy/validate cycle. Demand-gated items are
listed for visibility only — grouping here is NOT a build trigger
(COMPANY_PRINCIPLES Principle 3, BACKLOG.md hard rule).

Status legend: **READY** (validated bug, build anytime) · **BLOCKED** (needs
hardware/decision) · **GATED** (demand-gated, build only on pull).

---

## A. Fix-hint platform correctness — ✅ DONE (#218, 2026-06-13)

All four items shipped in #218 and validated live (macOS native + Alpine/OpenRC
CT210): the platform-aware hint helper, the audit of direct-print remedy lines
(`dsd docker`/`cron`/`kvm`/`proc` + entropy correlation → `analysis.PlatformServiceCmd`),
and the idle-timeout-on-no-sshd gate. Left below for history.

Diagnosis is platform-correct; the remedy text is not. One class, one branch.

| Item | Surface | Test target |
|---|---|---|
| BUG-053 — `ss -tlnp` hint on macOS | hardening hints, heuristics.go | macOS native build |
| BUG-054 — `systemctl`/journald hints on Alpine/OpenRC | hardening + logs hints | Alpine CT210 |
| Audit: all hardcoded `ss` / `systemctl` / `/etc/systemd/*` hint strings | repo-wide grep of hint text | n/a (code review) |
| Minor: "SSH idle timeout not set" INFO on hosts with no sshd | hardening check gate | Alpine CT210 |

Shared work: a platform-aware hint helper (GOOS + init-system branch — init
detection already exists from the Alpine hardening pass). Fix the helper once,
route all hints through it, validate on macOS + CT210 in one pass.

---

## B. ARM real-hardware validation — BLOCKED (needs aarch64 server)

Software pass done (2026-06-10); Graviton2 confirmed CPU id + health clean.
Container-unverifiable paths remain (BUGS.md ARM section, PLATFORM_COVERAGE.md):

1. Thermal — /sys/class/hwmon SoC sensors
2. DMI/SMBIOS — real system product name (`dsd inventory`)
3. SMART on real NVMe/SAS; EDAC/ECC; IPMI/BMC
4. cpufreq governors / per-core scaling on many-core Ampere
5. Ampere SoC implementer id (0x41 vs 0xc0) — pin a fixture from real Altra

Unblock paths: offered Ampere Altra box, Oracle always-free Ampere, or RPi
(partial — covers thermal/cpufreq, not IPMI/EDAC). One SSH session closes the
whole class; keep as a single validation checklist, not five tasks.

---

## C. Cloud-depth collectors — GATED (no cloud customer yet)

Fully specced in BACKLOG.md (AWS Nitro core ~5–6 checks, Azure Hyper-V core
~5–7, full-coverage tiers beyond). Do not build from this index. When a
customer pulls a specific check, build that check only; the customer reveals
which of the core list matters next. Basic cloud *detection* is already
validated (AWS + Azure captures, NVMe-timeout insight).

---

## D. Deferred architecture / features — BLOCKED on decision or demand

| Item | Ref | Gate |
|---|---|---|
| state.Store + JSONL storage (correlation v2 / drift) | Gap Spec 9, CLAUDE.md | Decide before correlation work hardens around stateless assumptions |
| platform.Profile | Spec 8 | Architectural, deferred |
| `dsd capture --cve`, `--timeline` | session notes | Demand |
| containerd standalone detection | session notes | Demand, low priority |
| `--share`/`--push` backend (sanitization lives here, not in capture) | ADR-0002 D6, SHARE_DESIGN.md | Pilot/demand |

---

## E. Recurring audit plays (not tasks — repeatable sweeps)

These found BUG-040–052; re-run after any collector/heuristic change:

1. **False-OK sweep** — "couldn't verify" must never render as OK/green.
   7 grep-able anti-patterns in agent memory `false-ok-bug-class`.
2. **Stale-signal recency gate** — cumulative counters (NRestarts, pstore)
   reported as current. Ask "where else?" — BUG-047/049 hid one file away.
3. **Sibling divergence diff** — same fact, two code paths, two verdicts
   (BUG-050 `cmd/disk.go` vs health thresholds). Diff cmd/* against analysis/.

---

## F. GPU sensor-read false-OK — ✅ DONE (#c784f68, 2026-06-16)

Closed by real-hardware validation on the new Ubuntu-on-MacBookAir4,2 node
(192.168.10.7): Intel HD 3000 / i915 exposes no hwmon temp by design, and
`dsd gpu` was rendering "✅ GPU healthy. Checks passed" for a GPU whose
temp/util/mem/power all read 0 — asserting health it never measured. The new
node was exactly the GPU observation this entry was BLOCKED waiting for (it
needed *any* real iGPU with all-zero sensors, not specifically AMD). Fix took
the narrow path predicted below: `gpuSummaryLine` now reports "GPU detected — no
health metrics exposed; health not verified" (INFO) when EVERY device exposed
zero metrics; a GPU with any real metric still summarizes healthy. Left below
for history.

A 2026-06-13 false-OK sweep verified a real path: a detected AMD/Intel GPU whose
sysfs sensors all read 0 (temperature never read) still renders `dsd gpu` →
"✅ GPU healthy. Checks passed" and emits no health insight (`collectAMDGPUs`/
`collectIntelGPUs` always append the device; `checkGPU` only skips on `len==0`;
every threshold no-ops on 0; `gpuSummaryLine` default asserts "Checks passed").

**Not blind-fixed** — the obvious fix (per-device INFO "temperature not readable")
is noisy on the many normal Intel iGPUs that don't expose hwmon temp by design, and
there's no clean sysfs signal to tell "sensor broken" (rare, real) from "GPU exposes
no temp" (common, fine). Unlike drives (BUG-048: `/sys/class/nvme` exists without
nvme-cli = clean signal), GPU has none.

| Item | Surface | Test target |
|---|---|---|
| Confirm a healthy AMD GPU actually reads temp (expected yes) | gpu_linux.go | AMD laptop testbed |
| If a clean "read nothing" signal exists → narrow guard: don't claim "Checks passed" when no device had a readable temp | cmd/gpu.go gpuSummaryLine + checkGPU | AMD laptop |

Unblock: one session on the AMD laptop. Agent memory: `gpu-allzero-falseok-deferred`.

---

## G. Debian/Ubuntu OVAL version-awareness — BLOCKED (needs real Ubuntu OVAL fixtures)

The dpkg version comparator (`analysis`/`cvedata` `CompareDpkg`, #231) is built and
verified against the real `dpkg --compare-versions` tool — but deliberately **not
wired** into the Ubuntu/Debian OVAL scan. That scan (`ScanUbuntuOVALPackages`) is
name-based today: it matches an affected package by NAME and ignores the installed
version, so it can over-report a CVE that a newer install already patched.

| Item | Surface | Test target |
|---|---|---|
| Extract per-component fixed version from Ubuntu OVAL | `cvedata/oval_debian.go` `ParseUbuntuOVAL` | real Ubuntu OVAL feed |
| Wire `CompareDpkg(installed, fixedIn)` into the affected/not-affected decision | `ScanUbuntuOVALPackages` | Debian/Ubuntu host |
| Validate no false-negatives introduced (the dangerous direction) | both | real OVAL fixtures |

Why blocked, not just unstarted: name-based over-reporting is a SAFE false-positive;
version-aware matching risks a **false-OK** (silently suppressing a real CVE) if the
fixed-version extraction is wrong. Per the project's deferred-OVAL caution
(agent memory `oval-boolean-tree-deferred`), this needs a real Ubuntu OVAL feed to
validate against before shipping — do not wire it blind. The comparator is proven; the
risk is entirely in the OVAL parsing + the suppress decision.

---

## H. `dsd replay` not fully hermetic — ✅ DONE for default capture path (2026-06-16)

Closed across #339–#349. The double-replay-diff (capture once, replay `--json`
twice, normalise, diff) now shows **zero non-volatile differences** for the default
`dsd health` capture path. Every live input it touches is recorded and replayed:
`os.ReadFile`/`Glob`/`ReadDir`/`Readlink` (#339–#343), `os.Stat` gates via a new
`Source.Stat` (#340–#341), `syscall.Statfs` via `Source.Statfs` (#344), gopsutil via
a generic `Source.Cached` (#345), ping+DNS (#346), service-collector dials +
HTTP/socket APIs incl. docker `apiGet` and cloud IMDS (#347, #349), and disk/multipath
device-list ordering (#348). Mechanism + the "no live I/O outside Source" grep
invariant are in WORKQUEUE.md and the agent's `replay-fidelity-stat-surface` memory.

Deferred (consistent scoping — NOT in the default capture path): NFS reachability
dials and `tls_remote` `--endpoint` dials (opt-in/deep); `ServicesCollector`
(config-gated). The `ServicesCollector` + cloudmeta AWS IMDSv2 token/termination
caching is staged on the in-progress `fix/replay-services` branch (see WORKQUEUE.md).
Left below for history.

## H (history). `dsd replay` not fully hermetic — READY (correctness gap in shipped feature)

`dsd replay <bundle>` promises (help text) that "every collector reads from the
bundle instead of the live system" so hardware-specific bugs reproduce on any
machine. Validated 2026-06-16 (CT201, main `01734ff`): replaying the *same* raw
bundle twice produced differing output on live-sampled fields —
`rx_packets`/`tx_packets`, `gateway_ping_ms`/`internet_ping_ms`, memory
free/used, context-switch rate. So several collectors ignore the bundle and
re-measure the live host during replay.

This is the false-green class: an AMD-thermal / EDAC / NVMe bug captured on the
affected box will **not** reproduce faithfully on replay if the relevant
collector live-samples instead of reading the bundle — replay would render the
replaying host's clean state and look like the bug vanished. The stated use case
("diagnose on any machine") is silently undercut.

| Item | Surface | Test target |
|---|---|---|
| Audit which collectors honour the bundle vs hit live system in replay path | `internal/source` (Live vs bundle Recorder wiring), replay cmd | CT201: capture once, double-replay, diff |
| Net/mem/ping/ctxsw collectors must read bundle inputs under replay, or be explicitly marked replay-excluded (not silently live) | offending collectors | same-bundle double-replay byte-identical on stable fields |

Repro: `dsd capture --raw`, then `dsd replay --json B.tar.gz` twice, diff.
Differences on non-timestamp fields = live leak. Not GATED — replay fidelity is
the feature's whole premise.

---

## I. `checks[]` array has no stable ordering — PARTIAL: sub-lists fixed (#348), top-level still GATED

Two `dsd health --json` runs on the same host emit `checks[]` in different array
positions (same 23-check set, same content, shuffled order). Confirmed
2026-06-16 across same-locale runs — collector scheduling non-determinism, not a
data difference. Benign for consumers that index by `name` (jq); a sharp edge
for byte/line-level golden-file tests on `--json` (they flake) and `diff`-based
support workflows (noisy).

**Done (#348):** the map-iteration ordering *within* a check's `raw` — disk
`Drives[].Mounts` (`range mountsByDev`) and the multipath device list (`range
deviceMap`) — now sorted, so those sub-lists are byte-stable.

**Still GATED (the headline item):** the *top-level* `checks[]` array order. Fix =
stable sort by check name at the render boundary (invariant-data layer, not
collectors). The replay double-diff harness sorted this away with `jq sort_by(.name)`
rather than changing the product. Build only when a test or workflow needs it.

---

## Locale safety — ✅ VALIDATED (2026-06-16), no open work

Forced-C subprocess discipline (`localeSafeCmd`/`localeSafeEnv`/`localeSafeExec`,
`LC_ALL=C`/`LANG=C`) confirmed holding on current main. Ran `dsd health --json`
under `en_US.UTF-8` vs `es_ES.UTF-8` on CT201 (locale proven hostile — `printf`
reads dot-decimals as `número inválido`). After controlling for check-ordering
(§I) and live-counter drift, every parsed value is a clean dot-decimal under
es_ES — no comma corruption, no zeroing, no garble; same exit code, same
23-check set, same severities both locales.

Root cause of the no-leak result (code audit, not just the live run): all ~260
numeric parses use Go's `strconv`, locale-independent by language design (always
reads `.` as decimal sep). The forced-C wrapper is real defense-in-depth — it
covers *string* uniformity (column headers, status words, month names; the #82
dmesg `[lun jun 8]` bug) that strconv-immunity does not. Committed guard:
`internal/collectors/exec_locale_test.go` — `TestCollectorsUseLocaleSafeExec`
(static: no raw `exec.Command` outside wrappers) + `TestParsingIsLocaleStable`
(behavioral: strconv parses dot-decimals, rejects comma-decimals under forced
es_ES env). Both run in default `go test`, no host.

A live double-run integration test was prototyped and discarded as inherently
flaky: with no locale-sensitive parser to leak into, comparing `--json` across
two shell locales only surfaces live-counter jitter (run-queue, CPU MHz, packet
counts) — an unbounded denylist. The unit guards test the actual risk.

UI/output **translation** stays demand-gated (no user has asked; sysadmin/SRE
buyer operates tooling in English; localized ops output hurts log/screenshot
searchability). Discipline regardless: `--json` is born locale-invariant
(English keys, raw numbers, ISO 8601); any future translation lives only in the
`render/` human layer, never the data plane.

---

## J. SMART wear% — guard the sibling 231/233 branch (hardening) — READY

The garbage-wear bug from the 2026-05-15 MacBook story (`3491877946276% used`)
came from **attribute 173's raw value** reaching `WearPct`, and was already
**fixed** the same evening in `05b8124` ("SMART attr 177/173 wear% uses
normalised value not raw") — ~2h after the marketing capture was taken. Verified
on the T1 Apple SSD (row 19) 2026-06-16: current `dsd hardware` correctly shows
`23% used` (the 173/177 guard rejects 173's out-of-range raw `3491877946276` and
lets attribute 177's normalised 077 → 100-77=23%). The marketing doc just froze
pre-fix output; nothing live to fix on this hardware.

Remaining (defensive, lower priority): the **sibling 231/233 branch** (SSD Life
Left / Media Wearout) lacked the same `attr.Value > 0 && attr.Value <= 100` guard
the 173/177 branch has — a copy-paste sibling-divergence (§E.3). Other SSDs report
wear via 231/233 and bad firmware there would produce the same garbage. Guard
added in this change for parity; **no live repro** (the Apple SSD has no 231/233
attribute, so this is hardening, not a confirmed-bug fix).

| Item | Surface | Status |
|---|---|---|
| Guard 231/233 branch to match 173/177 | `hardware_linux.go` ~L184 | ✅ done this change (hardening; unverified on real 231/233 firmware) |
| 173 garbage on Apple SSD | `hardware_linux.go` | ✅ already fixed `05b8124`; verified clean on row 19 |

---

## Housekeeping

- **pve01 hardware-collector T1** — ✅ probed 2026-06-16: HP ProDesk 600 G2 SFF
  (i7-6700 Skylake), added as PLATFORM_COVERAGE row 20. Key win: a real **WD 1.8TB
  rotational HDD** (`ROTA=1`) — the matrix's only spinning disk, exercising
  HDD-specific SMART + `is_ssd:false` heuristics — plus a 2nd SATA SSD (first
  multi-drive real node) and richer thermal (coretemp + pch_skylake + hp sensor).
  No ECC/EDAC or IPMI (consumer SFF), so §B/server-grade gaps remain open.
  **Remaining:** dsd on pve01 is v0.6.0 (Jun 1) — refresh to current and re-run
  `HW_HOST=root@192.168.10.20 bash scripts/hardware-smoke.sh` to validate the
  HDD-SMART path on current code (smoke passed on v0.6.0: 6 pass / 1 skip).
- BUGS.md: "Summary — Bugs by Category" + "Testbed Coverage" blocks are
  duplicated with diverging counts (13 vs 14) — delete the older pair.
