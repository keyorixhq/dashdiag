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
4. **Zero-vs-unreported ambiguity** — a numeric `0` for "attribute/sensor not
   exposed" renders identically to a measured `0`. Distinct from the false-OK
   sweep (#1): here the *verdict* is usually correct, but the displayed/JSON
   value is ambiguous. Lineage: the GPU all-zero false-OK (§F, #c784f68) was the
   verdict-breaking end of this; the cosmetic end is benign-but-misleading.
   Observed 2026-06-16 on pve01 (row 20): the LiteOn SSD exposes no SMART attr
   194/9, so `dsd hardware --json` shows `temp_c:0, power_on_h:0` — accurate
   ("not reported"), verdict correct (`SMART: PASSED` is driven by the health
   bit, not the zeros), but a consumer can't tell 0 from unsupported. **Not a bug
   to blind-fix:** the honest representation (null / a `supported` flag / omit)
   changes the `--json` shape, which is the **frozen 1.0 contract** — needs a
   deliberate schema decision, not a patch. Audit scope when picked up: temp_c,
   power_on_h, wear_pct, reallocated/pending across drives; CPU/GPU temps; any
   sensor field that can legitimately be absent. Low priority. **2026-06-18
   escalation:** the VMware virtual NVMe (§L) is the verdict-breaking end of this
   class re-surfacing — when the read returns *implausible* values rather than
   absent ones, the zeros (non-root) or the garbage (root) drive a false CRIT.
   §E.4's "honest representation needs a schema decision" still holds for the
   benign cosmetic case; §L is the not-benign case and is READY to fix now.

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
| Confirm a healthy AMD GPU actually reads temp (expected yes) | gpu_linux.go | ✅ DONE 2026-06-18 — validated on real AMD Cezanne (see note) |
| If a clean "read nothing" signal exists → narrow guard: don't claim "Checks passed" when no device had a readable temp | cmd/gpu.go gpuSummaryLine + checkGPU | ✅ DONE (#383 — guard in cmd + health; metric-less device → INFO) |

Unblock: ~~one session on the AMD laptop~~ — CLOSED 2026-06-18. Agent memory: `gpu-allzero-falseok-deferred`.

**2026-06-17 attempt — did NOT close this.** Ran on a real AMD Cezanne APU
(PLATFORM_COVERAGE row 21) expecting to confirm a healthy AMD GPU reads temp. It
couldn't: the host was a **live USB booted with `nomodeset`**, so `amdgpu` loaded
but never initialized the device — every telemetry node (gpu_busy_percent, VRAM,
hwmon temp) was absent and `dsd` correctly reported no GPU check. **Lesson for the
next attempt: a live USB / `nomodeset` boot cannot test the GPU path.** Need a
host where amdgpu fully binds the card — a *persistent* install (drop `nomodeset`)
or a discrete-GPU box. Friend's Proxmox host is a candidate IF it has an
amdgpu-bound card.

**2026-06-18 — CLOSED. Validated on real AMD Cezanne silicon.** Rebooted the same
laptop's live USB WITHOUT `nomodeset` → amdgpu fully bound the Radeon Vega (Cezanne,
`/sys/class/drm/card1`, driver in use `amdgpu`). `dsd gpu` read and parsed the real
sysfs correctly: edge temp 30°C, VRAM 0.2/0.5 GB (47%, `[shared APU memory]`),
power 2W, clock 400/1800 MHz (22%), util 0%, **IsAPU=true** (GTT 7.5 GB present) so
the VRAM-pressure check is correctly suppressed. The #383 metric-less guard
correctly did NOT trip (real metrics present → "GPU healthy. Checks passed" is here
legitimate, not the false-OK). Captured (`dsd capture --raw --sanitize`, GPU
auto-included) and **replayed `--gpu` offline** — the recorded GPU values reproduce
faithfully. The whole amdgpu path (temp/VRAM/power/clock/APU-detect, live + capture
+ replay) is confirmed on real hardware. Bundle: `testdata/captures/
amd-cezanne-gpu-20260618/` (local-only, excluded). KEY: a `nomodeset` boot can't
test GPU; drop it at the GRUB `e`-edit on a live USB.

**Under-load also exercised (same day, `clpeak` OpenCL compute via rusticl).** The
telemetry READS scale correctly under heavy load: util 0→97%, power 3→24W, clock
400→1800 MHz, temp 34→54°C — all parse right, and dsd correctly stayed "healthy"
(heavy but cool/within-limits → no false WARN). The elevated VERDICT thresholds were
NOT reachable on this low-power APU and remain unit-test-only on the verdict side
(reads validated on HW): temp peaked 54°C (< 80°C WARN); this APU exposes **no
`power1_cap`** hwmon node → `TDPLimitW=0` → the TDP-throttle check (correctly gated on
`TDPLimitW > 0`) never fires — no false throttle; VRAM-pressure is APU-suppressed by
design. A *discrete* AMD GPU (or a hotter/power-capped part) is needed to drive the
≥80°C / throttle / VRAM-pressure verdicts on real hardware. Under-load bundle:
`amd-cezanne-gpu-20260618/dsd-gpu-underload.tar.gz` (util 97% / clock 1800, replays faithfully).

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

**Re-observed 2026-06-18** (VCD root/non-root diff): besides the top-level order,
the Hardening check's `apparmor_groups[]` array also came out in a different order
between two runs — another map-iteration sub-list not yet sorted (the #348 sweep
covered Drives/multipath but not this one). Same benign-but-flaky class; fold into
the same render-boundary sort when the top-level item is built.

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

## K. Disk false-CRIT on read-only image filesystems — ✅ DONE (#382, 2026-06-17)

Surfaced by the first real AMD-silicon node (Ubuntu 26.04 live USB, PLATFORM_COVERAGE
row 21). `dsd health` reported `Disk CRIT — disk usage at 100% on /cdrom (/dev/sda1)`
on a healthy live boot. Root cause: inherently read-only image filesystems
(iso9660, squashfs, erofs, cramfs) are packed to capacity at build time — 100%
used is their normal state and no admin action can free space, so the usage/inode
level scoring was firing a guaranteed false CRIT on every live-USB `/cdrom`,
snap-backed squashfs, and AppImage mount.

Fix: added `isInherentlyReadOnlyFS()` and skip usage/inode scoring for those
fstypes (`checkDisk`, heuristics.go). The mount is still reported transparently in
the inline summary (`13 mounts, max 100% (/cdrom)`) — data shown, verdict corrected.
Writable filesystems unaffected: full ext4 still CRITs; the read-only error-remount
WARN (writable fs dropped to ro after I/O errors) still fires via its own allowlist.

Verified end-to-end on the AMD node: live run + replay of captured bundle both show
`Disk OK`. Regression guards in `TestCheckDisk`: full image fs clean; full writable
ext4 still CRIT; full read-only ext4 still WARN; image-fs inode-full clean.

| Item | Surface | Status |
|---|---|---|
| Skip usage/inode scoring for iso9660/squashfs/erofs/cramfs | `heuristics.go` checkDisk + `isInherentlyReadOnlyFS` | ✅ done #382 |
| Regression guards (image clean / writable still CRIT / ro-remount still WARN) | `heuristics_round10_test.go` TestCheckDisk | ✅ done #382 |

---

## L. NVMe SMART implausible-value → false end-of-life CRIT (VMware virtual NVMe) — ✅ DONE (fix/nvme-smart-plausibility-L, 2026-06-18)

Fixed by a plausibility gate in `checkNVMe` (`nvmeSmartPlausible`): a device whose
SMART log was read (`SmartRead:true`) but is physically impossible (temp ∉
[-40,125]°C, spare/threshold ∉ [0,100], counters > sane ceiling) is routed to a
new "implausible SMART data — health unverified, values rejected" **WARN** and its
fields are NOT scored — closing the false "near end of life" CRIT. Validated live
on the originating device (VMware vNVMe, guest 192.168.30.10): the Drives check
now emits the WARN and the NVMe CRIT is gone (the remaining CRIT that run was an
unrelated DBus false-positive → §M, separate branch). Regression cases in
`TestCheckNVMe`: vmware-garbage→WARN-not-CRIT, each implausibility trigger alone,
and boundary guards proving a real failing drive still CRITs / real high temp
still WARNs. Original investigation below for history.

First VMware Cloud Director node (vcd-msk-3, Ubuntu 22.04 guest 192.168.30.10,
2026-06-18 — see PLATFORM_COVERAGE). A 1 GB VMware Virtual NVMe disk hot-added
alongside PVSCSI/LSI-SAS/LSI-Parallel/SATA/IDE test disks exposes a SMART health
log full of nonsense, and `dsd health` ingests it and raises a **false CRIT**.

Raw `sudo nvme smart-log /dev/nvme0` on the device returns:
`temperature 11759°C`, `available_spare 1%` vs `available_spare_threshold 100%`,
`Data Units Read 56.67 YB`, `power_on_hours 1.1e21`, `power_cycles 1.8e20` —
i.e. out-of-range temps and counters sitting at ~2^63–2^64 (uninitialised /
sentinel fields in VMware's virtual NVMe). The read **succeeds**, so this is
parseable-but-garbage, not unread.

dsd's behaviour (confirmed by a root/non-root run pair, 2026-06-18):
- **root:** read succeeds → `smart_read:true`, `temp_c:11758.85`,
  `available_spare_pct:1`, `spare_threshold_pct:100`, `Drives` check →
  **CRIT** `"/dev/nvme0 spare capacity at 1% (threshold: 100%) — drive near end
  of life"` + WARN on temp. Overall **verdict flips WARN → CRIT**.
- **non-root:** read fails → `smart_read:false` + all-zero struct. No CRIT, but
  the zeros are indistinguishable from a measured 0 (§E.4) — only the missing
  privilege accidentally avoids the false CRIT.

So there is **no plausibility/reject-before-score guard**: the spare<threshold
end-of-life test fires on data whose own sibling field (11758°C) is physically
impossible. A real customer running `dsd` as root on any VMware NVMe guest from
these templates gets a spurious "drive dying" CRIT — a false positive in the
shipped health verdict.

Fix: add a bounds-check layer on the NVMe SMART struct *before* scoring —
temp ∈ [-40, 125]°C, spare/used/threshold percentages ≤ 100, counters below a
sane ceiling. On any implausible field, treat the whole SMART read as "couldn't
measure" (the honest-degradation pattern KernelSec/Hardening already use:
`-1`/`unknown`/explicit reason), **not** as measured values, and **do not** let
the end-of-life or temp tests fire. Distinct from §J (which guards garbage *wear%*
from bad SATA attr raw values): same class — raw-tool parser trusts a real
device's lying output — different tool (`nvme smart-log` vs `smartctl` attrs).
Strongest argument yet for a sanity layer on raw-tool parsers; the `/proc`
numeric fuzz harnesses should gain an `nvme smart-log` sibling.

| Item | Surface | Status |
|---|---|---|
| Plausibility-gate NVMe SMART before scoring (temp/pct/counter bounds) | nvme collector + `Drives` heuristic | READY — false CRIT confirmed root, repro on VMware vNVMe |
| Implausible read → "couldn't measure", not zeros and not CRIT | nvme render + scoring | READY (§E.4 surfacing + §J reject-before-score) |
| Fuzz harness for `nvme smart-log` parser (sibling to /proc parsers) | fuzz/ | demand/defensive |
| Empty/unpartitioned disks (sda–sde, 1 GB, no FS) — no false WARN/CRIT | disk enum | ✅ verified clean this run (no per-disk status fired) |

Also observed same run (logged, not new bugs): **PVSCSI driver detection correct**
despite blank `lsblk` TRAN on the paravirtual disk (`pvscsi_loaded:true` reads
`/proc/modules`, not transport); **device-name instability** — adding controllers
moved the root disk `sda`→`sdc` (Ubuntu boots by UUID; caution for any name-keyed
logic); **`fd0` phantom-floppy I/O errors** correctly deduped in Logs (`×2`),
benign VMware-template artifact (§E.4 virtualization-noise candidate, park).

---

## Systemd failed-unit listing — guarantee timeout never reads as "none" — READY (low)

Same 2026-06-18 root run: `systemctl list-units` did not complete under load, and
dsd correctly emitted `failed_units_unknown:true` + INFO `"could not list failed
units … failed-unit status is unverified"` — the honest path. But an earlier clean
run showed `failed_units:null` (confident "none failed"). Risk: the timeout/error
path must **always** yield `failed_units_unknown`, never collapse to an empty-but-
confident `null` that renders as "no failures." Verified correct in this instance;
add a regression test forcing the `list-units` timeout branch and asserting the
output is the unknown state, not `null`. Pure §E (False-OK sweep) discipline.

---

## M. D-Bus false-CRIT — "unknown" state treated as "failed" — ✅ DONE (fix/dbus-unknown-not-failed-M, 2026-06-18)

Found on the VMware Cloud Director guest (Ubuntu 22.04, 192.168.30.10) during the
2026-06-18 session: `dsd health` reported **CRIT "D-Bus system message bus has
failed"** on a host where `systemctl is-active dbus` returns `active` and
`busctl` lists live connections — a false CRIT, and a scary top-line one.

Two compounding silent-failure flaws (the false-OK class, inverted — a failed
*measurement* rendered as a failed *subject*):
1. **Wrong unit name.** The collector ran `systemctl is-active dbus.service`.
   On modern Debian/Ubuntu (and these VMware templates) the bus resolves via
   `dbus` (alias → `dbus.socket`/`dbus-broker`), and `is-active dbus.service`
   returns empty+nonzero → status `"unknown"`. `is-active dbus` returns `active`.
2. **"unknown" collapsed to "failed".** `info.Active = status=="active"` made
   unknown→`active:false`, and `checkDBus` CRIT'd on anything not active/n-a — so
   "couldn't determine" produced the same CRIT as a genuine "failed".
3. **Bonus:** `collectDBusLastError` returned the last *non-empty* journal line
   regardless of severity, so it captured `"Successfully activated service
   org.freedesktop.timedate1"` and reported a success message as `last_error`.

Fix (collector + heuristic, no `--json` schema change):
- Query `dbus`, not `dbus.service` (resolves the alias; the working invocation).
- Empty result → explicit `"unknown"`; heuristic treats anything other than
  `failed`/`inactive` as **INFO** "state could not be determined — health
  unverified, not assumed failed", never CRIT. Only explicit failed/inactive CRITs.
- `collectDBusLastError` now uses `journalctl -p err` (error priority only) and is
  called only when status is confirmed failed/inactive — no success-line-as-error.

Validated live on the originating guest: DBus check now `OK`
(`status:"active", active:true`), zero DBus insights, false CRIT gone. (The run's
remaining CRIT was the unrelated NVMe §L, fixed on its own branch.) Regression in
`TestCheckDBus`: unknown→INFO, activating→INFO, failed→CRIT, inactive→CRIT,
active→clean.

| Item | Surface | Status |
|---|---|---|
| Query `dbus` not `dbus.service`; unknown≠failed | `dbus_linux.go` Collect | ✅ done |
| Heuristic: non-failed/inactive status → INFO not CRIT | `heuristics.go` checkDBus | ✅ done |
| `last_error` severity-filtered (`-p err`), only when down | `dbus_linux.go` collectDBusLastError | ✅ done |
| Regression: unknown/activating→INFO, failed/inactive→CRIT | `heuristics_round6_test.go` TestCheckDBus | ✅ done |

---

## N. VMware live-guest probe checklist — BLOCKED (needs a VMware guest; tenant returned 2026-06-18)

Items identified during the 2026-06-18 VCD session that need a *live VMware guest*
to validate and weren't closable then — either gated by tenant role (couldn't edit
reservation/limit fields) or simply not exercised before access lapsed. Grouped
here by shared blocker: one VMware guest (own vSphere, a pilot's env, or a
re-provisioned tenant **with admin rights**) closes the whole class in one session.
Most have a plausible bug at the end — they're §E.4 / silent-failure probes, not
just coverage.

1. **open-vm-tools removed → do host-limit fields read "unknown" or a misleading 0?**
   (the sharpest one.) `mem_limit_mb`/`cpu_limit_mhz`/`balloon_mb` are read through
   the tools stat channel. Remove open-vm-tools (`apt remove open-vm-tools`) and
   re-run: the limit fields should go **absent/unknown**, NOT `0`. If they read `0`
   and the VMware heuristic interprets that as "no limit set" rather than "couldn't
   read", that's a §E.4 zero-vs-unreported false-negative — dsd would silently stop
   reporting a real host limit the moment tools are absent. Reversible: reinstall.
2. **Tools stopped/absent — collector-side detection on real hardware.** The
   *heuristic* paths are unit-tested (`vmware_test.go`: ToolsInstalled:false → WARN,
   ToolsRunning:false → WARN). Not exercised live: the *collector* readers
   `vmwareToolsRunning()` (/proc comm scan) and `vmwareToolsInstalled()` (binary
   probe) against a genuinely stopped/removed install. `systemctl stop vmtoolsd`,
   re-run, confirm `tools_running:false` actually surfaces. (Low — readers are
   simple; a fake-/proc collector test would also cover it.)
3. **Active ballooning (`balloon_mb > 0`).** GATED 2026-06-18 — couldn't lower the
   memory limit below allocated RAM from `user_adm`. With limit-edit rights: set
   mem limit < allocated, drive in-guest memory demand, confirm `balloon_mb` goes
   non-zero AND dsd attributes it to **host reclamation** (a host condition) vs
   in-guest memory pressure. Conflating the two would be a real diagnostic bug.
4. **Active CPU-limit throttle (`steal_pct > 0`).** GATED 2026-06-18 — the 3000 MHz
   limit on a 1-vCPU guest is ~1 full core, never throttled under `stress-ng --cpu 1`
   (steal stayed 0, dsd correctly OK — no false alarm). With limit-edit rights: set
   cpu limit < 1 core, load the guest, confirm steal goes non-zero AND dsd connects
   high steal to the known `cpu_limit_mhz` as "host-throttled" rather than reporting
   bare high CPU and missing the *why*.
5. **PVSCSI-attached SMART parse path.** §L validated that *implausible* NVMe SMART
   is rejected; separately, the PVSCSI controller branch (`pvscsi_loaded` detection
   confirmed working) has not had a drive with a *readable, plausible* SMART log
   attached through it. Attach a disk on the Paravirtual controller with real SMART
   and confirm the parse path is clean (not just the rejection path).
6. **vMotion / snapshot artifacts.** If a pilot env exposes live migration: post-
   vMotion clock skew and guest stun-time. dsd's Clock check would be the surface;
   untested against a real migration event. Demand/opportunity-gated.

Provenance: full capture set in
`dashdiag-private/marketing/marketing-assets/vmware-vcd-20260618-data/`. The
detection-at-rest half of items 1/3/4 is confirmed working; the active/absent half
is what's unverified.

---

## O. "Correct reading, wrong context" false-CRITs on Proxmox hosts — ✅ DONE (3 fixed, fix/proxmox-context-falsecrits-O); O.4 PVE-storage-INACTIVE candidate open

A coherent new bug *class*, distinct from §L/§M. There the bug was a failed or
garbage *measurement* rendered as a failed subject. Here the measurement is
**correct** — the bug is **misattributing its meaning** because the collector
doesn't understand the Proxmox/virtualization context it's running in. All three
below were found on a real AMD EPYC Proxmox host (`khhv01`, 252 GB RAM, 4 NUMA
nodes, Debian 12 / kernel 6.8-pve, dsd v1.4.0) via a capture a user sent
2026-06-19, and **confirmed false by the host's owner**. Full repro bundle +
replay output in
`dashdiag-private/marketing/marketing-assets/amd-gpu-friend-20260619-data/`
(`dsd.tar.gz` — replayable offline, no live host needed to validate fixes).

The host's verdict was **CRIT** driven entirely by these three. All three are
false. Owner's words (paraphrased, RU): the LVM is the default Proxmox-created
LVM on NVMe and is nearly empty; the ZFS is real but **passed through to a VM**,
not the host's; the journal-corruption CRIT is "just nonsense".

### O.1 — LVM: scores VG allocation, not thin-pool usage (Proxmox default layout)
- **Fired:** `CRIT volume group pve is 98% full (16.0 GB free of 930.5 GB)`.
- **Reality:** on a Proxmox host the `pve` VG is the default thin-pool layout —
  Proxmox *allocates* almost the whole VG to a thin pool (`data`) by design, so
  "VG ~98% allocated" is the normal healthy state. The capture's own `lvs`
  output shows the `data` thin pool at **8.37% data / 0.51% metadata** — i.e.
  ~92% free. dsd read VG allocated-vs-free and CRIT'd; the number that matters
  (`data_percent`) was already collected and ignored.
- **Fix:** when the host is Proxmox (detectable — `pveversion` is collected) and
  the VG backs a thin pool, score the **thin pool's `data_percent` / metadata%**,
  not VG allocation. A nearly-empty thin pool in a fully-allocated VG is healthy.
  Thin-pool *data* or *metadata* approaching 100% is the real CRIT condition.
  (Generalises beyond Proxmox: any thin-provisioned VG should be scored on pool
  usage, not VG free.)

### O.2 — ZFS: CRITs on `zfs-import-scan.service` failure with no host pools
- **Fired:** `CRIT unit zfs-import-scan.service has failed`.
- **Reality:** the host has no ZFS pools to import — the ZFS hardware is **passed
  through to a VM**. `zfs-import-scan` failing (or `zfs-import-cache` when pools
  are cache-imported) is expected/benign when the host itself manages no pools.
  dsd saw the failed unit and didn't understand the pools aren't the host's.
- **Fix:** don't let a failed `zfs-import-*.service` drive a CRIT unless there are
  actually imported/expected ZFS pools **on the host** (`zpool list` non-empty).
  No host pools + failed import unit → INFO/skip, not CRIT. Same "service failed
  but failure is expected in this configuration" pattern as a Systemd suppression.

### O.3 — Logs: journal-corruption CRIT doesn't distinguish active vs archived (`.journal~`)
- **Fired:** `CRIT journald journal corruption detected — some logs may be
  unreadable or missing`.
- **Reality:** of 4 `journalctl --verify` runs in the capture, **3 PASS, 1 FAIL**
  — and the FAIL is on a rotated `*.journal~` archive (bad hash at one offset,
  87% into an 8 MB deactivated segment). All **active** journals pass. A `~` file
  is a journal systemd couldn't cleanly deactivate, common after an unclean
  shutdown; one bad block in a historical archive does not mean current logging
  is compromised. A blanket "any verify FAIL → CRIT, logs may be missing" fires
  on a large fraction of real hosts and is the trust-eroding false-CRIT Principle
  4b warns against.
- **Fix:** distinguish **active**-journal corruption (real CRIT — current logging
  compromised) from **archived `.journal~`** corruption (WARN/INFO — historical
  artifact). Gate the severity on whether the failing file is an active journal
  or a rotated `~` segment.

**The class lesson (worth its own note):** dsd reads the raw signal correctly but
misattributes meaning because it lacks the host/virtualization context — Proxmox
thin-pool intent, ZFS passthrough, active-vs-archived journals. This is the
mirror of §L/§M (there: bad measurement → bad verdict; here: good measurement →
bad interpretation). Watch for siblings wherever a check scores a raw number
without asking "what does this number mean *on this kind of host*." Real-operator
feedback was essential — the thin-pool intent and the ZFS passthrough are not
derivable from the data alone; only the owner knew. (Validates Principle 4a: real
hardware + real operator surfaces what synthetic fixtures cannot.)

| Item | Surface | Status |
|---|---|---|
| O.1 LVM thin-pool usage vs VG allocation on Proxmox | LVM collector + heuristic | ✅ DONE (fix/proxmox-context-falsecrits-O) — VG-fullness skipped for thin-pool-backed VGs (`analysis.VGBacksThinPool`, single source of truth shared with `dsd disk`); thin-pool data/meta% still scored. **Validated end-to-end on the EPYC bundle: base v1.5.1 CRIT'd "pve 98% full", fixed binary → LVM ✅.** |
| O.2 ZFS import-service CRIT only if host pools exist | ZFS/Systemd heuristic | ✅ DONE — `zfs-import-{scan,cache,@}` failure → INFO when no host ZFS pools imported; `SystemdInfo.ZFSPoolsPresent` set by ApplyThresholds pre-scan from the ZFS/Disk collectors. Unit-tested (heuristic + e2e pre-scan). |
| O.3 Logs active vs archived `.journal~` corruption severity | Logs collector + heuristic | ✅ DONE — the collector already verifies *only* archived (`*.journal~`) segments (active ones race with writers, systemd#35916), so a hit is always a historical artifact → downgraded CRIT→WARN with honest wording. Unit-tested. |
| Replay-based regression for all three (offline, from bundle) | replay test | PARTIAL — O.1 validated end-to-end against the EPYC bundle. O.2/O.3 can't be re-validated by replay of this bundle: it was captured on v1.4.0, and the v1.4.0→v1.5.1 collector-code skew means the journal-verify + failed-unit signals are no longer reconstructed in a v1.5.1 replay (base v1.5.1 replay already shows them clean). Covered by unit tests instead; would re-fire on a *live* v1.5.1 run. |

**New finding while validating (NOT in scope here, needs owner confirmation → candidate O.4):**
replaying the EPYC bundle with **base v1.5.1** surfaces **2 `PVE storage … INACTIVE` CRITs**
(`VM03CR (dir)`, `Storage (dir)`) that were **absent in the v1.4.0 capture** and never
mentioned by the host owner — i.e. a *new* "correct-reading / wrong-context" false-CRIT
candidate introduced between v1.4.0 and v1.5.1, same class as O.1–O.3. A `dir`-type PVE
storage can be intentionally disabled or on an optional mount; whether INACTIVE is a real
fault is not derivable from the data alone (only the owner knows). Do not blind-fix — ask
the owner whether those two storages should be active before deciding CRIT vs INFO/skip.

Also confirmed clean this capture (good behaviour, not bugs): **no false GPU** —
the host's `card0` has `device/vendor: not_exist` (virtual console DRM, no
discrete GPU bound; the real AMD GPU is passed through to a VM), and dsd correctly
emitted **no GPU check at all** rather than misreporting the console device.
Consequently this capture does **NOT** close §F (no host-bound discrete amdgpu) —
§F still needs a capture from inside the GPU-passthrough VM, or the GPU bound on
the host. AMD-CPU thermal path validated incidentally: k10temp Tctl + Tccd1–3 on
a 4-NUMA EPYC, CPU Thermal correctly 57°C.

---

## P. K8s-on-VMware vertical — ✅ VALIDATED LIVE + 1 fix (fix/k8s-event-recency, 2026-06-19)

The prospective client's exact topology is **k3s/Tanzu on VMware** (Docker + managed
k8s on a VMware estate, OpenStack being built in parallel; founder's priority:
*kubernetes-on-vmware > openstack*). Rather than predict, we stood up k3s on the real
VMware tenant guest (vcd-msk-3, 192.168.30.10 behind 5.35.120.132:2222) and ran the
full `dsd health` vertical on the genuine topology.

**Result — the vertical coheres end-to-end on real hardware:** VMware layer (emulated
e1000/e1000e NICs, SCSI 30s<180s timeout, host CPU 3000MHz + mem 2048MB limits), K8s
deep OS-layer (the #271 k3s-aware paths all correct: flannel detected, CNI bins found
under `/var/lib/rancher`, embedded kubelet + bundled containerd recognised), and the
container layer via k3s's containerd. node=1/pods=7/0-not-ready. dsd produced useful
k8s-specific advice (`fs.inotify.max_user_watches` low, `vm.swappiness=60` high for a
k8s node). Note: the K8s OS-layer is **deep-only** (`dsd k8s --deep` / `health deep`).

| Item | Surface | Status |
|---|---|---|
| K8s Warning-event recency gate — stale startup events false-WARN a healthy cluster | `heuristics_virt.go` events check | ✅ DONE #421 — gate on last-seen `Age` (recent≤5m→WARN, quiesced→INFO); verified live |
| Determinism: event reason-summary built from Go-map iteration | `heuristics_virt.go` | ✅ DONE #421 — sorted count-desc/name-asc (replay/JSON-stability) |
| Tanzu (TKG) OS-layer — kubeadm/Photon/**Antrea** | `collectK8sOSLayer` (k8s.go) | PARTIAL — code review says largely TKG-ready (kubelet/containerd/CNI-bins/cert paths cover kubeadm; Antrea won't false-CRIT). Needs real TKG to validate |
| No *positive* CNI-health check for non-flannel CNIs (Antrea/Calico/Cilium) | k8s OS-layer | BLOCKED (needs TKG) — mild false-OK; pod-not-ready/sandbox events catch a broken CNI |
| `checkCertExpiry` 0-day sentinel collision (cert expiring today reads as "unset") | k8s.go ~578 | READY — narrow 24h-window false-OK, general (not TKG-specific) |

Rig kept running on the tenant guest for re-validating K8s changes on the true
topology. The k3s-on-VMware path is now a concrete demo/pilot asset.

---

## Housekeeping

- **VMware Cloud Director T1 node** — 2026-06-18: first VMware-hypervisor guest
  (vcd-msk-3 tenant, Ubuntu 22.04, 192.168.30.10 behind Edge DNAT 5.35.120.132:2222).
  Six controller families exercised in one run via hot-added 1 GB disks:
  Paravirtual (PVSCSI), LSI Parallel (boot), LSI SAS, SATA, IDE, NVMe. Findings →
  §L (NVMe false-CRIT, the headline) + Systemd timeout entry; passing results:
  PVSCSI detection, empty-disk handling, and **root/non-root privilege-degradation
  honesty** (Hardening/KernelSec/Logs all degrade with explicit reason strings,
  no silent green). Add row to PLATFORM_COVERAGE.md (VCD/vSphere axis, NVMe-garbage
  path documented). VM left powered off in VCD to stop the PAYG meter; disks/config
  persist for revisit (PVSCSI-SMART parser re-test if §L fix needs a live target).
- **VMware coverage boundary — host-limit *active* paths GATED by tenant role.**
  The `user_adm` role on the vcd-msk-3 tenant exposes allocated memory/CPU but
  **not** the reservation/limit fields, so the limits can't be lowered below what
  the guest can reach, and a shared tenant gives no control over host memory/CPU
  pressure. Net: the *active* host-throttle conditions are not inducible here.
  - **Confirmed working (at-rest + no-throttle):** dsd correctly *detects* the
    limits exist (`cpu_limit_mhz:3000`, `mem_limit_mb:2048`, `balloon_loaded:true`,
    `balloon_mb:0`) and correctly does **not** false-alarm when they aren't being
    hit — under `stress-ng --cpu 1` the 3000 MHz limit on a 1-vCPU guest was never
    reached, `steal_pct` stayed 0, CPU check stayed OK. No false throttle alarm.
  - **GATED (needs limit-edit rights or a host you control):** active ballooning
    (`balloon_mb>0` → does dsd WARN and attribute it to *host reclamation* vs
    in-guest pressure?) and active CPU throttle (limit < 1 core → `steal_pct>0` →
    does dsd connect high steal to the known cpu_limit as "host-throttled"?). These
    are the §L-class "behave under the real condition" tests; the detection-at-rest
    half passes, the active half is unverified. Re-test on pve01 (own limits) or in
    a pilot's own vSphere where reservation/limit editing is available.
- **Methodology — root/non-root pair is now a standing check.** The 2026-06-18
  diff proved its worth: the NVMe false-CRIT (§L) was *invisible* in a non-root
  run (hidden behind "can't read") and only exposed under root. Every privileged
  collector gets a root + non-root run; non-root must degrade to an explicit
  "couldn't measure", never to OK. Fold into CLAUDE.md test matrix alongside the
  locale-safety and amd64-guest-on-ARM rules.
- **pve01 hardware-collector T1** — ✅ done 2026-06-16: HP ProDesk 600 G2 SFF
  (i7-6700 Skylake), PLATFORM_COVERAGE row 20. Fresh current-`main` dsd deployed
  and validated (hardware-smoke 6 pass / 1 skip). Confirmed the real **WD 1.8TB
  rotational HDD** SMART reads correctly on current code (temp 51°C, 36563h, attrs
  9/194) and types as HDD; SSD/HDD discrimination verified in `dsd disk`; verdicts
  sound. No defects found — the SSD temp=0/power-on=0 is accurate "not reported"
  (drive exposes no such attrs), logged as cosmetic under §E.4. No ECC/EDAC or
  IPMI (consumer SFF), so §B/server-grade gaps remain open.
- BUGS.md: "Summary — Bugs by Category" + "Testbed Coverage" blocks are
  duplicated with diverging counts (13 vs 14) — delete the older pair.
