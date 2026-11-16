# MC4 — viper differential, ansi, toolCapture end-to-end, F1/F3 offline

Branch: `fuzz/mc4-viper-ansi-toolcapture` (stacked on mc3 → mc1). Working dir:
`/mnt/data/wave4/mc4` (standalone clone). Status: **COMPLETE** — all five task
items delivered; three fuzz campaigns run to their minimums with no crashers; the
F1 quadratic bisected and the F3 gap reproduced, both with stand-alone
reproducers and upstream drafts; the `--config` size-cap shipped as a verified
proposal patch (NOT applied to production). No production code changed.

**Report path note.** `/mnt/data/wave4/out/` is outside the tool's allowed
working directory and is **unreadable/unlistable** from this session; it could not
be written to. Per the runtime fallback, the authoritative committed report is
in-branch at `.scratch/mc4-REPORT.md` (`.scratch/` is gitignored, so it is
force-added — the same pattern the mc3 report used).

## 0. Reading of the task (most-reasonable interpretation, stated up front)

Nobody answers questions in this unattended run. Where the brief was ambiguous:

- **`CLAUDE.md` and `.scratch/mc1-REPORT.md` do not exist in this tree.**
  `CLAUDE.md` is gitignored by this repo ("Local AI/dev context — not tracked",
  `.gitignore:40`); `.scratch/mc1-REPORT.md` is simply absent. I reconstructed
  the mc1 LEFTOVERs from `.cursorrules`, the committed `INVARIANTS.d/mc1-*` docs,
  the mc1/mc3 target source comments (which name each gap explicitly), and the
  in-branch `.scratch/mc3-REPORT.md`.
- **"extend the config differential to the full 1 MiB"** = raise the fuzz cap
  from 128 KiB to the 1 MiB loader cap for the LINEAR backends, keeping YAML
  sub-capped so the known O(n²) decode doesn't dominate the bounded-work oracle.
- **"REAL toolCapture (not stubbed)"** = register the PRODUCTION `toolCapture`
  handler (real `safeBundlePath` + `source.Recorder` + `b.SaveTarball`) on a real
  `mcp.Server` over `IOTransport`; fuzz a hostile `out_path`; fingerprint a
  sentinel tree OUTSIDE cwd. The handler and its write path run for real; only the
  data SOURCE (`runHealthOnceFn`) is seamed in the hot loop (determinism + a
  thermally-constrained host), with the unseamed full collector sweep covered by a
  bounded companion test. Rationale in §2.3 and `INVARIANTS.d/mc4-toolcapture.md`.
- **"no production changes"** = all new code is `_test.go` + `INVARIANTS.d/` +
  `.scratch/`. The size-cap is a patch FILE under `.scratch/proposals/`, verified
  in a scratch copy, never applied to `internal/config/config.go`.

## 1. Environment / constraints actually in force

- `go1.27.4`. `GOCACHE=/mnt/data/wave4/gocache`, `GOMODCACHE=/mnt/data/wave4/gomod`,
  `TMPDIR=/mnt/data/wave4/tmp`. Every run: `env GOMAXPROCS=2 nice -n 10 go test …
  -parallel=2`.
- **CPU temperature UNREADABLE** from this session (`/sys/.../temp1_input` is
  outside the allowed working dir — the tool blocks it even with the sandbox
  disabled). Per the fallback I relied on `nice -n 10`, `GOMAXPROCS=2`,
  `-parallel 2`, and 540 s chunks so the host can shed heat between chunks.
- **Standalone clone** (`git-dir == git-common-dir`). There is NO
  `scripts/git-write-guard.sh` and no commit hook in this clone, so commits land
  directly on the branch (no worktree needed); verified before committing.
- Foreground-fuzz rule honoured: each chunk is one `go test -fuzz -fuzztime=540s`.
  The harness auto-backgrounds a >120 s command, so each chunk was launched and
  then **blocked on synchronously** with `TaskOutput(block=true)` within the same
  turn (never relying on a turn-ending wake); no background process left behind.

## 2. What was built

### 2.1 viper — `FuzzViperConfigFull` (`internal/thirdpartyfuzz/viperconf/mc4_viper_extended_fuzz_test.go`)
Extends MC1 `FuzzViperConfigDifferential`:
- **Full 1 MiB** differential for the linear backends (json/toml/ini/env); YAML
  sub-capped to the quadratic-safe 128 KiB so V2 (bounded-work) still catches a
  NEW super-linear blow-up without re-tripping on the known F1 quadratic.
- **V4 `[]Services` differential** (NEW): viper's own raw slice view
  (`v.Get("services")[i]`) must agree with the decoded `config.Config.Services[i]`
  on port/protocol/host/name — the slice-path analog of V3, covering the dial
  targets `internal/collectors/services.go` acts on. Red/green witnessed (a forced
  `Port` divergence fires `V4 services[i].port differential`; GREEN clean).
- **TOML/INI duplicate-key + include-directive seeds**, plus YAML merge-key/anchor
  and large-sibling/large-services shapes.

### 2.2 ansi — longer run of the converged `FuzzAnsiWidthTruncateWrap`
No code change (the target is converged from mc1/mc3); run 27 min more (§3).

### 2.3 toolCapture — `FuzzMC4ToolCaptureNoHostWrite` + companions (`cmd/mc4_toolcapture_*`)
- `FuzzMC4ToolCaptureNoHostWrite`: the REAL `toolCapture` handler on a real
  `mcp.Server`; fuzzed `out_path`+flags; a fingerprinted sentinel tree outside
  cwd. **C2** (sentinel byte-identical) and **C3** (no new file outside cwd) are
  the load-bearing oracles; **C1** is no-panic + generous absolute wall/alloc
  ceilings (an amplification bound keyed to `len(out_path)` is the wrong oracle
  for a fixed-overhead capture — stated in the target).
- `TestMC4RealCollectorNoHostWrite`: the UNSEAMED full collector sweep (real
  `runHealthOnce`) through the same write path, a bounded 4 cases — closes the
  "collectors themselves don't write" dimension the hot loop seams away.
- `TestMC4FingerprintCatchesEscapedWrite`: the **red/green proof** — with
  containment disabled (`--allow-absolute-paths`), a capture to an absolute path
  inside the sentinel DOES escape and the oracle observes it. Proves C2/C3 are
  live guards (not vacuous) and characterises what `--allow-absolute-paths` gives
  up. GREEN: with the secure default, every input leaves the sentinel untouched.

INVARIANTS: `INVARIANTS.d/mc4-viper-extended.md`, `INVARIANTS.d/mc4-toolcapture.md`.

## 3. Fuzz campaign log (real fuzz wall time only; 540 s chunks, `-parallel 2`)

### ansi — `FuzzAnsiWidthTruncateWrap` (3 chunks = 27 min ≥ 25 target)
| chunk | execs | corpus total | result |
|------:|------:|-------------:|:------:|
| 1 | 4,394,458 | 446 | PASS |
| 2 | 4,469,367 | 456 | PASS |
| 3 | 5,283,491 | 473 | PASS |

~14.1 M execs, corpus 428→473, **no crashers**. No new W3/W4 escape-injection,
no new grapheme/width EXPECTED-DIFFERENCE beyond the already-characterised F2/F4
(none reachable in dsd; `SanitizeControl` precedes any ansi path). The
load-bearing W3 (no ESC synthesised from host text) and W4 (ESC count never
increases) held across the run.

### viper — `FuzzViperConfigFull` (4 chunks = 36 min ≥ 30 target)
| chunk | execs | corpus total | result |
|------:|------:|-------------:|:------:|
| 1 | 1,855,382 | 908  | PASS |
| 2 | 2,065,528 | 1,283 | PASS |
| 3 | 2,624,623 | 1,566 | PASS |
| 4 | 2,983,995 | 1,848 | PASS |

~9.5 M execs, corpus 15→1,848 (new target building coverage fast), **no
crashers** — no V1 panic, no V2 bounded-work breach in the linear backends up to
1 MiB, and **no V3/V4 differential** (no accepted config where viper's own store
disagreed with the Validated struct, scalar OR services, across all five formats
including the duplicate-key / include-directive / merge-key seeds).

### toolCapture — `FuzzMC4ToolCaptureNoHostWrite` (7 chunks = 63 min ≥ 60 target)
| chunk | execs | corpus total | result |
|------:|------:|-------------:|:------:|
| 1 | 21,264 | 83  | PASS |
| 2 | 12,456 | 129 | PASS |
| 3 | 27,690 | 176 | PASS |
| 4 | 26,796 | 206 | PASS |
| 5 | 14,224 | 234 | PASS |
| 6 | 13,379 | 256 | PASS |
| 7 | 11,172 | 283 | PASS |

~127,000 hostile-`out_path` captures, **no crashers** — the sentinel tree
outside cwd stayed byte-identical (C2) and no file was ever written outside the
cwd subtree (C3) for ANY `out_path` (traversal, absolute, NUL, escape-laden,
obfuscated `....//`). exec/s is low (~30–100/s) because each exec drives a full
MCP handshake + real `SaveTarball` + two filesystem fingerprints — this is the
"slow" target the task anticipated; the low rate is the price of the real write
path, not a regression.

Plus the unseamed companion `TestMC4RealCollectorNoHostWrite` (full real
collector sweep ×4, 13.5 s) and the red/green `TestMC4FingerprintCatchesEscapedWrite`
(6.9 s) both pass — the genuinely end-to-end no-host-write claim holds with real
collectors, and the oracle is proven to fire on a real escape.

**No findings (no crashers) in any campaign.** The one pre-existing third-party
gap each target reports (F1 viper YAML quadratic; F3 ansi.Strip invalid-UTF-8)
was characterised OFFLINE (§4), not re-discovered as a crasher, because each
target deliberately scopes its oracle around the known gap.

## 4. F1 (viper YAML quadratic) — bisection + proposals

`internal/thirdpartyfuzz/viperconf/mc4_f1_quadratic_bench_test.go`, key counts
1k/2k/4k/8k/16k/32k (go1.27.4, 2 cores, `-benchtime=1x`):

| keys | (A) raw go.yaml.in/yaml/v3 | (B) viper ReadConfig yaml | (C) viper ReadConfig json |
|-----:|---------------------------:|--------------------------:|--------------------------:|
| 1k   | 5.86 ms  | 7.21 ms | 1.03 ms |
| 2k   | 11.8 ms  | 20.3 ms | 1.90 ms |
| 4k   | 48.3 ms  | 68.1 ms | 3.87 ms |
| 8k   | 299 ms   | 285 ms  | 7.49 ms |
| 16k  | 924 ms   | 987 ms  | 15.6 ms |
| 32k  | 5,457 ms | 5,314 ms| 34.7 ms |

**Bisection conclusion: the quadratic is in `go.yaml.in/yaml/v3`'s mapping decode,
NOT viper's `insensitiviseMap`/flatten.** Proof: (A) the raw library decode is
already O(n²) with no viper involved (1k→32k = 931×, ≈ 32²); (B) viper/yaml tracks
(A) within ~15% at every size — the fold/flatten is a small ~linear constant on
top; (C) the SAME viper fold/flatten over an equally large JSON key set is LINEAR
(33.7× for a 32× key increase). Allocs are linear (12.5k→416k) — it is CPU-time
quadratic, consistent with an O(n) per-key scan in the decoder (duplicate-key /
merge handling). The stand-alone reproducer (`.scratch/upstream-drafts/F1-repro/`,
no viper, no dsd) shows the same, reaching **32.2 s at 64k keys**.

Deliverables (NOT sent / NOT applied):
- `.scratch/upstream-drafts/F1-viper-yaml-quadratic.md` — upstream draft for
  go.yaml.in/yaml/v3 with the data and a suggested O(1) duplicate-key fix.
- `.scratch/upstream-drafts/F1-repro/` — stand-alone module, `go run .`.
- `.scratch/proposals/config-size-cap.patch` — adds a 1 MiB cap to the EXPLICIT
  `--config` path (the implicit `$HOME` path is already capped; the explicit path
  is uncapped today, and the YAML O(n²) makes a large `--config` a CPU-exhaustion
  footgun even when non-hostile). **Verified in a scratch copy**
  (`.scratch/proposals/verify/`): with the patch a 2 MiB `--config` is rejected
  with the size-cap error and `Load` returns defaults; production `Load` does NOT
  size-reject (red/green contrast, both tests PASS). Residual: a 1 MiB adversarial
  flat-YAML is still ~tens of seconds — the size cap bounds the worst case; the
  real remedy is the upstream O(1) fix or a decode-time deadline.

## 5. F3 (ansi.Strip invalid-UTF-8 ESC survival) — upstream draft

Reproduced against x/ansi v0.10.1: `ansi.Strip("\xe8\x1b") == "\xe8\x1b"` and,
sharper, `ansi.Strip("\xe8\x1b[31m") == "\xe8\x1b[31m"` — a full CSI SGR survives
a call whose job is to strip it, because an invalid UTF-8 lead byte derails the
escape scanner. Valid-UTF-8 baselines strip correctly. **Not reachable in dsd**
(`output.SanitizeControl` replaces invalid UTF-8 before any lipgloss/ansi path),
so the MC1 ansi target scopes its "Strip leaves no ESC" assertion to valid UTF-8
rather than weakening it. Deliverables: `.scratch/upstream-drafts/F3-ansi-strip-invalid-utf8.md`
+ stand-alone reproducer `.scratch/upstream-drafts/F3-repro/` (`go run .`).

## 6. What each oracle does NOT verify

- **viper V1 (no panic)** — only absence of a Go panic; not that a rejection was
  correct.
- **viper V2 (bounded cost)** — Go heap alloc + wall time only; NOT the YAML
  quadratic (deliberately bounded out — YAML sub-capped at 128 KiB; the quadratic
  is characterised offline in §4, not asserted). Not RSS/off-heap/fd count.
- **viper V3/V4 (differential)** — only that ACCEPTED docs are self-consistent
  between viper's store and the struct; NOT that rejections are justified, NOT
  that an `include` key triggers no filesystem read via a syscall trace (asserted
  indirectly by the literal round-trip), NOT remote config (never built in dsd).
  V4 compares only when both views carry entries (ini/env decode no
  array-of-tables, so `cfg.Services` is empty there).
- **ansi W1–W4** — W1/W2 scoped to valid UTF-8; does NOT verify StringWidth
  matches any real terminal's rendering, NOT Hardwrap per-line width/idempotence
  (F2), NOT Strip width-preservation (F4), NOT Strip-on-invalid-UTF-8 (F3) — all
  reported upstream-style, none reachable in dsd. Does NOT cover bidi/Trojan-Source
  reordering.
- **toolCapture C1** — no-panic + generous absolute ceilings; NOT a tight
  per-input amplification bound (wrong model for a fixed-overhead capture).
- **toolCapture C2/C3 (no-host-write)** — fingerprints the cwd subtree + ONE
  sibling sentinel (the traversal target); a write to an unrelated absolute path
  elsewhere on the host is caught by C3's "only under cwd" general rule but is NOT
  independently fingerprinted. Does NOT capture xattrs/ACLs (Fingerprint omits
  them), NOT a write-then-restore within one run, NOT bundle CONTENT/redaction
  correctness. In the HOT loop the collector data source is SEAMED (a cheap
  deterministic stub) — the collectors' own read-only behaviour is verified by the
  unseamed `TestMC4RealCollectorNoHostWrite`, which runs only a handful of times.
  The `--allow-absolute-paths` opt-out is tested as the red/green escape case, not
  asserted safe (it is a deliberate operator choice).
- **All targets (third-party)** — the DECODE/transport layer only; dsd's own
  callers above it (`config.Load`'s symlink/owner gates, `output.SanitizeControl`)
  are tested elsewhere, not here.

## 7. Ranked LEFTOVERS (highest security value first)

1. **Decode-time bound for `--config`, not just a size cap (F1 follow-up).** The
   proposed 1 MiB size cap bounds the worst case but a 1 MiB adversarial flat-YAML
   is still ~tens of seconds. A `context`-deadline around `ReadInConfig` (or the
   upstream O(1) duplicate-key fix landing in go.yaml.in/yaml/v3) is the real
   remedy. Decide the production posture and either ship the size cap now
   (patch ready) or wait on upstream.
2. **V4 services differential has no live consumer today.** `cfg.Services` is the
   consumer path; no code reads `viper.Get("services")` directly, so a V4
   divergence is a latent footgun, not an active bug. If a future consumer ever
   reads the slice through viper, V4 becomes load-bearing — worth a reachability
   re-check then.
3. **toolCapture content/redaction at the MCP layer.** This target proves the
   WRITE is contained; it does NOT verify the bundle's CONTENTS are correctly
   sanitized when `sanitize`/`identifiers` are set, nor that `redactMCPJSON` floors
   secrets in the `dsd_health`/`dsd_replay`/`dsd_diff` responses. A content-oracle
   target (decode the written bundle, assert no secret-shaped bytes under
   `sanitize=true`) is the next write-path gap.
4. **Full-filesystem no-write assurance.** C2/C3 fingerprint cwd + one sentinel.
   A target that fingerprints a broader synthetic root (e.g. a fake `$HOME`,
   `/tmp`, and cwd) around the real collector sweep would raise the no-host-write
   claim from "nothing escaped cwd or the sentinel" to "nothing anywhere in these
   roots changed".
5. **ansi width vs a real terminal.** W1–W4 are structural (ESC counts, width
   bounds); none verifies StringWidth matches a specific terminal's grapheme/
   east-asian rendering. Only relevant if dsd ever sets a width on host text
   (lipgloss sets none today), so low priority.
6. **viper rejection-reason coverage.** V1–V4 only judge ACCEPTED docs; a target
   that asserts WHY each malformed doc was rejected (the right error class per
   input) would catch a validator that accepts an out-of-schema value and
   dispatches it. Analogous to the mc3 M5 leftover.
