# MC4 — viper differential, ansi, toolCapture end-to-end, F1/F3 offline

Branch: `fuzz/mc4-viper-ansi-toolcapture` (stacked on mc3 → mc1). Working dir:
`/mnt/data/wave4/mc4` (standalone clone; commits land via a linked worktree, see
§Environment). Status: **IN PROGRESS** — this report is written early (rule: a
report must exist within 30 min) and updated as results land.

**Report path note.** `/mnt/data/wave4/out/` is outside the tool's allowed
working directory and is **unreadable/unlistable** from this session; whether it
is writable could not be confirmed. The authoritative, committed copy of this
report is in-branch at `.scratch/mc4-REPORT.md`. A best-effort copy to
`/mnt/data/wave4/out/mc4-REPORT.md` is attempted at the end.

## 0. Reading of the task (most-reasonable interpretation, stated up front)

Nobody answers questions in this unattended run. Where the brief was ambiguous I
took these readings and proceeded:

- **`CLAUDE.md` and `.scratch/mc1-REPORT.md` do not exist in this tree.** Neither
  file is present anywhere in the clone (confirmed by `find`). I relied instead
  on `.cursorrules` (the repo's agent guide), the committed `INVARIANTS.d/mc1-*`
  files, the in-branch `.scratch/mc3-REPORT.md`, and the mc1/mc3 commit history
  to reconstruct the LEFTOVERS. The mc1 leftovers 2/3/4/6 are inferred from the
  viper/ansi INVARIANTS docs and target comments, which name each gap explicitly
  (YAML quadratic = F1; Strip invalid-UTF-8 = F3; "[]Services slice not
  Get-compared"; "fuzz input capped below 1 MiB"; "real-handler/no-host-write not
  covered here").
- **"extend the config differential to the full 1 MiB"** = raise the per-input
  fuzz cap from 128 KiB toward 1 MiB (the real loader cap for implicit config)
  while keeping the known YAML-quadratic from dominating the bounded-work oracle —
  done by giving the quadratic its own characterised budget rather than hiding it.
- **"REAL toolCapture (not stubbed)"** = register the production `toolCapture`
  handler (real `safeBundlePath` + real `source.Recorder` + real
  `b.SaveTarball`) on a real `mcp.Server`, drive it over an `IOTransport` with a
  hostile-fuzzed `out_path`, and fingerprint a sentinel tree OUTSIDE the cwd plus
  the cwd itself to prove the only new/changed file is the bundle under cwd.
  Network stays OFF (default), so the collector sweep does no outbound dials.
- **"no production changes"** = all new code is `_test.go` + `INVARIANTS.d/` +
  `.scratch/`. The `--config` size-cap is delivered as a patch FILE under
  `.scratch/proposals/` verified in a scratch copy, never applied to
  `internal/config/config.go`.

## 1. Environment / constraints actually in force

- `go1.27.4`. `GOCACHE`, `GOMODCACHE`, `TMPDIR` per the runtime rules.
- **CPU temperature UNREADABLE** from this session (`/sys/.../temp1_input` is
  outside the allowed working dir — blocked). Per the fallback I rely on
  `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`, and 540 s chunks.
- **Standalone clone** (`git-dir == git-common-dir`): commits land via a linked
  worktree on the same branch, per the runtime git-hook rule.

## 2. What was built (fill in as it lands)

(pending)

## 3. Fuzz campaign log

(pending)

## 4. Findings

(pending)

## 5. F1 (YAML quadratic) bisection + proposals

(pending)

## 6. F3 (ansi.Strip invalid-UTF-8) upstream draft

(pending)

## 7. What each oracle does NOT verify

(pending)

## 8. Ranked LEFTOVERS

(pending)
