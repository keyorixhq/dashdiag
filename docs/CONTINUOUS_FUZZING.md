# Continuous fuzzing

DashDiag is fuzzed in three layers. Continuous discovery runs on dedicated
self-hosted rigs; CI runs bounded regression checks. **All rigs run one
standardized runner — the external `fuzz-harness` `fuzz-runner.sh`** — so
DashDiag, Keyorix, and the third-party-libs rigs share the same architecture
despite being different projects.

| Layer | What | Cadence | Crash reporting |
|---|---|---|---|
| **Continuous rig** (self-hosted, systemd `dashdiag-fuzz.service`) | Every `FuzzXxx` target, rotated one at a time, `FUZZTIME` each; targets DISCOVERED per rotation (never hardcoded) | Always-on (`Restart=always`) | Reproducer pushed to the **private** `fuzz-corpus` repo (`REPORT_MODE=private`); flakes filtered by the runner's re-verify guard; ntfy alert. **No public issue/PR.** |
| **Weekly full run** (`.github/workflows/fuzz.yml`) | Every target, sharded via `scripts/run-fuzz-targets.sh` | Weekly + `workflow_dispatch` | CI job failure; reproducer uploaded as a build artifact |
| **Per-PR regression** (`.github/workflows/fuzz-changed.yml`) | Fuzz targets in the packages a PR changed (dep bumps fan out), brief `FUZZTIME`, seeded from committed corpus | Every PR | CI job failure; new crash input uploaded as a build artifact |

## The rig runner (fuzz-harness)

The runner, its config schema, the crash **report sink** (`REPORT_MODE`:
`local` / `private` / `pr` / `issue`, defaulting to `private` for this
security product), the exec-rate-scaled slice reweighting, and the
re-verify-before-alert guard all live in the **`fuzz-harness`** repo
(`keyorixhq/fuzz-harness`, `fuzz-runner.sh` + `examples/dashdiag.conf`). The
rig deploys a standalone copy of the runner and a per-project `fuzz.conf`; see
that repo for operational detail. Each rig's systemd unit's `ExecStart` points
at `fuzz-runner.sh`.

> Historical note: an earlier in-repo `scripts/fuzz-continuous.sh` +
> `scripts/fuzz-runlog.sh` subsystem posted every failing run's log to a public
> `fuzz rig: failing-run logs` tracking issue. That was superseded by the
> shared `fuzz-harness` runner (private crasher repo, no public log dump) and
> removed — a public issue that accumulates raw crash logs is a disclosure
> anti-pattern for a security product.

## Shared discovery

`scripts/fuzz-discover.sh` (target enumeration via `go list` + `go test
-list`) is used by the weekly run, the per-PR gate, and the Makefile, and is
the single source of truth for "every fuzz target in this module."
