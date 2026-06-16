# ADR-0003: Raw input capture & replay

Status: Accepted (Phase 1 skeleton + Phase 2 capture/replay landed)
Date: 2026-06-14
Supersedes: none
Related: ADR-0002 (D6 support-offload / sanitization boundary), Gap Spec 9 (state.Store)

## Context

`dsd capture` records the **output** of the collectors (`dsd health --json` →
fixture YAML → `dsd mock` re-renders). That exercises the render / insight /
correlation layers, but it cannot help debug a collector or a parser: by the time
the fixture exists, the collector has already run and discarded the raw bytes it
read. SMART text, sysfs trees, `sensors` output — gone.

This is exactly where hardware-specific bugs live. AMD thermal (k10temp `Tccd*`,
the `Tctl` offset), EDAC ECC counters, amdgpu sysfs — none of it is reproducible
from a findings fixture. And our highest-leverage, bug-finding activity is
real-hardware validation on machines we get one or two shots at (a borrowed AMD
Proxmox host now; ARM / Oracle Ampere / Pi next). Each of those windows is scarce
and currently throws away everything except a rendered table.

## Decision

Introduce a `Source` interface that abstracts every raw system input a collector
reads — file contents, glob expansions, directory listings, external command
output — with three implementations:

- **Live** — reads the running system (production behaviour, the default).
- **Recorder** — wraps another Source and tees every read/exec into a `Bundle`.
- **Replay** — serves reads/execs from a `Bundle`, re-running the *real collector
  code* against recorded inputs offline.

A captured `Bundle` is a portable, re-runnable artifact: capture once on real
hardware, replay and debug forever on a laptop, then freeze the bundle into
testdata so the fixed bug stays fixed.

## Invariants

1. **Absent ≠ unrecorded.** A path that did not exist at record time replays *as*
   not-existing (the replayed error satisfies `errors.Is(err, os.ErrNotExist)`).
   A path that was *never recorded* returns `ErrNotRecorded` — a loud, distinct
   error. Replay never silently falls through to the live system; that would read
   the developer's own machine and manufacture a phantom-healthy result. This is
   the empty-looks-healthy bug pattern, designed out at the I/O layer.

2. **Faithful command semantics.** `Result` keeps stdout, stderr, and exit code.
   A non-zero exit is data, not an execution error (tools like `rpm --verify`
   report findings via exit code). Only a genuine exec failure (tool absent,
   context cancelled) returns a non-nil error — and "tool absent" is itself
   recorded, so it replays faithfully.

3. **Bundles are trusted-debugging artifacts.** They are raw and UNREDACTED
   (hostnames, IPs, serials, journald lines). Sanitization stays the job of the
   `--share`/`--push` path, never the capture path — consistent with ADR-0002 D6.
   A raw bundle is never auto-shared.

## Bundle format (raw-v1)

Directory (or `.tar.gz` of the same) layout:

```
manifest.json              # format, host, os, kernel, dsd version, created
files/index.json           # [{path, blob|not_exist|err}]
files/blobs/NNNN           # raw file bytes
globs.json                 # {pattern: [matches]}
dirs.json                  # {dir: [entry names]}
commands/index.json        # [{argv, stdout|stderr blob, exit, absent|err}]
commands/blobs/NNNN        # raw stdout/stderr bytes
```

The **file layer is keyed by the real absolute path**, which is deliberately the
same key `hack/hw-snapshot.sh` already emits via its `===== /path =====` dumps.
So the bash snapshot and a future `dsd capture --raw` produce interchangeable
file layers, and `source.FromSnapshot()` ingests a returned tarball directly —
the AMD investigation replays from the friend's tarball with no extra tooling.

Command replay from the bash script is best-effort only (its friendly labels —
`lscpu_json`, `ipmi_sensor` — do not encode argv); native `dsd capture --raw`
keys commands by canonical argv. Most AMD-relevant collectors (thermal, edac,
cpufreq, cpuinfo, amdgpu sysfs) are file-based, so the file layer alone unblocks
them; the command-based ones (smartctl, ipmitool, lspci, sensors) land in Phase 2.

## Known hard edges

- **Time-based collectors.** A few collectors sample over wall-clock (GPU busy %,
  PSI deltas, IO rates). Input replay cannot re-derive a sample; the recorder must
  capture the *sampled values* and replay must inject them. Finite, enumerated
  list — handled per-collector during migration, not by the generic Source.
- **Volume.** Full sysfs + journald can be large; the native `--raw` capture will
  carry an allowlist/bound. The skeleton does not yet.
- **Replay binary must match the captured host's OS.** Platform-specific
  collectors are build-tagged (`thermal_linux.go`, `edac_linux.go`, …), so the
  Linux parser only exists in a Linux binary. To replay an AMD Linux bundle and
  exercise the real Linux thermal/EDAC code, run `dsd replay` inside a Linux
  binary (an OrbStack container on Apple Silicon is enough). The bundle is
  portable; the replay binary is not. Replaying a Linux bundle on macOS runs the
  darwin stubs and can fall back to live reads — use it only for plumbing checks.

## Phasing

- **Phase 1 (done):** `internal/source` package — interface, Live, Recorder,
  Replay, Bundle persistence (dir + tarball), `FromSnapshot`. Standalone, tested.
- **Phase 2 (done):** routed `runCmd`/`runCmdOutput`/`runCmdTimeout` through an
  injected `source.Run` (locale-safe env preserved); added `readFile`/`glob`/
  `readDirNames` and migrated the thermal, cpufreq, and amdgpu-sysfs reads;
  shipped `dsd capture --raw` (one command → one tarball) and `dsd replay`.
  `dsd replay` runs only the migrated collectors (thermal, cpufreq, gpu) so it
  never serves dev-host data as the captured host's.
- **Phase 3 (todo):** migrate the remaining ~40 file-reading collectors and the
  `localeSafeCmd` direct callers; widen the replay collector set; add an
  enforcement test (mirroring `exec_locale_test.go`) forbidding direct
  `os.ReadFile`/`filepath.Glob` in collectors; fold captured bundles into testdata
  as golden replay fixtures.

`hack/hw-snapshot.sh` remains as the no-binary fallback — for a host where you
cannot get a `dsd` binary on. When a `dsd` binary is available, `dsd capture
--raw` is the one-command path and its bundles are natively replayable.

## Consequences

Real-hardware windows stop being disposable: each one becomes permanent,
re-runnable test capital. Cost is bounded because exec is already chokepointed
(`collector.go`, guarded by `exec_locale_test.go`) and the file-read migration is
finite and mechanical. The risk is partial migration leaking live reads on a
replay machine — closed by invariant 1 (loud `ErrNotRecorded`) plus the Phase 2
enforcement test.

Once replay is byte-stable (the determinism/ordering work guarded by the
`replay-hermetic` CI job), two captures of the same host become directly
comparable. `dsd replay <current> --diff <baseline>` replays both bundles
through the identical health pipeline and prints only what changed (per-check
status transitions, `--json` for machines) — the ADR-0002 D6 support workflow:
"diff a customer's healthy capture against the one taken when it broke" without
ever touching their machine. Reuses the existing `baseline.ComputeDiff` +
`render.PrintDiff` drift machinery.
