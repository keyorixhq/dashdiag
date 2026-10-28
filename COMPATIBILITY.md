# Compatibility & Stability Policy

DashDiag follows [Semantic Versioning](https://semver.org/). Starting at **1.0.0**,
this document defines exactly what is covered by that promise — what you can build
against and rely on across the entire `2.x` series, and what you can't. (The `1.x`
promise ended at `2.0.0`, which shipped the breaking changes described in this
document's "Covered" section below — see CHANGELOG.md's `[2.0.0]` entry for the
full migration list.)

The short version: **`dsd health --json` is the stable platform API.** Everything
listed under "Covered" below will not change in a breaking way without a major
version bump (`3.0.0`). Everything under "Not covered" may change in any release.

---

## What "breaking" means

For the covered surface, a **breaking change** is any of:

- Removing a field, command, flag, or exit code
- Renaming a field or changing its type
- Changing the meaning of an existing field or an exit code
- Narrowing an enum (removing a possible value) or tightening accepted input
- Changing default behaviour in a way that alters output a consumer already parses

The following are **not** breaking and may ship in any `2.x` minor or patch:

- **Adding** a new field to an existing JSON object
- **Adding** a new enum value (consumers must tolerate unknown values — see below)
- **Adding** a new command, subcommand, or flag
- Adding a new insight, check, or correlation rule
- Changing wording of human-readable `message` / `hints` text
- Changing the content or shape of any `raw` object (see Not covered)

> **Consumer rule:** treat enums as open. A `status` or `level` you don't recognize
> should degrade gracefully (e.g. map unknown → treat as at least WARN), not crash.
> New severity-adjacent values may be added under `2.x`.

---

## Covered by the 2.x promise

### 1. `dsd health --json` top-level object

These top-level keys, their types, and their meanings are stable:

| Field       | Type     | Guarantee |
|-------------|----------|-----------|
| `hostname`  | string   | Always present |
| `os`        | string   | Always present |
| `timestamp` | string (RFC 3339 UTC) | Always present |
| `version`   | string   | Always present |
| `verdict`   | enum `OK` \| `WARN` \| `CRIT` | Always present; mirrors exit code |
| `counts`    | object `{crit,warn,info}` (integers) | Always present; keys stable |
| `checks`    | array    | Always present (may be empty) |
| `insights`  | array    | Always present (may be empty) |
| `coverage`  | object `{checked,not_checked,not_applicable}` (integers) | Always present (added in 2.6.0, additive); see §2 |

The authoritative machine-readable definition is `schema/dsd-output.json`, generated
from the `JSONOutput` struct in `internal/render/json.go`. The struct is the source
of truth; the schema tracks it.

### 2. `checks[]` entries

Stable fields per check: `name`, `status`, `duration`, `error`.

- `status` is one of `OK` \| `WARN` \| `CRIT` \| `INFO` \| `ERROR`.
- `ERROR` means the collector itself failed to run; `error` carries the message.
- `WARN`/`CRIT`/`INFO` are rolled up from the worst insight for that collector,
  **including subsystem-qualified insights** (a `CPU/Steal` CRIT correctly raises
  the `CPU` check's status).
- A collector that is not applicable to the host is **omitted**, not shown as `OK`.
  Consumers must not assume a fixed set of checks is always present.
- Since `2.0.0`, outbound network calls are off by default (see PRIVACY.md and the
  `[2.0.0]` CHANGELOG entry for the full list of affected calls). Two effects on
  this covered surface follow, both stable as of `2.x`: without `--network` /
  `DSD_ALLOW_NETWORK=1`, the `Network` and `NFS` checks' `status` degrades to
  `INFO` instead of a real verdict, and — on an actual cloud instance — the
  `CloudMeta` check is **omitted from `checks[]` entirely** rather than degraded
  (the same "not applicable" omission rule above, since cloud detection itself
  needs the network call it's gating).

#### Coverage (added in 2.6.0, additive)

`status` says what a check found; it cannot say whether the check looked. Every
`checks[]` entry now also carries `coverage`, and the top level a `coverage`
summary. Nothing existing changes: the `status` enum, the verdict and the exit
code keep their meaning (a not-checked item floors the verdict exactly as before:
see §4).

- `coverage` is `checked` \| `not_checked` on a `checks[]` entry.
- `coverage_reason` (present when not checked) is one of `needs_root` (a root-only
  read on a non-root run: re-run with sudo), `timeout` (a deadline passed),
  `unreadable` (a read failed: permission or I/O error), `collector_error` (the
  collector failed for another reason), `parse` (a tool ran but its output was not
  recognised), `not_recorded` (`dsd replay` only: the bundle never recorded the
  input, a recording gap and not a finding on the captured host) or `unverified`
  (fallback: no finer cause is known, e.g. a snapshot from an older dsd). `parse`
  and `not_recorded` are new, and `timeout`/`unreadable`/`collector_error` now also
  appear where `unverified` used to: additive, a consumer sees a finer value where
  it saw `unverified`. The same values are `not_checked_subchecks[].reason`, and an
  insight with `unverified: true` carries its own `unverified_reason` (omitted when
  unknown).
- **Partial rule.** A collector that ran and returned data is `checked`. Whatever
  part of it could not be read (an `unverified` insight it owns) is listed in
  `not_checked_subchecks` (`check`, `reason` = any not-checked reason above,
  `message`), and the collector counts in `coverage.partial`. A collector is
  `not_checked` only when it errored, timed out or panicked, or reports itself
  absent while an `unverified` insight says it could not look. "Nothing meaningful
  ran" is never inferred from insights. (`not_checked_subchecks` also appears on
  such an absent-but-unverified `not_checked` entry, listing why.)
- **Not applicable.** A collector with nothing to check on the host (no GPU, no
  Docker, not a cloud VM; nil data, or `Available=false`, and no insight) is
  `not_applicable`. It stays **out of `checks[]`** (the omission rule above is
  unchanged, so there is no phantom `OK`) and is listed in
  `coverage.not_applicable_checks[]` with `coverage_reason` `not_present` (the host
  has nothing of this kind) or `not_supported_platform` (the collector does not
  exist on this platform). A collector that is not even registered on this host
  (`dsd` gates many on a probe) never runs and is not counted.
- Top-level `coverage`: `checked` (checks that ran, partial ones included),
  `not_checked` (things not looked at: whole checks that did not run plus the
  sub-checks of partial ones, one per distinct check name; it equals what the
  terminal summary calls `NotRun + Skipped`), `not_applicable`, and the optional
  `partial`, `not_checked_reasons` (`{reason: count}`) and `not_applicable_checks`.
- The reason list is closed per release: adding a value is a minor change,
  renaming or removing one is breaking. `internal/render/coverage_guard_test.go`
  fails when a collector cannot resolve to exactly one coverage value.
- The same numbers reach every other output: the terminal summary line
  (`N checked · M not checked (reasons) · K not applicable`, with a Not checked
  group naming each item and the action), the Markdown and HTML reports,
  `dsd share` (all formats), Nagios (perfdata `checked=` `not_checked=`
  `not_applicable=` plus `NOT CHECKED:` long text) and Prometheus
  (`dsd_checks_coverage{coverage}`, `dsd_checks_not_checked{reason}`,
  `dsd_check_checked{check}`). Human-readable wording is not part of the contract.

### 3. `insights[]` entries

Stable fields per insight: `level`, `check`, `message`, `hints`, `details`.

- `level` is one of `INFO` \| `WARN` \| `CRIT`. OK-level insights are not emitted.
- `check` may be a bare collector name (`CPU`) or subsystem-qualified
  (`CPU/Steal`, `Network/DNS`, `Disk /var`). Consumers matching on collector
  should match by prefix, not equality.
- `message` and `hints` are human-readable; their **presence** is stable, their
  **exact text is not** — do not parse them.
- `details`, when present, has a stable envelope (`type`, `title`, `columns`,
  `rows`, `kv`, `note`) and a stable set of `type` discriminators.
- `unverified` (added in this release) is `true` when `level` reflects a
  downgrade because the underlying data could NOT be read/measured this run
  (permission denied, an unreadable file, a collector error) — not a genuine
  "nothing wrong here" finding. Additive, `omitempty`: existing consumers
  validating against the frozen schema are unaffected when it's absent.
- New "could not read" sentinels (DD-COLLECTOR-GAPS-1 task 2), all additive and
  `omitempty`, `true` only when that specific read failed — absent means no
  caveat: `disk.unreachable_mounts[]` (`mount`, `device`, `fstype`, `error`; a
  mount whose statfs hung or failed), `k8s.events_unreadable` /
  `k8s.pvcs_unreadable` / `k8s.workloads_unreadable`, and
  `tls.uncheckable[].needs_root`. Each also produces an `unverified` insight
  (or, for `dsd tls`, a non-ok status).
- Task 2b adds, same rules: `services_deep.masked_units_queried` (`true` when the
  masked-unit query ran, the opposite polarity of the others, like the existing
  `failed_units_queried`), and `logs.crash_loops_unverified` /
  `logs.crash_files_unreadable` / `logs.journal_size_unreadable` /
  `logs.journal_corrupt_unverified`. A permission-denied TLS scan root is now an
  `tls.uncheckable[]` entry instead of being dropped. Also additive:
  `services_deep.journal_verify_unverified` (`true` when the archived journals
  could not be verified; `journal_healthy` stays `true`). Capture bundles may
  contain an optional `direrrs.json`; readers that do not know it ignore it.
- Task 3 adds, same rules (`true` only when that read failed): `network.interfaces_unreadable`,
  `network.connections_unreadable`, `processes.list_restricted`,
  `processes.list_unreadable`, `rancher.server_unreadable`,
  `rancher.webhook_unreadable`, `cpu.usage_sample_failed`. `pve.ha_verified` is now
  `false` for a pvesh failure other than an explicit 501 (previously `true`). Each
  produces an `unverified` insight.
- Task 4 adds, same rules (`true`/non-empty only when that read failed):
  `kdump.state_unverified`, `tuned.state_unverified`, `thermal.sensor_unreadable`,
  `containerd.namespaces_unreadable`, `containerd.container_counts_unreadable`,
  `timeline.unread_sources[]`, `kvm_guest.steal_unreadable`, `swap.swaps_unreadable`,
  `swap.zram_unreadable`, `nfs.stats_unreadable`, `health_deep.mem_detail_unreadable`,
  `pressure.unreadable_metrics[]`. On macOS, `security.ssh_config_unreadable` is now
  set when no sshd_config could be read, and `packages` reports `checked: false`,
  `status: "query-failed"` when `brew outdated` fails (previously `checked: true`,
  0 updates).
- Task 5 adds, same rules: `cron.quality_scan_unreadable`. `cloud.spot_check_failed` is
  now also set when the termination probe was not recorded, `network.interfaces_unreadable`
  also when the I/O counters could not be read, and a macOS `FDLimits` sysctl failure is
  now a collector error (previously an empty result).

### 4. Exit codes

**Changed in this release** — a new code (3) was added; 0/1/2 keep their
existing meaning unchanged. Previously, a tool-internal failure (a panic, a
config load error, every collector erroring) had no distinct signal and
could read as exit 0 (looked healthy) or collide with exit 1 (looked like an
ordinary WARN) — see BUGS.md/CHANGELOG.md for the specific defect this
closes. Anything gating on exit code should treat `>= 1` as "look at it" and
`== 3` as "the tool itself did not produce a verdict" (config/policy error,
zero collectors ran, an unrecovered panic in a collector) rather than a
finding about the host.

| Code | Meaning |
|------|---------|
| `0`  | OK — all checks ran, nothing found |
| `1`  | WARN — at least one WARN or CRIT finding, or one or more checks could not determine something (an `unverified` insight, other than a root-only read skipped by a non-root run, below) with no CRIT present |
| `2`  | CRIT — at least one CRIT finding |
| `3`  | **New.** UNKNOWN — no meaningful verdict at all: an unparseable `--policy` file, zero collectors ran, or another fatal error before any check ran. Matches the Nagios plugin spec's reserved `UNKNOWN` code; `dsd health --nagios` already followed this convention and previously just never produced it. |

`--json`'s `verdict` field only ever reads `OK`/`WARN`/`CRIT` (a `checks[].status`
of `ERROR`, or any `unverified` insight, forces `verdict` to at least `WARN`
when it would otherwise read `OK` — see `counts.errored`/`counts.unverified`
to distinguish these from a genuine WARN finding without iterating
`insights[]`). Exit code 3 is a command-level failure (the process couldn't
produce a report at all) and has no corresponding `verdict` value. These
mappings, including the new code, are stable going forward.
Monitoring integrations (`--nagios`) follow the Nagios convention (0/1/2/3)
and are likewise stable — 3 there has always been reserved, per Nagios's own
spec, even though this dsd version is the first to ever produce it.

**Root-only reads skipped by a non-root run do not floor the verdict (2.5.0).**
An `unverified` insight that carries `needs_root: true` (a root-only file, log or
ioctl that a non-root `dsd` could not read) is shown as
`needs root: N checks skipped - re-run with sudo` but does not by itself turn an
otherwise OK run into WARN/exit 1. `needs_root` is only ever set when `dsd` is not
root; the same read failing as root is a plain `unverified` and floors. Any other
`unverified` insight and any errored collector still floors. `counts.unverified`
stays the truthful total; `counts.needs_root` is how many of them are root-only.
`dsd tls` follows the same rule: a root-only scan directory seen by a non-root run
stays in `uncheckable[]` with `needs_root: true` but does not raise `status` or the
exit code. Before 2.5.0 (2.4.0) every unverified insight floored, so a non-root
`dsd health` with no finding exited 1.

**All outputs agree with the exit code.** The "a run that could not verify itself
is not OK" floor above applies to every rendering of the verdict, not only
`--json`/exit/`--nagios`. For a run in which a collector errored or an insight is
`unverified` and nothing is WARN/CRIT (so exit code 1):

| Output | Before | Now |
|--------|--------|-----|
| terminal summary (human) | `✅ System healthy. Checks passed` | `⚠ Not fully verified: N checks could not run — see INFO below` |
| `--plain` / CI summary | `OK: All checks passed` | `WARN: Not fully verified: N checks could not run — see INFO below` |
| `--report` (Markdown) | `✅ **All checks passed** — system is healthy.` | `⚠️ **Not fully verified** — N checks could not run; see Issues below.` |
| `--report-html` badge | `HEALTHY` (class `ok`) | `NOT VERIFIED` (class `warn`) |
| `dsd share --format text` | `Verdict: OK — all checks passed` | `Verdict: WARN — not fully verified: N checks could not run` |
| `--prometheus` | `dsd_health_status 0` | `dsd_health_status 1` (and `dsd_check_status{check="x"} 1` for the affected check) |
| `--persist` history entry | `"verdict":"OK"` | `"verdict":"WARN"` (closed vocabulary unchanged) |

A run where every collector ran and nothing is WARN/CRIT prints exactly the
strings it always did. A script that greps for `All checks passed`/`healthy` and
treats a match as "all good" will no longer match on a run that could not verify
itself — that is the intent; gate on the exit code or `--json` `verdict` instead.

**The per-subcommand closing lines agree too.** `dsd cpu`, `db`, `disk`, `docker`,
`gpu`, `k8s`, `kvm`, `logs`, `net`, `processes`, `pve`, `security`, `steamos` and
`thermal` each end with a one-line summary. They used to derive "healthy" from the
subcommand's own per-section counts; they now ask the same `render.Verdict` and
the exit code is that verdict's. For a run whose collector errored or whose check
is `unverified`, with no finding of its own:

| Subcommand | Before | Now |
|------------|--------|-----|
| `dsd <sub>` closing line (human / `--plain`) | `✅ <X> healthy. Checks passed` (e.g. `Disk`, `Docker`, `CPU`, `Databases`, `Cluster`, `Proxmox VE`) | `⚠️ <X>: Not fully verified: N check(s) could not run — re-run with sudo / see the INFO lines above` |
| `dsd <sub>` exit code, collector errored with partial data | `0` (`pve`, `processes`: always `0`) | `1` |
| `dsd pve`, `dsd processes` whose collector returned no data and an error | exit `0`, no output | the collector's error, non-zero |
| `dsd pve`, `dsd processes` with a real WARN/CRIT finding | exit `0` | `1` / `2`, as every other subcommand (BUG-022 contract) |
| `dsd disk` unverified-read line | `Disk: checks passed, but some state could not be verified — run as root` | `Disk: no finding, but some state could not be verified — run as root` |

A fully verified run prints the same strings and exits with the same codes as
before. `--json` output of every subcommand is unchanged.

### 5. The `--blob` / `decode` round-trip

`dsd health --blob` emits a gzip+base64 report block; `dsd decode` reads it back.
The format is versioned internally; a `2.x` `dsd decode` will read any blob produced
by a `2.x` `dsd`. The blob is **encoded, not encrypted or redacted** — this is a
documented property, not a bug (see PRIVACY.md). That contract is stable.

---

## NOT covered — may change in any release

### `checks[].raw`

**This is the most important exclusion.** Each check's `raw` object is the collector's
full internal model, serialized as-is. It exists for debugging, `dsd capture`/`replay`,
and exploratory use — **not** as an API. Its fields may be added, renamed, retyped, or
removed in any release, including patch releases, with no notice and no changelog entry.

If you are building automation, read `verdict`, `counts`, `checks[].status`, and
`insights[]`. **Do not build consumers against `raw.*` fields.** If you need a value
from `raw` to be stable, open an issue requesting it be promoted to a first-class
insight or check field — that's the supported path to making it durable.

### `checks[].inline`

Pre-rendered human-readable drill-down text. Presence and content may change freely.

### Per-subcommand JSON (everything except `dsd health --json`)

`--json` output from other commands — `dsd fleet`, `dsd timeline`, `dsd tls`,
`dsd db`, `dsd net`, `dsd disk`, `dsd k8s`, etc. — is **best-effort**, not part of
the frozen platform API. These shapes (`incidents[]`, `issues[]`, `uncheckable[]`,
and the rest) are useful and we try not to churn them, but they are not bound by the
2.x promise. If you depend on one and want it frozen, open an issue and we'll
consider promoting it.

The single designated platform API surface is **`dsd health --json`**.

### Hidden / experimental flags

Flags hidden from `--help` (currently including `--share` and `--qr`, which are
unimplemented stubs) carry **no** stability guarantee and may change or disappear.
Only documented, visible flags are covered. A flag becomes covered when it ships
documented in a release.

### Internal packages

Everything under `internal/` is, by Go convention, private. There is no API
guarantee for importing DashDiag as a library. The supported interface is the CLI.

---

## Deprecation policy

When a covered surface must change incompatibly, we will, where practical:

1. Add the replacement alongside the old surface in a `2.x` minor.
2. Document the old surface as deprecated in the changelog and `--help`.
3. Keep the deprecated surface working until the next major (`3.0.0`).

Some changes (a genuine correctness fix to a wrong exit code, say) may not allow a
gentle path; those are called out explicitly in the changelog under **Breaking
Changes** and are reserved for major versions except where a field was actively
misreporting.

---

## Reporting a compatibility break

If a `2.x` release breaks something listed under "Covered" above, that's a bug —
please open an issue tagged `compat`. If you're relying on something under "Not
covered" and want it stabilized, open an issue and make the case; promotion from
best-effort to covered is exactly how this surface is meant to grow.
