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

### 4. Exit codes

| Code | Meaning |
|------|---------|
| `0`  | OK — no WARN or CRIT findings |
| `1`  | WARN — at least one WARN, no CRIT |
| `2`  | CRIT — at least one CRIT |

`--json` always exits with the code matching `verdict`. These mappings are stable.
Monitoring integrations (`--nagios`) follow the Nagios convention (0/1/2) and are
likewise stable.

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
