# ADR-0001 — Persistence is the platform foundation, not a CLI feature

**Status:** Accepted
**Date:** 2026-06-04
**Deciders:** Andrei Beshkov (founder)
**Context source:** Strategy session 2026-06-04, building on the baseline/drift
design (`docs/SHARE_DESIGN.md`, `docs/fleet-design.md`) and the deferred
`spec-baseline-drift.md` Store-interface draft from 2026-05-29.

---

## Context

DashDiag is currently a pure point-in-time tool: it reports what is wrong *now*
and keeps no memory between runs. This is excellent for a single operator on a
single machine — and that is precisely the monetisation problem. A solo user
gets the full diagnostic value for free, forever, with no recurring need and no
expanding surface. There is no forcing function toward payment.

The recurring question — "how do we store data between runs to analyse drift" —
is therefore not just a feature question. The answer determines whether DashDiag
can ever be more than "another good open-source tool you don't pay for."

## Decision

**The CLI stays open source forever. The paid product is the hosted platform.
The persistence layer is the architectural prerequisite for every team feature,
and it is built as layer one of the push-to-backend path — not in isolation.**

Concretely, the build order is:

1. **Local JSONL store (free, ships with the CLI).** Each run appends a small
   snapshot to `~/.dsd/` (non-root) or `/var/lib/dashdiag/` (root). Enables
   local `dsd diff`, drift correlation rules, and richer timeline. Purely local,
   fully free, and makes the tool better for solo users.
2. **`--push` to dashdiag.sh (the revenue gate).** After collecting, push the
   snapshot to the user's account; first run returns a URL. This is the existing
   `--share` stub, implemented for real. Free tier: limited history / 1 node.
   Pro: unlimited history, unlimited nodes.
3. **Fleet dashboard at dashdiag.sh (what teams pay for).** Web UI showing all
   nodes, which are red, trending metrics, searchable freeze-frames. The CLI
   becomes the agent; the platform becomes the product.

> **Later revision (2026-06-04, see ADR-0003):** "the paid product is the *hosted*
> platform" holds for the connected/SaaS path above, but it is not the only
> commercial model. For datacenter/cloud providers and air-gapped customers who
> will not send data to dashdiag.sh, the platform is hosted **by them**, on their
> premises, and the commercial model is licence + support rather than hosting.
> The CLI/collector layer is identical across both; the platform layer forks.
> ADR-0003 records this split.

**Storage format: append-only JSONL, behind a `Store` interface.** Zero
dependencies, cross-compiles cleanly (critical for the Mac → `GOOS=linux
GOARCH=amd64` workflow), human-inspectable. If scale ever forces a database,
only `modernc.org/sqlite` (pure Go) is acceptable — never cgo `mattn/go-sqlite3`,
which would break the cross-compile pipeline. The `Store` interface exists so
this swap is invisible to callers. Default is a `NullStore` (no-op) so the tool
stays pure-read unless persistence is opted into.

**Schema is designed with the fleet view in mind from day one.** Migrating a
snapshot schema after there are users is painful; the local snapshot must already
carry the host-identity and trendable-metric fields the dashboard will need.

## Why open source is a feature, not a liability

This follows the Grafana / PostHog / Metabase model: the agent/CLI is open
source and always will be; the platform is paid. Open source means zero
procurement friction, no security review required for the agent, and community
contributions to collectors. The moment someone asks their team to install it,
it gets evaluated on the GitHub page — and being open source passes that
evaluation automatically.

**The mistake would be locking CLI features.** The correct gate is: the CLI is
free forever; history, fleet view, and shared team state require an account.
This is already the line drawn in `COMPANY_PRINCIPLES.md` Principle 1 — the
free/paid boundary follows the cost line (local is free; backend infrastructure
that costs us money to run is paid).

## Consequences

- The persistence layer must not be built as an isolated "drift" feature. Every
  schema and storage decision is made in service of the eventual push + dashboard.
- `dsd timeline` is complementary, not a replacement: timeline reconstructs the
  past from existing logs (journald, dmesg); the Store remembers what DashDiag
  itself observed, including values that never appear in those logs (SMART
  reallocated-sector deltas, EDAC/ECC counts between snapshots).
- Collectors stay pure (emit current values only). The analysis layer gains
  read access to `Store.History` to compute drift slopes.
- The backend is a much larger build than anything in the current backlog (auth,
  storage, web UI, billing, operational burden). It must not be started before
  signups validate which monetisation path to build first (see ADR-0002).

## Status of open questions (unresolved, carried forward)

1. Default-on or opt-in for persistence in the first cut?
2. Snapshot dir + permissions across the distro matrix (ties into `platform.Profile`).
3. Retention defaults — count vs. age?
4. Does freeze-frame reuse the deep-output log-line selector, or need its own?
5. Host-identity key when running inside containers vs. on the PVE host.
