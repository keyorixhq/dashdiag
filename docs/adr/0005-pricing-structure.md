# ADR-0005 — Pricing structure: consolidated tiers + the signals that commit them

**Status:** Proposed (placeholders only — prices are deliberately *not* committed here;
ADR-0002 Decision 4 reserves that for post-GTM conversations)
**Date:** 2026-06-05
**Deciders:** Andrei Beshkov (founder) — pending GTM data
**Context source:** Resolves the `[DISCUSS] Pricing strategy` item in BACKLOG.md by
consolidating prices currently scattered across ADR-0002 (Decision 5), `docs/SHARE_DESIGN.md`,
and `docs/fleet-design.md` into one table, and naming the exact signal that converts each
placeholder into a commitment. Does **not** override ADR-0002's "decide from conversations,
not counts."

---

## Context

Pricing numbers exist in three docs and don't sit in one place, so they read as commitments
when they are placeholders:

- ADR-0002 Decision 5: consultant report ~€15/mo, hosted history ~€5/mo, team dashboard
  €79/yr — explicitly "placeholders for signal, not commitments."
- `fleet-design.md`: `dsd fleet` Pro €79/yr (superseded by ADR-0004 — `dsd fleet` is free).
- `SHARE_DESIGN.md`: Starter $19–49/mo, Team tier with SSO; "don't fix prices until signal."

The BACKLOG `[DISCUSS]` item asks for: anchor price, per-host fee, and the open-core/paid-
cloud model. ADR-0001 already settled open-core (CLI free forever; backend paid). ADR-0004
settled *what* is paid (backend-backed surfaces only). What remains genuinely open is the
**packaging shape and the numbers** — and those are gated on willingness-to-pay data the
instrumented landing page (ADR-0002) is built to produce.

## Decision

**Open-core is settled (ADR-0001). The packaging is one freemium ladder with three paid
populations on one backend. The numbers below are placeholders; each is committed only when
its named signal arrives.** This ADR fixes the *structure* and the *decision triggers*, not
the prices.

### The consolidated ladder (placeholders)

| Tier | Population (ADR-0002) | Placeholder | Gated by (ADR-0004 cost line) | Commit trigger |
|---|---|---|---|---|
| **Free** | Hobbyist + all CLI users | €0 forever | nothing — fully local incl. `dsd fleet` | n/a (committed) |
| **Reports** | Solo consultant / MSP | ~€15/mo | hosted report render + white-label | ≥N `msp_forum` plan-clicks **and** ≥3 confirming convos |
| **History** | Small operator (3–10 VPSes) | ~€5/mo | hosted snapshot retention + alert emails | ≥N `reddit_homelab`/`sysadmin` history-tier clicks + convos |
| **Team** | Team (5+ ops, 20+ nodes) | €79/yr (per-seat or per-org TBD) | fleet dashboard + shared state + SSO | first closeable team conversation (ADR-0002 maths: 1 deal = €1,580/yr) |
| **Self-hosted** | Provider / air-gapped | licence + support (ADR-0003) | their infra, our licence | a provider trial that completes (ADR-0002 Decision 6) |

### Anchor and per-host

- **Anchor = the Team tier (€79/yr).** It is the wedge (ADR-0002 Decision 2) and the only
  tier whose unit economics close on a solo founder's runway (ten conversations → €15k).
  The individual tiers anchor *below* it so a consultant doesn't self-disqualify by reading
  a team-shaped price (the exact failure ADR-0002 Decision 5 records).
- **Per-host vs per-seat is explicitly unresolved.** `dsd fleet` being free (ADR-0004) means
  we are *not* charging per managed host for the local loop. The paid dimension is backend
  scope. Open question: does Team bill per **seat** (operators with dashboard logins) or per
  **node** (hosts pushing history)? Per-seat aligns with "teams pay for shared state"; per-
  node aligns with infra cost. **Lean per-seat** (predictable for the buyer, decouples price
  from fleet size which `dsd fleet` made free) — but this is a trigger-gated decision, see
  below.

### What stays deliberately undecided (and the signal that decides it)

Per ADR-0002 Decision 4, raw counts decide nothing; tier *engagement joined to source* +
~10 conversations decide. Concretely:

1. **Do individuals monetise at all?** → per-tier plan-page engagement split by UTM source
   (ADR-0002 Decision 5's three-tier un-priced page). If Reports/History tiers get
   near-zero engagement while Team does, collapse to Team-only and stop building individual
   surfaces.
2. **Per-seat vs per-node for Team?** → decided in the first ~3 team conversations: ask how
   they'd expect to be billed. Don't guess from the page.
3. **Exact numbers** → the un-priced "See Pro plans" page measures whether each *placeholder*
   feels roughly right (engagement vs bounce per tier); real numbers are set in the closing
   conversations, not on the page.
4. **Annual vs monthly** → Team is annual (€79/yr) to match buying cycles; individual tiers
   monthly to lower the trial barrier. Revisit if churn data contradicts.

## Consequences

- No price in this ADR or any doc is a public commitment until its trigger fires; the landing
  plans page (ADR-0002) shows them as signal instruments, not a price list.
- The billing dimension (seat vs node) must not be hard-coded into the backend schema before
  it's decided — the Store should record both per-node enrolment **and** per-seat membership
  (ADR-0004 already requires both), so either billing model is implementable without
  migration.
- This ADR supersedes the standalone price mentions in `fleet-design.md` (€79 for `dsd fleet`
  — now free) and consolidates SHARE_DESIGN's Starter/Team numbers into the Reports/Team rows.
- Until GTM produces the signals above, the *only* pricing action is keeping the placeholders
  consistent across docs and the plans page. No tier is built ahead of its trigger.

## Open questions (carried forward)

1. Free `--push` allowance — 1 node (ADR-0001) vs a small free fleet — interacts with whether
   `dsd fleet` being free makes a 1-node history limit feel stingy (shared with ADR-0004 Q1).
2. White-label / report tier: one-off per-report pricing vs subscription (consultants may
   prefer per-deliverable).
3. Provider licence shape (per-socket, per-node, flat site licence) — deferred to ADR-0003's
   first completed trial.
