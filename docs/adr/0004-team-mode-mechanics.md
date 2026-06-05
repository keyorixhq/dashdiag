# ADR-0004 — Team mode: two surfaces, one cost-line gate

**Status:** Proposed (drafted ahead of GTM so the decision is ready the day signups arrive)
**Date:** 2026-06-05
**Deciders:** Andrei Beshkov (founder) — pending
**Context source:** Resolves the `[DISCUSS] Team mode — how should it work?` item in
BACKLOG.md. Builds on ADR-0001 (persistence is the platform), ADR-0002 (teams are the
wedge), `docs/fleet-design.md` (`dsd fleet` SSH design), and `docs/SHARE_DESIGN.md`.

---

## Context

"Team mode" is named in three places that do not yet agree, and the disagreement is the
whole decision:

1. **`docs/fleet-design.md`** describes `dsd fleet` as an **agentless SSH coordinator** that
   runs on your own laptop/jump host, SSHes into each server, runs `dsd health --json`, and
   aggregates locally. It states plainly: *"No dashdiag.sh server involved… your data never
   leaves your network."* Yet it also lists `dsd fleet` as the **Pro €79/yr** feature.
2. **ADR-0001** says the paid product is the **hosted** fleet dashboard at dashdiag.sh — the
   CLI is the agent, the platform is the product — gated because the backend costs us money
   to run.
3. **`docs/SHARE_DESIGN.md`** adds a third notion: a "team workspace" that organises shared
   snapshots under an org account, with SSO/audit.

The contradiction: **a feature that runs entirely on the user's machine against an
open-source binary cannot be paywalled.** Anyone can delete the license check and rebuild —
and per ADR-0001 / COMPANY_PRINCIPLES Principle 1 we have *committed* the CLI stays free and
open forever. So pricing `dsd fleet` (a local SSH loop) at €79/yr is unenforceable and
off-principle. Meanwhile the genuinely gateable thing — hosted history, a persistent
cross-node dashboard — is the thing teams actually pay for (ADR-0002 Decision 1).

## Decision

**Team mode is two distinct surfaces, and only the backend-backed one is paid. The gate is
the cost line (ADR-0001), never a license check on a local binary.**

### Surface 1 — `dsd fleet` (local, free, open source)

Stays exactly as `docs/fleet-design.md` designs it: SSH fan-out from the operator's machine,
self-copying binary, parallel `dsd health --json`, local aggregation. **No server, air-gap
compatible, free forever.** This is *not* the paid tier. It is a power-user feature that
makes the open-source tool obviously better for anyone managing more than one box — and it is
the **demo that sells the hosted tier**: once someone is running `dsd fleet health` across 20
boxes from their laptop and wanting it to *remember* yesterday, the upgrade writes itself.

> This reverses `fleet-design.md`'s "Monetization" section, which lists `dsd fleet` as the
> €79/yr feature. That section is superseded by this ADR: `dsd fleet` is free; what's paid is
> persistence + the hosted dashboard below.

### Surface 2 — `dsd fleet --push` → hosted dashboard (the paid team product)

The paid tier is everything that requires infrastructure **we** run and therefore can gate
honestly:

- **Persistent cross-node history** — snapshots pushed to the account (ADR-0001 layer 2), so
  "which nodes regressed since last week" becomes answerable. A stateless local loop cannot
  do this at any quality.
- **The web fleet dashboard** — all nodes, what's red, trend lines, searchable freeze-frames
  (ADR-0001 layer 3).
- **Shared team state** — multiple operators see the same fleet, the same history, the same
  acknowledged/silenced alerts. Org-scoped.
- **Alerting** — "db-01 SMART reallocated-sector count is climbing" by email/webhook.
- **Audit** — who ran what, who acknowledged what.

The free→paid line is therefore identical to ADR-0001's: **local is free (including the SSH
fleet loop); anything that lives on our backend is paid.** Nothing about the CLI is locked.

## The four `[DISCUSS]` sub-questions, answered

**Sharing model.** Two mechanisms, already designed, kept distinct:
- *Ephemeral share* (`--share`, `docs/SHARE_DESIGN.md`): one snapshot, public/expiring link,
  E2E-encrypted, freemium — for "look what prod-db-01 showed me" virality.
- *Persistent fleet* (`--push`, this ADR): durable org-scoped history feeding the dashboard.
  Same upload plumbing, different retention + access model.

**Identity / auth.** Account is required only to `--push` or view the dashboard — never to run
the CLI. Start with email + OAuth (GitHub/Google) for self-serve; **SSO/SAML is a Team-tier
upsell, not table stakes** (matches SHARE_DESIGN's tiering). Org = billing boundary; users
join an org; nodes belong to an org via an enrolment token baked into `--push`.

**Monetisation boundary.** The cost line. Collect-and-render-locally = free. Store-on-our-
infra / view-on-our-web / notify-via-our-pipes = paid. This is mechanically enforceable
(the backend simply refuses unauthenticated pushes / rejects over-quota free accounts),
unlike a local license check, and it is on-principle.

**Privacy / trust.** Three postures, descending by sensitivity:
- *Most private:* `dsd fleet` local — data never leaves the network (air-gapped MSPs, banks).
- *Opt-in ephemeral:* `--share` — E2E encrypted, expiring, the user chooses each time.
- *Opt-in persistent:* `--push` — org-scoped, retained; **and for customers who won't send
  data off-prem at all, ADR-0003's self-hosted/air-gapped platform is the same dashboard run
  on their own infra under licence.** The collector layer is identical across all three;
  only where the snapshot lands differs.

## Consequences

- `fleet-design.md` Monetization section must be updated to point here (`dsd fleet` = free).
- The enrolment-token + org model becomes a schema requirement for the ADR-0001 Store from
  day one (host-identity + org-id fields), so the local JSONL snapshot already carries what
  the dashboard needs — no painful post-users migration.
- Build order is unchanged from ADR-0001: local store → `--push` → dashboard. `dsd fleet`
  (free, local) can ship **before** any backend exists and starts manufacturing the demand
  that justifies building the paid surface.
- We must never ship a feature whose only "paid" enforcement is a flag in the open-source
  binary. If a capability can't be gated at our infrastructure boundary, it's free.

## Open questions (carried forward)

1. Node-count quota for free `--push` (ADR-0001 says "1 node free" — does the *local* fleet
   loop staying free make a 1-node push limit feel stingy, or is that the right wedge?).
2. Does `dsd fleet --push` enrol nodes individually, or push the operator's aggregated view
   as one document? (Affects per-node alerting fidelity.)
3. MSP multi-tenant: one operator account, many client orgs — billing and data isolation
   model (touched in fleet-design "per-client fleet configs"; needs its own decision).
4. Self-hosted dashboard (ADR-0003) and SaaS dashboard from one codebase — how much config
   forks vs shares.
