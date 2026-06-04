# ADR-0003 — On-prem / air-gapped commercial model (the second business)

**Status:** Accepted (direction); build deferred — Tier 1 available today, Tier 2 gated on a real buyer
**Date:** 2026-06-04
**Deciders:** Andrei Beshkov (founder)
**Context source:** Strategy session 2026-06-04, continuing ADR-0002 Decision 6.
Partially revises ADR-0001's "the paid product is the *hosted* platform."

---

## Context

ADR-0001 framed the paid product as the platform *hosted by us* at dashdiag.sh.
Two questions in this session pushed past that frame:

- A customer manages **air-gapped infrastructure at scale** and will never connect
  to dashdiag.sh. How does collection work entirely inside his perimeter?
- Can a **datacenter / cloud provider** run the air-gapped model — hosting *all*
  DashDiag data on their own premises, including their customers' VM diagnostics?

Both answers are yes, and together they reveal that DashDiag has **two distinct
commercial models**, not one. This ADR records the fork.

## The fork — two businesses, one collector

| | Connected / SaaS (ADR-0001) | On-prem / air-gapped (this ADR) |
|---|---|---|
| Who hosts the platform | We do (dashdiag.sh) | The customer does, inside their perimeter |
| Data location | Our infrastructure | Never leaves the customer |
| Commercial model | Recurring subscription (we host) | Licence + support (they host) |
| We can see usage / iterate | Yes | No — we support blind |
| Update cadence | We push continuously | They upgrade on their schedule; we support old versions |
| Data-boundary objection | Real (esp. provider holding customers' data) | **Dissolved** — that's the selling point |

**The collector layer is identical across both.** The static `dsd` binary +
`--json` + local JSONL store (ADR-0001) is the same artifact in both worlds. The
fork is entirely at the *platform* (aggregation/dashboard/storage) layer.

## Why on-prem is the *natural* fit for the provider/air-gapped segment

The data-boundary problem that dogged the provider org-account idea (ADR-0002
Decision 6 — a provider's tenant holding *their customers'* diagnostics on *our*
SaaS) **disappears** under on-prem. "Our customers' telemetry never leaves our
datacenter / never touches a third-party vendor" is not a limitation for a
provider — it is a feature they sell to their own customers, and it sidesteps
GDPR / data-residency exposure (relevant for an EU/Spain-based operation).
Air-gapped/regulated buyers — defence, finance, critical infra, government,
sovereign-cloud providers — are underserved precisely because most modern tooling
is SaaS-only, and they pay well for on-prem.

So the on-prem appliance — flagged in ADR-0002 as "the heaviest build, defer it"
— is the *most natural* commercial shape for this specific segment, more natural
than the multi-tenant SaaS. That partially inverts the org-account conclusion for
air-gapped customers.

## The honest counterweight — self-hosted is heavier, not lighter

The seductive misread is "they host it, so it's less work for us — it's just our
backend, installable." It is not. Self-managed software is a *different
engineering discipline*:

- We cannot hotfix; we support customers running versions months old.
- We debug blind, from log bundles they mail out of the air gap.
- We write install/upgrade docs for environments we cannot see.
- An OSS-core on-prem product can be self-hosted for free, so the *paid* thing
  must be something they cannot trivially replicate (the aggregation/dashboard
  layer, a commercial-use licence, and support).

Companies stand up entire separate tracks for self-managed editions (GitLab
self-managed, Grafana Enterprise). For a solo founder, a self-hostable multi-node
aggregation platform is arguably **heavier than the SaaS**, despite "they run it"
feeling simpler.

## The three tiers (increasing effort)

1. **Collector-only, they integrate — LIGHTEST, AVAILABLE TODAY.** They put the
   OSS `dsd` binary on their nodes, run `dsd --json` on a schedule (cron/systemd
   timer), and pipe output into *their own* existing aggregation (their Zabbix,
   Prometheus, ELK, internal dashboards). We ship nothing new. Revenue =
   commercial-use licensing and/or support. An air-gapped provider *already* runs
   internal aggregation (you can't run air-gapped at scale without it), so this is
   the diagnostician-not-monitor positioning (ADR-0002) in its purest form: `dsd`
   is the OSS collector/diagnostician feeding *their* platform. **This may be all
   they want.**
2. **On-prem aggregation appliance — HEAVY, DEFERRED.** We package the dashboard +
   storage + trending as something they install and run inside their perimeter.
   Per-node / per-site annual licence. The real product if a provider says "we
   want the DashDiag fleet view, but hosted by us." Genuinely lucrative for
   air-gapped/regulated buyers — but it is the separate-engineering-track
   commitment above. **Do not build speculatively. Gate on a real buyer with a
   budget asking for it.**
3. **Hybrid (local aggregation + optional provider-controlled scrubbed sync) —
   LATER, IF EVER.** Almost certainly more complexity than value for a long time.

## Decision

- **Serve the air-gapped / provider-on-prem segment with Tier 1 now.** It needs
  essentially nothing new beyond what ADR-0001 already plans (static binary,
  `--json`, local store). Sell commercial licensing + support, not hosting.
- **Treat Tier 2 (on-prem appliance) as a distinct, deferred product line**,
  validated only by a real buyer with budget. Price it to reflect that it is a
  separate engineering commitment, not a re-skin of the SaaS backend.
- **Record that the strategy now has two commercial models**, unified at the
  collector layer and forking at the platform layer. ADR-0001's "paid product is
  the *hosted* platform" is true only for the connected path; for air-gapped it is
  licence + support for a platform they host.

## Consequences

- Keep the `Store` interface (ADR-0001) clean enough that "the aggregation point"
  can be *their* tool (Tier 1) or *our* appliance (Tier 2) without changing the
  collector. The `--json` contract is the integration surface for Tier 1 — treat
  it as a stable public API, since air-gapped customers will build against it.
- Do not let the lucrative-sounding Tier 2 appliance pull runway forward. It is
  the *third* heavy thing this session has surfaced (after the SaaS backend and
  the multi-tenant org account). All three are real; none is the wedge.
- The wedge is unchanged and unbuilt: validate that *any* provider finds `dsd`
  useful (ADR-0002 Decision 6), via the two warm contacts and the landing page.

## Open question for a real air-gapped/provider buyer

When they say "on-prem," do they mean **(Tier 1)** "feed our existing internal
dashboards via `--json`" — or **(Tier 2)** "give us your dashboard to run
ourselves"? The answer decides whether this segment costs you nothing new or
becomes a separate product line. Ask before assuming Tier 2.

**Founder's lean (2026-06-04): Tier 1, but unconfirmed.** Reasoning: people tend
to use the tools they already have, and a provider running air-gapped at scale
*necessarily already runs internal aggregation* (Zabbix etc.) — you cannot
operate an air-gapped fleet without it. So they are not missing a dashboard; they
are missing a diagnostician to feed the one they have. That is the
diagnostician-not-monitor positioning, and it points at Tier 1 as the
lower-friction entry. **This is a lean with a reason, not a decision** — and the
founder explicitly flagged "I am not sure," which is the correct posture.

> **Guarded by COMPANY_PRINCIPLES.md Principle 3 (don't presume; tooling-state
> doesn't predict buying behaviour).** The Tier-1 lean must not harden into a
> decision on the strength of "their existing aggregation is capable" — capable
> tooling does not preclude wanting a separate diagnosis view, and (the
> counter-evidence) sophisticated orgs tolerate bad tooling for years (Microsoft
> clients running IPAM in Excel indefinitely). Tooling quality, good or bad,
> predicts nothing about adoption. Only the buyer's stated adoption behaviour
> resolves this.

**Why it stays genuinely open (the counter-scenario):** the Tier-1 lean assumes
the buyer wants the raw diagnostic *data* inside their existing tool. The opposite
is plausible — they keep Zabbix for *metrics-over-time* and want DashDiag's
*point-in-time root-cause-with-fix view* as a **separate** surface, precisely
because a Zabbix dashboard renders metrics, not "here is the diagnosis and the fix
steps." In that world they want Tier 2's dashboard *because* Zabbix structurally
can't show what `dsd` produces. First principles cannot distinguish these two
worlds; the provider can, in one sentence.

**Sharpened question for the actual conversation:** not "do you want on-prem"
(too coarse) but — *"when `dsd` finds a root cause with fix steps, do you want
that piped into Zabbix as data, or do you want a separate view that shows the
diagnosis itself? Would your existing dashboards render a root-cause verdict
usefully, or is that a different kind of thing for you?"* The answer to **that**
decides Tier 1 vs Tier 2 — and it is free to ask, expensive to guess. Do not
build either dashboard surface until it is answered by a real buyer.
