# ADR-0002 — Monetisation paths and how the landing page decides between them

**Status:** Accepted (method); monetisation path deliberately undecided pending data
**Date:** 2026-06-04
**Deciders:** Andrei Beshkov (founder)
**Context source:** Strategy session 2026-06-04. Refines `COMPANY_PRINCIPLES.md`
Principle 1.

---

## Context

ADR-0001 establishes that the paid product is the hosted platform. This ADR
addresses two questions left open by it: *who pays*, and *how do we decide which
monetisation path to build first* without committing limited runway on reasoning
alone.

## Decision 1 — Three monetisable populations, one backend

The earlier assumption that "tools like this can't monetise individuals" was too
broad. It conflated two different groups:

- **Hobbyists managing their own single machine** — genuinely hard to monetise.
  Run it, fix it, close the terminal. No recurring need. These stay free forever
  and are propagation/goodwill capital (per Principle 1).
- **Professionals who manage servers for a living but aren't on a software-buying
  team** — a large, underserved, monetisable group.

The three monetisable populations, all served by the *same* push-to-backend
infrastructure (build once, serve all three):

| Population | What they pay for | Why it monetises |
|---|---|---|
| Solo consultants / MSPs | Shareable, branded, professional report (`dsd report --pdf`, white-label) | The deliverable is billable-hour leverage — value is the artifact handed to the client, not the diagnosis |
| Small operators (3–10 VPSes) | Hosted history + "your disk is failing" email alerting | Convenience and peace of mind that compounds; survives a machine wipe; no setup |
| Teams (5+ ops on 20+ servers) | Fleet dashboard, cross-node history, shared state, audit | Cross-node questions are unanswerable by a stateless single-node tool at any quality |

## Decision 2 — Teams are the wedge, individuals are the complement

Individual monetisation is *viable* but not the *first wedge*, on runway maths:

- Individuals at ~€5/mo need enormous volume — ~800 subscribers for ~€50k/yr,
  implying ~40k+ free users given typical conversion. That is a marketing machine
  a solo founder with ~6 months runway does not have.
- One team deal at €79/yr × 20 seats is €1,580/yr from a single closeable
  conversation. Ten such deals is €15k from ten conversations.

So: build the backend once (ADR-0001); the team dashboard is the first revenue
target; the consultant report and hosted history/alerting are complements that
run on the same infrastructure. **The consultant/MSP report is the strongest
individual path** because the value (the client-facing artifact) is concrete.

## Decision 3 — The landing page is instrumented, not interrogated

Bare email capture cannot decide monetisation — it measures interest, not
willingness to pay, nor which feature opens the wallet. But adding fields to the
capture path kills conversion (founder's Microsoft-services experience: every
added field costs a 2–10× conversion drop). The resolution:

- **The conversion-critical path stays a single email field.** No segmentation
  question on it.
- **Audience type is observed, not asked.** UTM-tagged per-channel links
  (`?utm_source=reddit_sysadmin`, `hn`, `reddit_homelab`, MSP forums, etc.) plus
  the server-side `Referer` header map each signup to its source community at
  zero conversion cost. r/homelab skews hobbyist; r/sysadmin + HN skew
  professional/team; MSP forums skew consultant.
- **Willingness-to-pay is observed off the capture path** — see Decision 5 for
  the corrected design. A single priced button cannot separate the three
  populations, so the willingness-to-pay surface is an *un-priced* "See Pro plans"
  button leading to a three-tier plans page, with the click joined to the
  visitor's source community.
- **An optional post-submit question** ("which would you pay for: hosted history /
  fleet view / shareable reports?") lives *after* email capture, where a
  non-answer costs nothing; answers come from the highest-intent subset.

## Decision 4 — The actual decision comes from conversations, not counts

The instrumented page produces a segmented list at zero acquisition cost. The
monetisation path is then chosen from: which-tier-engaged (Decision 5) + source
community + ~10 direct conversations with the people who engaged a tier. The list
makes those conversations possible; it does not replace them. Raw signup counts
decide nothing.

## Decision 5 — One €79 button can't measure individual monetisation (correction, 2026-06-04)

The earlier draft of Decision 3 used a single fake-door "Pro — €79/yr" button.
That is wrong, and the flaw is worth recording so it isn't reintroduced.

**Why one button fails.** A single button collapses three different questions
("would a consultant pay for reports?", "would an operator pay for history?",
"would a team pay for a dashboard?") into one undifferentiated click. Worse,
€79/yr is a *team-shaped* price: an individual consultant who would happily pay
~€15/mo for white-label reports looks at "Pro — €79/yr" framed as one
enterprise-y tier and assumes it is not for them, so they do not click. The
single team-priced button therefore *suppresses* the individual signal and would
produce a false negative — "individuals won't pay" as a measurement artifact, not
a finding.

**The corrected design.** Two mechanisms, both still off the email-capture path:

1. **Source attribution does the population-typing for free** (already in
   Decision 3). A click from `utm_source=msp_forum` is a consultant
   willingness-to-pay signal; from `reddit_homelab`, an operator/hobbyist signal.
   So separating populations does not require multiple buttons — it requires
   *joining the click to its source*.

2. **A single un-priced "See Pro plans" button → a three-tier plans page.** The
   landing page keeps one clean, un-priced button (respects the single-CTA
   conversion discipline). The page behind it shows three differently-priced,
   population-shaped tiers:
   - Shareable client reports — ~€15/mo (consultant)
   - Hosted history & alerts — ~€5/mo (operator)
   - Team fleet dashboard — €79/yr (team)
   *Which tier the visitor engages* (expands / clicks "notify me") is the typed
   willingness-to-pay signal, and per-tier engagement also sanity-checks whether
   each *price* is roughly right. Friction here is cheap because intent is already
   earned by the time they reach the plans page.

Prices are placeholders for signal, not commitments. The explicit per-tier
framing is what makes the individual paths measurable — without it, the plan
could only ever validate the team tier.

## Consequences / sequencing (the part that protects runway)

- **Ship the instrumented landing page before building the backend.** The page
  is the cheapest test of every assumption in this ADR and in ADR-0001.
- Do not open the backend design doc on the strength of reasoning alone, however
  clean. Let a few weeks of segmented signups + per-tier engagement on the plans
  page + conversations pick the direction.
- **Current blocker (only the founder can clear it):** register `dashdiag.sh`,
  wire the Formspree endpoint (replace `REPLACE_WITH_FORM_ID` in the landing
  repo), then post UTM-tagged links to the target communities. Everything in this
  ADR sits behind those two manual steps.
- Landing-page changes still needed once the domain is live: add the un-priced
  "See Pro plans" button (off the capture path) → three-tier plans page, and the
  UTM link structure. Small HTML change, no backend required.
