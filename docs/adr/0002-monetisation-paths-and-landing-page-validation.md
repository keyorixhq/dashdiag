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
- **Willingness-to-pay is observed off the capture path.** A fake-door priced
  button ("Pro — €79/yr") sits next to the free download, not in the email flow.
  Click-through on a *priced* button is the closest pre-backend willingness-to-pay
  signal, and people who click it are a distinct, higher-value list. (Founder
  to weigh the honesty cost of advertising a tier that doesn't exist yet.)
- **An optional post-submit question** ("which would you pay for: hosted history /
  fleet view / shareable reports?") lives *after* email capture, where a
  non-answer costs nothing; answers come from the highest-intent subset.

## Decision 4 — The actual decision comes from conversations, not counts

The instrumented page produces a segmented list at zero acquisition cost. The
monetisation path is then chosen from: priced-button click-through rate + ~10
direct conversations with the people who clicked. The list makes those
conversations possible; it does not replace them. Raw signup counts decide
nothing.

## Consequences / sequencing (the part that protects runway)

- **Ship the instrumented landing page before building the backend.** The page
  is the cheapest test of every assumption in this ADR and in ADR-0001.
- Do not open the backend design doc on the strength of reasoning alone, however
  clean. Let a few weeks of segmented signups + priced-button clicks +
  conversations pick the direction.
- **Current blocker (only the founder can clear it):** register `dashdiag.sh`,
  wire the Formspree endpoint (replace `REPLACE_WITH_FORM_ID` in the landing
  repo), then post UTM-tagged links to the target communities. Everything in this
  ADR sits behind those two manual steps.
- Landing-page changes still needed once the domain is live: add the fake-door
  priced button (off the capture path) and the UTM link structure. Small HTML
  change, no backend required.
