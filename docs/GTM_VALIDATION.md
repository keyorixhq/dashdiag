# GTM Validation Playbook

**Status:** Active — blocked on domain registration + Formspree wiring
**Decision record:** `docs/adr/0002-monetisation-paths-and-landing-page-validation.md`
**Last updated:** 2026-06-04

This is the *how-to* for validating which monetisation path to build first.
The reasoning lives in ADR-0002; this is the checklist.

---

## The principle

The landing page is **instrumented, not interrogated.** Every field added to the
capture path costs a 2–10× conversion drop, so the conversion-critical path stays
a single email field. Everything we need to learn is either *observed* (free, no
friction) or moved *off* the capture path.

What we learn, and how:

| Signal | Method | Cost to conversion |
|---|---|---|
| Audience type (hobbyist / professional / consultant) | UTM-tagged per-channel links + server-side `Referer` | Zero — observed |
| Willingness to pay, *typed by population* | Un-priced "See Pro plans" button → three-tier plans page; which tier they engage = the signal | Zero — off the capture path |
| Which feature opens the wallet | Per-tier engagement on the plans page + optional post-submit question | Zero — off / after capture |
| *Why* they'd pay + actual use case | ~10 conversations with people who engaged a tier | The real work |

Raw signup counts decide nothing. The decision comes from which-tier-engaged
(joined to source community) + the conversations.

> **Why not a single "Pro — €79/yr" button?** It can't separate the three
> populations, and €79/yr is a team-shaped price — an individual consultant
> assumes it isn't for them and doesn't click, so a single button would report a
> *false* "individuals won't pay." Full reasoning: ADR-0002 Decision 5.

---

## Checklist (in order)

### Blocked on founder — only Andrei can do these

1. **Register `dashdiag.sh`** (~€35/yr, Namecheap, confirmed available).
2. **Wire the email capture** — replace `REPLACE_WITH_FORM_ID` in the landing
   repo (`keyorixhq/dashdiag-landing`, `index.html`) with the real Formspree
   form ID. Register a free Formspree form first.
3. **Connect the landing repo to Netlify** (`netlify.toml` already committed).

### Landing-page changes (small HTML, no backend) — do once domain is live

4. **Add an un-priced "See Pro plans" button → a three-tier plans page.** One
   clean button next to the free download (keeps the single-CTA discipline). It
   does NOT gate the free email field. The page behind it lists three
   population-shaped tiers, each with a "notify me" capture:
   - **Shareable client reports — ~€15/mo** (consultant / MSP)
   - **Hosted history & alerts — ~€5/mo** (small operator)
   - **Team fleet dashboard — €79/yr** (team)
   *Which tier a visitor engages* is the typed willingness-to-pay signal; per-tier
   engagement also tells you whether each price is roughly right. Prices are
   placeholders for signal, not commitments. (A single €79 button would suppress
   the individual signal — see ADR-0002 Decision 5.)
5. **Add the optional post-submit question** on the confirmation page:
   "We're planning a Pro tier — which would you actually pay for?"
   Options: hosted history / fleet view / shareable reports. A non-answer costs
   nothing because email is already captured.

### Distribution — generates the segmented list

6. **Post UTM-tagged links per channel.** Each community gets its own link:
   - `?utm_source=reddit_sysadmin`
   - `?utm_source=reddit_selfhosted`
   - `?utm_source=reddit_homelab`
   - `?utm_source=hn`
   - `?utm_source=msp_forum` (specific MSP/consultant community)
   The referrer + UTM maps each signup to its source community automatically.
   r/homelab → hobbyist; r/sysadmin + HN → professional/team; MSP forum →
   consultant.

### Decision — after a few weeks of data

7. **Read the per-tier engagement + source segments**, then **email ~10 people
   who engaged a tier** for 15-minute calls. The conversations decide the path:
   - Consultant-source + reports-tier engagement → build the shareable report.
   - Company/team-source + fleet-tier engagement → build the fleet dashboard.
   - Operator-source + history-tier engagement → build hosted history/alerting.

---

## What this protects against

Building the backend (auth, storage, web UI, billing — a much larger build than
anything in the current backlog) on the strength of reasoning alone, before any
signal confirms which population showed up or what they'd pay for. The page is
the cheapest possible test; the backend waits until the page has spoken.

## The honesty cost to weigh

The three-tier plans page advertises tiers that don't exist yet — a fake door.
Some founders are uncomfortable with this, and it's the one part of the method
with a real honesty cost, worth a deliberate decision rather than defaulting into
it. An "early access — coming soon, leave your email" framing on each tier
mitigates it: the visitor is told plainly the tier is planned, not live.
