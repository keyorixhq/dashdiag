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
| Willingness to pay | Fake-door priced button next to the free download | Zero — off the capture path |
| Which feature opens the wallet | Optional post-submit question | Zero — after email is captured |
| *Why* they'd pay + actual use case | ~10 conversations with people who clicked the priced button | The real work |

Raw signup counts decide nothing. The decision comes from priced-button
click-through + the conversations.

---

## Checklist (in order)

### Blocked on founder — only Andrei can do these

1. **Register `dashdiag.sh`** (~€35/yr, Namecheap, confirmed available).
2. **Wire the email capture** — replace `REPLACE_WITH_FORM_ID` in the landing
   repo (`keyorixhq/dashdiag-landing`, `index.html`) with the real Formspree
   form ID. Register a free Formspree form first.
3. **Connect the landing repo to Netlify** (`netlify.toml` already committed).

### Landing-page changes (small HTML, no backend) — do once domain is live

4. **Add the fake-door priced button.** A "Pro — €79/yr" button next to the
   free download/install. It links to an early-access capture page — it does NOT
   gate the free email field. Clicking it is itself the willingness-to-pay
   signal. People who only want the free CLI never see friction.
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

7. **Read the segments + priced-button click-through**, then **email ~10 people
   who clicked the priced button** for 15-minute calls. The conversations decide
   the path:
   - List skews consultant + report-button clicks → build the shareable report.
   - List skews company/team → build the fleet dashboard.
   - List skews small operators + history interest → build hosted history/alerting.

---

## What this protects against

Building the backend (auth, storage, web UI, billing — a much larger build than
anything in the current backlog) on the strength of reasoning alone, before any
signal confirms which population showed up or what they'd pay for. The page is
the cheapest possible test; the backend waits until the page has spoken.

## The honesty cost to weigh

The fake-door priced button advertises a tier that doesn't exist yet. Some
founders are uncomfortable with this. It's the one part of the method with a real
honesty cost — worth a deliberate decision rather than defaulting into it. An
"early access — coming soon" framing on the click-through page mitigates it.
