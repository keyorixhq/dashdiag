# UnpackOps Portfolio Principles

> **Scope:** Applies to all products under the umbrella brand —
> DashDiag, Keyorix, future RCA platform, future FinOps product.
>
> **Status:** Drafted 2026-05-10. Currently lives in the DashDiag
> repository for convenience; should relocate to a dedicated
> umbrella-brand repo during the deferred file-reorganisation.
>
> **Author:** Andrei Beshkov, founder.

---

## Why principles, written now

Small companies become big companies partly *because* their principles
were written down when they were small.

Stripe's "Working at Stripe" handbook existed when they were five
people. Basecamp's "Shape Up" predated their growth. By the time a
company is 50 people, principles get rewritten by committee and lose
their teeth.

These principles are written by the founder, in the first days of
the company, before there is pressure to compromise them. Future
versions of this team should treat them as the honest ones.

---

## Principle 1 — Free for individual use, forever

Every UnpackOps product offers a fully-functional free tier for
individual use. Not crippled. Not time-limited. Not feature-flagged
into uselessness.

**The line between free and paid is team coordination, not utility:**

- **Free forever:** the tool itself, all diagnostic and management
  capabilities for one person on one machine.
- **Paid tier:** shared state, multi-user dashboards, centralised
  reporting, audit logs, SSO, fleet management — anything that
  requires backend infrastructure or coordinates more than one user.

### How this maps across the portfolio

| Product             | Free (individual use)                   | Paid (team coordination)                              |
|---------------------|-----------------------------------------|-------------------------------------------------------|
| DashDiag            | Full CLI, all diagnostic capability     | `--share` backend, team dashboards, centralised RCA   |
| Keyorix             | Personal secrets vault                  | Team vaults, audit log, SSO, policy enforcement       |
| RCA platform (future) | Individual incident investigation     | Team incident management, on-call integration         |
| FinOps tool (future)  | Personal cloud-account viewing        | Multi-account aggregation, team budget governance     |

### Why this principle

- Aged-infrastructure operators, public sector, students, hobbyists,
  and ops engineers in lower-income regions all benefit fully.
- These users become **propagation vectors and goodwill capital** —
  the de-facto adoption layer that compounds over years.
- Paying customers come from companies with ops budgets, where the
  team-coordination tier becomes genuinely valuable.
- The architecture already draws this line cleanly: CLI / personal
  use is local; team features require backend infrastructure that
  costs us money to run. The free/paid line follows the cost line.
- Enforcement is honest: we do not ask *"are you commercial?"* — we
  only ask *"do you use team features?"*

### What we will not do

- Crippled "free trial" that downgrades after 14 or 30 days.
- Hidden feature flags in the OSS distribution that gate basic
  capability behind paid keys.
- Telemetry that tracks whether free users are "really individuals."
- Version-pinning or forced-upgrade pressure on free users.
- Surveillance of how the free tier is used.

### Regional pricing on the paid tier

When the paid tier reaches ~50 customers and operational maturity
allows it, regional pricing applies on the **paid** tier — not the
free tier — so engineers in lower-income regions can still afford
team features. This follows the JetBrains / Spotify / Netflix model
of honest purchasing-power parity.

---

## Principle 2 — Localisation as distribution

Every UnpackOps product ships with localisation in major languages
as a **first-class capability**, not a v3 afterthought.

The rule: **i18n architecture is mandatory from v1.0 in every
product.** Translations beyond the launch set arrive via community
pull requests over time — but the architecture must be there from
day one to make those contributions possible.

### Launch language set

Every product launches with translations in the languages where
we can vouch for native-speaker quality. Bad translation is worse
than no translation — it signals "we don't actually care."

At the time of writing (founder + close network):

| Language              | Reviewer / source                                  |
|-----------------------|----------------------------------------------------|
| English               | Default, native quality                            |
| Spanish (Spain + LATAM) | Founder + Spanish-speaking friends as review panel |
| Russian               | Founder native                                     |
| Chinese (Simplified)  | Trusted friend, native speaker                     |

This covers >2 billion potential users at launch. It is a stronger
footprint than most B2B tools achieve in their first three years.

### Languages beyond the launch set

Everything else is community-driven, by design:

- Portuguese, German, French, Hindi, Japanese, Italian, Polish,
  and any others arrive via GitHub pull requests from native
  speakers in the community.
- Translators are publicly credited in product docs and release
  notes.
- A community translator becomes an advocate. A hired translator
  is a one-shot transaction. The community model is structurally
  better, not just cheaper.
- This is the JetBrains / VLC / Linux model and it works at scale.

### What gets localised

- User-facing messages, insights, hints, error explanations.
- CLI help text, command descriptions, examples.
- Web UI text.
- Public documentation, where community translation is welcomed.

### What stays English

- JSON / YAML output — machine-readable contract for programmatic
  consumers.
- Debug logs — so issue reports are universally readable when
  debugging across regions.
- Source code, comments, commit messages, API responses.

### Why this principle

- Most localised users will not pay directly. They become
  propagation vectors. A LATAM ops engineer adopts → shares with
  their team → that team's parent company adopts → parent company
  pays for the team tier. The flywheel takes years and pays
  off compoundingly.
- Localisation at v0 means a 5-year flywheel of multilingual
  community. Localisation at v3 means catching up to competitors
  who got there first.
- Spanish at launch specifically: we are a Spanish-registered
  company building from Zaragoza. Shipping English-only to a
  Spanish-speaking market is a missed signal. Spanish at launch
  says "we are a Spanish company building globally" rather than
  "we are a US-style startup that happens to live here."
- It is also simply the right thing to do. Engineers maintaining
  global infrastructure deserve tools in their language regardless
  of where they sit on the global wage curve.

### Implementation rules

- **i18n architecture is mandatory from v1.0** in every product.
  No product ships v1.0 without the architectural affordances
  for localisation, even if only English is populated at first.
- **Launch translations** are limited to languages we can vouch
  for via native-speaker review. No machine-translated fallbacks.
- **DashDiag launch:** English + Spanish at v0.3 if achievable;
  Russian and Chinese added as the i18n pipeline matures. Build
  the architecture in v0.3, populate the launch set as quickly
  as quality review allows.
- **Keyorix launch:** same principle applies retroactively. Spanish
  and English minimum at launch; Russian and Chinese added before
  major public push. ENISA's 5-10 language commitment is a
  two-year window — doing the architecture right at launch
  de-risks that commitment, rather than treating it as a future
  scramble.
- **Future products** (RCA platform, FinOps tool): same pattern,
  no exceptions.
- Translation contributions welcomed via GitHub pull requests.
- Translators credited publicly in product docs and release notes.

---

## What these principles imply, in concrete decisions

When making a product decision, these principles should constrain it:

- **Pricing tier design** — free tier must be useful; paid tier gates
  team coordination, not basic utility.
- **Feature gating** — gate enterprise features (audit, SSO, fleet
  management), not core diagnostic / management capability.
- **UI architecture** — i18n affordances built from the start in
  every new product.
- **Community building** — translators, free-tier advocates, and
  educators are first-class community members.
- **Marketing voice** — "we serve everyone, enterprises pay for
  team coordination" — not "individuals get a taste."

If a future product or pricing decision contradicts these principles,
it should require an explicit, documented override. The default is
that these principles are followed.

---

## Future principles

This document will grow as more decisions become principles rather
than tactics. Likely candidates over time:

- Engineering principles (testing discipline, release cadence)
- Hiring principles (when the company grows beyond solo)
- Communication principles (HN voice, blog tone, CEO accessibility)
- Open-source principles (which parts of the stack are OSS, governance)

These will be added as they become clear, not speculated about now.
