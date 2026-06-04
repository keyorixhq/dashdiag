# ADR-0002 — Monetisation paths and how the landing page decides between them

**Status:** Accepted (method); monetisation path deliberately undecided pending data
**Date:** 2026-06-04
**Deciders:** Andrei Beshkov (founder)
**Context source:** Strategy session 2026-06-04. Refines `COMPANY_PRINCIPLES.md`
Principle 1. Decision 6 added the same day from two conversations with insiders
at one mid-size cloud/datacenter provider (head of networking + solutions sales).

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

## Decision 6 — Provider-shaped segments + diagnostician-not-monitor positioning (2026-06-04, from two conversations)

Two people at one mid-size cloud/datacenter provider independently described the
same pain from different functions. This sharpens "teams" (Decision 1) into named,
findable segments and surfaces a distribution channel. **Status: corroborated
pain hypothesis from two informed insiders — NOT validated demand. Neither has yet
committed to pilot, pay, or champion.** Treat as the strongest pre-launch signal
to date, not as confirmation.

### The two segments

| Segment | Source role | The pain (their angle) |
|---|---|---|
| Infra teams running VMware farms on big aging Linux-adjacent hosts | Head of networking dept | Huge servers hosting client VMs; aging-hardware-under-load diagnosis. (NB: his *network-gear* pain — Cisco/Huawei — is real but OUT of scope; see scope boundary below) |
| Provider support / NOC orgs | Solutions sales | Customers complain "my box is broken"; support either SSHes in or sends a wall of commands. "Run one line, send the link" offloads diagnosis to the customer |

The support-offload angle is the more interesting *wedge*: it is **additive, not
rip-and-replace** (slots into the support runbook; nobody must abandon a tool or
admit their internal tooling is bad), it has a daily-felt metric a support manager
will pay against (diagnostic round-trips per ticket), and it doubles as
**distribution** — every customer handed the one-liner becomes a new end user,
feeding exactly the consultant/operator individual populations from Decision 1.
It also leans on infrastructure already designed (`--share`, the e2e-encryption
design) where "the provider only sees what the customer chooses to share" may be a
deal-closing feature, not a nice-to-have.

### Diagnostician, not monitor (positioning that survives the "zoo")

The target buyer already owns monitoring — Zabbix, vendor dashboards, self-written
scripts, "a real zoo." The naive "replace your monitoring" pitch is dead on
arrival; nobody rips out Zabbix. But every tool in that zoo is **continuous
monitoring** (watch metrics, alert on thresholds, graph over time). DashDiag is
**point-in-time diagnosis** ("everything wrong with *this* box right now, with the
fix"). The zoo is full of monitors and has no diagnostician. The self-written
scripts are the tell — they exist precisely because the monitoring left a
diagnostic gap someone had to plaster over by hand.

Positioning, therefore: **DashDiag is not another animal in the zoo. It is the
diagnostician you run when Zabbix says a box is sick and you need to know *why* in
one command.** The `--json` surface, exporters, and the push backend let it *feed*
the zoo (make existing alerts actionable) rather than compete with it. "Has
internal tooling" / "has a monitoring zoo" is a **pain signal, not a
disqualifier** — the real barrier at larger orgs is procurement and security
review (which the open-source CLI clears trivially), not market saturation.

### The open commitment questions (the difference between signal and validation)

- **Head of networking → would he pilot it on his own fleet?** Even informal
  ("deploy across our test racks, tell me in two weeks"). A yes makes him the
  first design partner — worth more than the entire reasoning chain in this ADR.
- **Solutions sales → would he point one real, mid-complaint customer at the
  one-liner?** Near-zero-cost test of the support-offload distribution flywheel
  with a real end user.

Until one of those converts to action, this stays a hypothesis. It should add two
UTM channels / outreach targets to the validation plan (infra-team communities;
provider support/NOC communities) — not start backend work.

### Scope boundary — what "aging heterogeneous fleet" does and doesn't mean (2026-06-04 refinement)

Follow-up with the head of networking clarified his pain is actually **two
distinct problems on the same VMware estate**, and only one is DashDiag-shaped.
Recording the boundary precisely so "he has aging-hardware pain too" is not
misread as roadmap permission.

**Pain A — network equipment (Cisco / Huawei / mixed, aging).** Real and large,
but it is *switches and routers*, not Linux servers. DashDiag has no SNMP, no
NX-OS/IOS parsing, no fabric visibility, and acquiring them would turn it into a
network-monitoring product competing head-on with entrenched incumbents
(SolarWinds, Zabbix, vendor NMS). **OUT OF SCOPE. Do not chase.** This is the
specific way the "aging heterogeneous fleet" framing could mislead: most of that
fleet is network gear DashDiag cannot serve.

**Pain B — the VMware farm (huge servers hosting client VMs).** Where DashDiag
has a real, mostly-built surface — and it is two Linux-shaped layers:

1. **Linux hosts in/around the farm.** ESXi internals are NOT visible to DashDiag
   (ESXi is not Linux). But any KVM/Proxmox hosts, and the Linux management /
   jump / storage nodes around the VMware estate, run `dsd` natively. `dsd health`
   on a big box carrying dozens of client VMs is exactly the
   aging-hardware-under-load diagnosis it is built for (SMART drift, ECC, thermal,
   IO saturation, noisy-neighbour signals).
2. **Guest Linux VMs.** The blame-attribution pain: a client's new VM "doesn't
   work," the customer blames the network, the department must prove it isn't
   them. `dsd net deep` inside the guest gives *fast exoneration* — if the guest's
   own network stack is provably healthy (interface/MTU/gateway/DNS/conntrack),
   that is evidence the fault is the vSwitch, fabric, or customer config, not the
   network team.

**The honest fit caveat:** for the blame-attribution case DashDiag adjudicates
only the *guest-side slice* (~40%). It cannot see the vSwitch, port groups,
physical fabric, or the customer's side. That slice may still be valuable —
clearing the team is mostly about *fast, credible exoneration*, and "the guest
network layer is provably clean" does much of that — but it is partial, and must
be sold as such, not as full cross-boundary adjudication.

**Scope line to hold:**
- IN: Linux hosts (KVM/Proxmox/management nodes) in the VMware estate; guest Linux VMs.
- OUT (real pains, not our product): ESXi hypervisor internals; Cisco/Huawei/network gear.

**Qualifying question still open for the head of networking:** when a
VMware-blame ticket lands, would proof that the guest VM's own network stack is
healthy be part of getting his team off the hook — or does he need vSwitch/fabric
visibility DashDiag will not build? His answer separates "design partner" from
"polite dead end."
