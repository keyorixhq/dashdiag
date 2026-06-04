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

### Candidate capability (to VALIDATE, not yet a commitment) — guest-side network path-trace

Raised 2026-06-04 in response to the ~40% fit caveat. The question was: can we do
checks for *where in the infra the client VM's traffic dies*, to raise the
exoneration slice? Answer: partially — and the part we can do is genuinely useful,
but the architectural wall must stay explicit.

**What this would be:** a guest-side "where does it die" network collector
extending `dsd net deep`. From INSIDE the guest Linux VM, with no privileged or
VMware access, it builds a *directional* map of how far traffic gets before it
fails:

- Path-MTU black-hole detection — small packets pass, large ones vanish silently;
  the classic signature of a vSwitch/overlay MTU misconfig that gets wrongly
  blamed on "the network."
- Gateway L2/ARP reachability — can the guest even reach its default gateway? If
  not, the fault is the vSwitch / port-group / VLAN, not the guest.
- Staged hop-walk (traceroute-style) — dies at hop 1 → virtual layer; dies N hops
  out → physical fabric/upstream; reaches everything except the customer's target
  → customer side.
- DNS-vs-connectivity split — resolves-but-won't-connect vs won't-resolve.

**Why it helps:** turns the verdict from "the guest stack is healthy" (passive,
~40%) into "the break is at/before the first hop" vs "N hops out" vs "customer
side" (directional, ~60–70%). It specifically catches the vSwitch-layer faults
(MTU black-hole, gateway unreachable) the network team gets wrongly blamed for.

**The wall that stays (do NOT pretend otherwise):** this is *inference from the
guest's vantage point*, not a read of the vSwitch/port-group/fabric/customer
config. DashDiag still cannot SEE those — it concludes "traffic dies before
leaving the virtual layer," which is strong evidence but remains an inference an
adversarial party can contest, unlike a direct config read. Truly closing it
needs ESXi/vCenter API access or host agents — both deliberately OUT of scope
(would make it a VMware product). This capability is pure Linux, guest-side, no
VMware API — it extends `dsd net deep`, it does not cross the boundary.

**Status: candidate to validate, NOT a build commitment.** Gated on the same open
question as the rest of Decision 6 — the head of networking confirming that
guest-side *directional* evidence ("we can show the packet never made it past the
vSwitch") is what actually gets his team off the hook. If yes, this is the first
concrete feature to scope for that use case. If he needs an actual vSwitch/fabric
read, this does not close his gap and should not be built for him. Validate before
building.

### Deployment & commercial container — golden-image distribution, out-of-band install, per-org account (2026-06-04)

A chain of follow-up questions worked the support-offload wedge down to its
operational reality. Recording the chain because each link is sound and the
*cumulative* result is much larger than the wedge — the discipline is staging it,
not building it all now.

**The dependency chain that was uncovered:**

1. **Share needs the network.** "Run `dsd`, send the link" requires the VM to
   reach `dashdiag.sh` — but the customer is complaining *because* the network is
   broken. Resolution: local-artifact-first, network-optional. `dsd` writes the
   full report to a local file (`--out`, already built) and can emit a compact
   copy-pasteable encoded blob to the terminal; upload is a convenience on top,
   never a prerequisite. The customer's own support channel (browser/laptop, not
   the broken VM) carries the blob.
2. **Install needs the network too — and earlier.** `curl …/install.sh | sh`
   can't run on a network-broken VM. This is the harder dependency: you can't even
   reach the point of sharing. Resolution: **pre-position the static binary.**
3. **Pre-position via golden image.** If the provider bakes the single static
   `dsd-linux-amd64` into their VM templates, the binary is present on every VM
   from first boot, no install step, no network. Trivial for them given the
   no-runtime-deps static binary. Turns provider into distributor (one
   integration → tool on thousands of VMs).
4. **Out-of-band install/run via the hypervisor management plane.** Even on a
   *fully* network-isolated VM, Proxmox (`qm guest exec` / file-write via
   `qemu-guest-agent`) and vSphere/vCloud (Guest Operations via VMware Tools) can
   push the binary in and pull the report out *through the hypervisor*, not the
   guest network. Best operated by the **provider's own support team** — no
   customer action, guest network irrelevant. Requires the guest agent / VMware
   Tools present (usually true on provider templates; reinforces golden-image
   pre-positioning). **Requires nothing new in the CLI** — just a static binary
   that writes to a file, which exists. This is a runbook/deployment pattern, not
   a feature.

**The commercial container — per-organisation corporate account on the share
backend.** Once `dsd` is in a provider's golden image, every provisioned VM can
push diagnostics, and the only coherent destination is **one org-scoped tenant
for that provider** (not local-only = wastes the platform; not individual
accounts = incoherent for the provider's own fleet). The org account is the
"team workspace / shared state" paid tier from `COMPANY_PRINCIPLES.md`, made
multi-tenant. It unlocks: provider-scoped fleet view, pre-provisioned identity
(golden image carries an org-scoped enrolment token → VMs auto-register on boot),
and one billing relationship (per-node/seat against one account — far better unit
economics than chasing individual subs).

**What this introduces (do not under-price the complexity):**

- **Multi-tenancy is a trust problem, not just code.** A provider's tenant holds
  *their customers'* VM diagnostics — other people's data. Needs an explicit
  consent/visibility model: does the VM owner know it reports to the provider?
  What does the provider see by default vs. what stays customer-private? The
  e2e-encryption design (`share-e2e-encryption-design.md`) is in tension with an
  org account that auto-ingests everything, and that tension must be resolved
  before a provider signs.
- **Enrolment-token-in-the-image is a credential-management problem.** A token
  baked into every VM leaks the moment a customer inspects the image. Must be
  narrowly scoped (push-only, to tenant X), rotatable, ideally per-VM-derivable.
- **Tenant isolation becomes security-critical** — one provider's data must never
  leak to another's. Table stakes for the provider's security review.
- **This is the heaviest build in the portfolio:** multi-tenant SaaS + tenant
  isolation + enrolment + per-tenant billing + a customer-data consent model. The
  *right* eventual shape, and the furthest thing from six-month-runway reality.

**Staging (the discipline) — expansion tier, explicitly NOT the wedge:**

1. **Wedge (validate first):** support runs/sends `dsd` on a partially-broken VM
   (the common case — some path out exists), finds it useful. Proves value, costs
   nothing new to build.
2. **Expansion:** golden-image pre-positioning + out-of-band guest-exec — "works
   everywhere, including fully-isolated VMs." Sold *after* the support team is
   hooked.
3. **Commercial container:** per-org corporate account + multi-tenancy — built as
   the container for (2), *after* a provider has said "put it everywhere" and is
   willing to be the design partner for the data-boundary questions.

Each stage funds and de-risks the next. Building the org account now — before a
provider has confirmed the wedge — would commit the entire remaining runway to
the heaviest possible bet on two friends' enthusiasm. **Recorded here precisely
because it is seductive:** writing down "yes, and it is stage 3, not stage 1" is
what stops it from quietly becoming next week's build instead of registering the
domain.

**Question to take back to the contact:** when support troubleshoots a
network-broken VM today, do they already use Proxmox/vCenter guest-exec to get
inside it? If that is already their habit, dropping `dsd` into that existing
workflow is near-zero-friction — a strong fit signal.

### Adjacent candidate — CMDB inventory feed (see BACKLOG.md)

DashDiag's already-collected hardware inventory could feed a provider's existing CMDB —
which is chronically starved of fresh, accurate data because it relies on manual entry.
Same diagnostician-not-monitor logic applied to inventory: feed the system of record,
don't compete with it. Feeds technical-facts columns only (model/serial/specs/installed
software), not the administrative layer (owner/asset-tag/warranty/location/licence).
Additive, cheap (data already collected), demand-unvalidated per Principle 3 — gated on a
real request. Origin: co-founder Yuri (ex-MS IT manager who built a homemade Access CMDB).
Full entry in BACKLOG.md.

### Candidate environment — OpenStack (private/public cloud guests) (2026-06-04, anticipated)

Some prospective clients are expected to run `dsd` on OpenStack instances. Recorded so
the plan exists; **demand-unvalidated (Principle 3)** — anticipated, not a named client
with the pain. Plan now, do NOT build until a real OpenStack user appears.

**Key fact — an OpenStack instance is a KVM guest.** OpenStack Nova almost universally
uses KVM/QEMU (libvirt). From inside the guest it *is* a Linux box on KVM — which is
already validated (openSUSE KVM VM, Proxmox guests, the Debian VM 101). So the baseline
needs essentially **nothing new**: CPU steal time, the run-queue collector (already
VM/container-aware), virtio disk detection, the SMART-suppression-on-virtual-disks gate
— all already handle the KVM-guest case. OpenStack is mostly *already covered*.

**The only genuinely OpenStack-specific guest-side candidates** (the parts that differ
from a plain KVM guest are about the guest's relationship to the OpenStack control plane):

- **cloud-init health (the one worth building first).** OpenStack provisions guests via
  cloud-init pulling from the metadata service. Failed/hung cloud-init = instance boots
  but never configures — a real, common, OpenStack-flavoured failure. A check for
  `cloud-init status` (completed vs error/degraded) is the highest-value OpenStack-relevant
  guest check — and it is **generic to every cloud-init platform** (AWS, GCP, the Debian
  VM 101), so it pays off well beyond OpenStack. Can be developed and tested on the
  existing KVM VMs — no OpenStack cloud needed to validate it.
- **Metadata service reachability (169.254.169.254).** Cheap guest-side check; cloud-init
  and config depend on it. Modest value, generic to most clouds.
- **virtio / paravirtual driver detection** — generic to KVM, largely already present
  (the `isVirtualDisk` gate already sees `vd*`).

**Out of scope (the wall — same as ESXi internals for VMware):** Nova/Neutron/Cinder
control-plane health, hypervisor-host state, the OpenStack API. The moment `dsd` reads the
OpenStack control plane it stops being a guest diagnostician and becomes an OpenStack
monitoring product — a crowded space with its own ecosystem tooling, and a different
product. Diagnostician *on the node*, never the control plane.

**Status:** plan recorded, build deferred. The cloud-init health check is the one concrete
candidate; it is generic-cloud-useful (not OpenStack-only), testable on existing KVM/VM
infra, and still gated on a real user asking — same discipline as every other candidate.

### Candidate environment — edge computing / carrier base stations (2026-06-04, one declaration)

A mobile-carrier contact declared a direction: cellular base stations and antennas going
cloud-connected and cloud-managed, running client workloads in Docker on the base station
itself — compute pushed to the edge, closer to clients, including rural regions where
on-site support and remote diagnostics are hard.

**Status: hypothesis from one directional declaration — NOT validated demand, and weaker
than the two D6 provider contacts (who described their own daily pain; this contact
described an industry trend).**

**Why the technical fit is strong — arguably the strongest in the strategy:**

- Base stations are general-purpose Linux boxes running Docker workloads — `dsd health` +
  `dsd docker` core competency, not a new collector.
- Physically scattered, often rural, no one on-site, hard remote access — the canonical
  "OBD for your server" case at its extreme: a box you cannot reach that must tell you
  what is wrong in one shot.
- Heterogeneous, aging, constrained hardware — the same distro-matrix muscle already built.
- The static single binary with no runtime deps is ideal for constrained edge nodes
  (cannot assume a package manager, fat runtime, or reliable bandwidth).
- The broken/intermittent-network deployment chain already reasoned through in this
  Decision is *the* edge connectivity condition. That work transfers directly.

**Why it is NOT a near-term wedge (the counterweight):**

- **Hardest buyer in the strategy.** Telecom/carrier procurement is brutally slow: long
  cycles, heavy security/compliance/certification review, entrenched network-equipment
  incumbents (the same Cisco/Huawei/Ericsson/Nokia world ruled out earlier). A solo founder
  on short runway selling into carriers is a multi-year motion. Excellent technical fit does
  not shorten that cycle. The opposite of the low-friction support-offload wedge.
- **Crowded with platform plays.** Hyperscaler edge (Outposts/Wavelength, Azure Edge),
  carrier-cloud initiatives, KubeEdge, k3s-at-the-edge. The trap is drifting toward building
  an edge *fleet-management platform* — the multi-tenant backend again, now competing with
  hyperscalers and the carriers' own management stacks.
- **Positioning discipline (same as the rest of D6):** DashDiag is the *diagnostician on the
  node*, feeding whatever edge-management plane the carrier already runs — NEVER the
  management plane itself. Node-level diagnostic emitting clean data into their existing
  orchestration = coherent. Trying to be the edge platform = dead on arrival. Do not drift.

**What this means in practice:** the EXISTING product (Linux + Docker diagnosis, static
binary, local-first) pointed at a new environment it already fits — so validating it costs
almost nothing, there is nothing new to build to *try* it. Per Principle 3: hot trend +
excellent technical fit + one contact's directional declaration = a strong hypothesis, not
validated demand. "The fit is obvious" is not "the buyer will adopt."

**Zero-build validation step (one conversation):** ask the carrier contact whether their
edge / base-station ops people struggle to diagnose those remote Docker-running boxes
*today*, and whether they would drop a static binary on a handful of them. If yes → a third
validation thread at zero build cost. If only "we are moving to edge eventually" → a trend
to revisit later, not a thing to build toward now.

### Three connected signals from one contact — infra, personal pain, distribution (2026-06-04)

The Decision 6 solutions-sales contact produced three distinct signals in one conversation.
They matter as a connected engine, not three scattered notes — one well-placed person who
can test, who has the pain, and who would distribute. Relationship context: the founder was
his manager at a large telecom and helped him repeatedly; he is loyal and helping in return.
He is a social connector in his org and the account person clients call FIRST when something
breaks.

**Signal 1 — Free test infrastructure (GOODWILL, not demand).** He is using his position to
give free access to VMware infrastructure (a one-MONTH trial of VMs, available immediately)
and bare-metal servers (~10 days out) to test dsd. This is a favor from a loyal former
report, NOT a trial in the evaluative sense and NOT a procurement process. What it validates:
nothing commercial. What it gives: a real, zero-cost place to test dsd on genuine VMware +
server hardware (IPMI/BMC, ECC, physical disks, RAID) that the existing Proxmox/LXC/NixOS
matrix cannot provide. Take it fully; hold zero commercial expectation; let any management
interest emerge only if the tool earns it. Risk to manage: a favor-driven test is warm, so
feedback may be too kind to be informative — treat as TECHNICAL validation, not commercial.

**Signal 2 — His own support-triage pain (FIRST REAL WEDGE VALIDATION).** Clients call him
first when something breaks; his clients' wellbeing — and his own standing — depends on how
fast triage / troubleshooting / fixing happen. Faster diagnosis makes HIM look good to HIS
clients. This is not "observes a pain" or "a trend" — a named person with the pain
personally, tied to his own performance, i.e. self-interest, the most reliable signal. It
lands exactly on the support-offload wedge this Decision already called the more interesting
one. First genuine validation that the wedge's PAIN is real and located in a real user.
Principle 3 caveat: validates the pain and the wedge — does NOT yet validate that his ORG
would buy, nor that the pain monetises. Those remain open.

**Signal 3 — Willingness to distribute to his clients (FIRST DISTRIBUTION-CHANNEL
VALIDATION).** He wants to recommend dsd to his clients so they can troubleshoot their own
on-prem infrastructure. His incentive is durable and aligned: his method for winning client
loyalty (and beating competitors long-term) is being generally useful, even when he earns
nothing short-term on a given recommendation. This puts a real face on the "support-offload
doubles as distribution" hypothesis: not "providers will hand it out" in the abstract, but a
connector-type account person distributing it as part of his trusted-advisor method —
self-sustaining as long as the tool stays good and makes him look good. More specific and
credible than the Decision previously stated. Principle 3 caveats: validates that a
well-placed person WOULD recommend it and WHY (durable, real) — does NOT validate that his
clients would ADOPT on his recommendation, and a connector recommending a free OSS tool
generates USAGE not revenue (and individual on-prem operators are the hardest population to
monetise, per Decision 1 / ADR-0001). The channel is real; the business model THROUGH the
channel is still open.

**Why the three connect (the engine):** test on his infra (1) → make dsd genuinely good and
nail HIS own triage scenario (2) → which earns his willingness to stake his client-credibility
on recommending it (3). Signal 3 is gated on the tool being solid — connectors are careful
with their credibility and won't recommend something rough. Sequence: use the free infra to
make dsd impressive on VMware + bare metal first; the personal-pain win and the distribution
both follow from the tool actually being good. The most complete real-world thread in the
strategy — and it is all from ONE person, which is also its limit. Breadth (does this
replicate beyond him) is still the landing-page / multi-contact job.

**Near-term action (no build):** use the infra to make dsd demonstrably faster than his
current process for the "client reports a broken VM → cause + fix" loop. A management-facing
slide deck is worth making ONLY AFTER testing produces real "dsd caught this on your
infrastructure" moments — build the deck FROM what the testing shows, not from hypotheticals.
Deck-to-management is goodwill carriage, not procurement; keep expectations there at zero.

### Trial scoping — VMware (1 month, now) + bare metal (~10 days) resource asks (2026-06-04)

Resources to request from the contact, chosen to let dsd *trigger the conditions it is meant
to catch* (not just run clean). The trial is TECHNICAL validation — make dsd genuinely good
on real VMware + server hardware; demand stays a separate, open question.

**VMware VMs (1-month access, now):**
- 3–4 small Linux guests: 2 vCPU / 4 GB RAM / 40 GB disk each (dsd is light; testing
  diagnosis, not workloads).
- Distro variety matching the existing matrix: e.g. Ubuntu 24.04, AlmaLinux/Rocky 9, Debian
  — tests `platform.Profile` under VMware.
- At least 2 guests on the same port group (needed to test cross-vSwitch network behaviour /
  blame-attribution path-trace).
- Console or vCenter access to deliberately misconfigure virtual networking (change MTU,
  detach vNIC, wrong port group) — the highest-value item: lets you create the "VM network is
  broken, who's to blame" condition and verify guest-side directional evidence.
- VMware Tools / open-vm-tools installed (usually default) — relevant to out-of-band install.
- GPU: not needed on VMs.

**Bare metal (~10 days):**
- 1–2 real servers — feature-complete beats powerful.
- IPMI/BMC (iDRAC/iLO/Supermicro) — tests the IPMI collector + hardware sensors (impossible on a VM).
- ECC memory — dsd reads EDAC/ECC counters, a flagship aging-hardware signal (real server RAM only).
- Mixed physical disks (SATA/SAS + NVMe if possible) — SMART/NVMe collectors are central;
  older boxes with some drive history are MORE useful than pristine ones.
- Hardware RAID controller (PERC/MegaRAID) if available — tests the RAID collector.
- Distro variety or a multi-boot/reinstallable box.
- Moderate CPU/RAM is fine (8–16 cores, 32–64 GB) — reading sensors/subsystems, not running load.
- GPU optional — only if a box happens to have one (tests the GPU collector on real hw).

**For both:** ask whether you can deliberately create fault conditions (fill a disk, saturate
IO, misconfigure network, stress CPU). A clean run proves nothing; a correctly-diagnosed
*induced* fault is the demo that makes the contact a believer and becomes a deck slide.

### Trial discipline — one month is for doing it well, not over-building (2026-06-04)

A month of VMware access removes the rush; it is NOT a licence to build a VMware product.
Sequence:
- **Week 1 — deploy and observe, build nothing.** Run the full check suite on VMware guests;
  watch what fires and especially what it gets WRONG on VMware (false positives reveal
  themselves only on real hardware, as with the macOS work). Structured observation first.
- **Week 1–2 — fix what's wrong before adding what's new.** A demo where dsd says something
  *wrong* about his infrastructure is worse than one that says less but is right. Ops
  credibility is fragile.
- **Week 2–3 — add small VMware-specific sharpening, informed by observation:** verify steal
  time fires with a clear message (the headline VMware signal — host overcommit, exonerates
  the guest); VMware Tools / open-vm-tools status check; paravirtual-vs-emulated driver
  detection (VMXNET3/PVSCSI vs E1000/LSI — silent perf killer); hypervisor platform detection
  so heuristics can be VMware-aware. Add only the gaps real observation reveals.
- **Week 3–4 — deliberately induce fault scenarios and capture the wins** as an evidence
  library for the eventual deck.

Deliverable: dsd catching 3–5 genuinely VMware-relevant things correctly and impressively,
plus an evidence library — NOT a VMware product. Resist the more-time-means-more-features
pull. The no-new-features-before-paying-customer rule still applies; trial-scoped sharpening
is the only justified exception, and only after Week-1 observation says what's actually needed.
