# ADR-0100: Feature flags — deferred until a cloud backend exists

Status: **Deferred.** No decision taken. Reopen when the triggers below are met.
Date: 2026-07-30
Supersedes: none
Related: Keyorix ADR-068 (feature flags — no flag service), which explicitly places
DashDiag out of its scope

> **Numbering note.** This ADR opens a **0100+ range for public DashDiag ADRs**.
> Public `docs/adr/` and private `dashdiag-private/docs/adr/` had both been numbering
> from 0001, producing a collision: public ADR-0003 is raw input capture & replay,
> private ADR-0003 is the on-prem/air-gapped commercial model. Separating the ranges
> is cheaper than renumbering the private business ADRs, which are referenced from
> planning documents.

## Context

DashDiag is expected to become a SaaS product with its own backend and cloud
infrastructure. It is not one yet: today it is a host collector with no cloud
control plane, no server-side deployment we operate, and no user population we can
segment.

The question of feature-flag strategy came up while deciding it for Keyorix
(ADR-068). The two products sit at opposite ends of the constraint space, and it is
worth recording why the same answer cannot serve both.

| | Keyorix | DashDiag (as SaaS) |
|---|---|---|
| Telemetry | None — no phone-home by design | Available |
| Deployment control | Customer's, on their schedule | Ours, continuous |
| Flag lifetime | Effectively permanent (up to 5 years) | Days to weeks |
| Config space visibility | Unobservable | Fully observable |
| Remote toggling | Prohibited — attack surface | Expected — a feature |
| Percentage rollout | Impossible | The main point |
| Experimentation | Structurally impossible | Legitimate |

Every constraint inverts. Keyorix's answer — no flag service, three separate
mechanisms, compile-time preferred — would be actively wrong for a SaaS product,
and the SaaS answer would be disqualifying for a secrets manager.

## Decision

**None. Deferred deliberately.**

Adopting a flag platform now would be choosing an abstraction before anything has
pulled it out of us. That is the failure mode this project has consistently avoided
elsewhere — MSP multi-tenancy, namespace and zone abstractions, and the HRPS identity
concept were all deferred on the same grounds, and in each case the deferral proved
correct. A flag platform selected against an imagined SaaS architecture would be
selected against the wrong requirements.

Concretely, choosing now would mean picking a provider before we know the deployment
topology, the identity model, or whether flag targeting needs to key on user, org,
fleet, or host. Those are the inputs that actually determine the choice.

## Reopening triggers

Revisit when **any** of the following is true:

1. A cloud backend we operate exists and serves multiple tenants
2. A change needs to ship to a subset of users — percentage rollout, staged
   migration, or a canary cohort
3. An experiment requires two variants live simultaneously with measurement
4. An incident calls for a remote kill switch on a code path we control

Trigger 1 alone is not sufficient. A backend with a single deployment target and no
segmentation need still does not need a flag system; environment configuration is
enough. The real trigger is the first time we want a change live for *some* users.

## Direction, if reopened

Recorded as a starting point for the discussion, not as a decision:

- **OpenFeature as the SDK interface** (CNCF, vendor-neutral), so the provider stays
  swappable. The interface decision is the one that is expensive to reverse; the
  provider is not.
- **Self-hosted provider** — Unleash or Flagsmith — rather than a hosted platform.
  Not for the sovereignty reasons that drive Keyorix, but because DashDiag's on-prem
  and air-gapped distribution (private ADR-0003) means some deployments will never
  reach a hosted control plane. A provider we can run keeps one flag model across
  both distributions instead of two divergent ones.
- **Release, operational, and experimentation flags all in scope.** Unlike Keyorix,
  none of the three is structurally excluded.

### The constraint that will still apply

Even as SaaS, DashDiag has an on-prem and air-gapped distribution path. Whatever is
chosen must degrade to **static, file-based flag evaluation with safe defaults** when
no flag service is reachable. A design that assumes the control plane is always
available will break the offline distribution, and that will be discovered late.

This is the single requirement most likely to be forgotten in the eventual
discussion, because it is invisible from the SaaS side.

## Consequences of deferring

**Positive.** No premature dependency. No abstraction built against imagined
requirements. When the decision is made it will be made against a real backend, real
targeting needs, and a real identity model.

**Negative.** The first genuine need for a rollout will arrive before the
infrastructure to serve it, and will be met with something ad hoc — an environment
variable, a hardcoded allowlist. That is acceptable once. The signal to stop
improvising and reopen this ADR is the second time it happens.

**Risk accepted.** Ad hoc flag mechanisms tend to survive. If a stopgap ships, it is
tracked as debt at the time it ships, not later.
