# Architecture & Strategy Decision Records

Numbered, dated records of significant decisions — the *why* behind choices that
would otherwise be re-litigated or forgotten. Distinct from the collector/code
architecture table in `DashDiag_Project_Guide.md` §3 (that covers code structure;
these cover product and strategy direction).

| ADR | Title | Status |
|---|---|---|
| [0001](0001-persistence-is-the-platform-foundation.md) | Persistence is the platform foundation, not a CLI feature | Accepted |
| [0002](0002-monetisation-paths-and-landing-page-validation.md) | Monetisation paths and how the landing page decides between them | Accepted (method); path pending data |
| [0003](0003-on-prem-and-air-gapped-commercial-model.md) | On-prem / air-gapped commercial model (the second business) | Accepted (direction); build deferred |
| [0004](0004-team-mode-mechanics.md) | Team mode: two surfaces, one cost-line gate (`dsd fleet` free, hosted dashboard paid) | Proposed (ready for GTM) |
| [0005](0005-pricing-structure.md) | Pricing structure: consolidated tiers + the signals that commit them | Proposed (placeholders; pending GTM data) |

## Format

Each ADR records: context, the decision, rationale, consequences, and any
open questions carried forward. Status is one of Proposed / Accepted /
Superseded (with a pointer to the superseding ADR).
