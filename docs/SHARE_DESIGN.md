# Share design

Status: design captured 2026-05-10. Not implemented. Targeted for v0.3 or
later, after launch traction signals demand for sharing functionality.

This document records design decisions made during v0.2.0 prep so the
v0.3 implementation can start from a clear specification rather than
re-deriving the choices.

## What `--share` does

When a user runs `dsd health --share`, DashDiag uploads the diagnostic
output to a hosted backend and returns a short, unguessable URL that
can be shared via Slack/email/chat. Anyone with the URL can view the
diagnosis in a browser.

When combined with `--qr`, the URL is also rendered as an ASCII QR code
in the terminal, scannable from a phone camera.

## Status as of v0.2.0

The `--share` and `--qr` flags exist in the CLI but are hidden from
`--help` (`f.MarkHidden("share")`, `f.MarkHidden("qr")` in cmd/root.go).
The `--qr` flag accepts an empty share URL and silently does nothing,
which is correct behaviour: until the backend exists, there's no URL
to share.

This means scripts using these flags will silently no-op rather than
error, and they don't appear in the user-facing help. When the backend
ships, the flags become visible again with one line removed from
cmd/root.go.

## Design decisions

### Public links by default, password protection opt-in

Three options were considered:

**A. All shares public** — anyone with the URL can view. Equivalent to
Pastebin or transfer.sh model. Simple, frictionless, but no recourse
if URL leaks.

**B. All shares password-protected** — every share requires a password
to view. High security but high friction. Most users would have to
share both URL and password through separate channels for the password
to add real protection (a single Slack message containing both is no
better than no password at all). Reduces virality.

**C. Public default, password opt-in** — short-lived public link by
default, optional `--share=private` for password protection.

**Decision: Option C with smart defaults.**

Rationale: matches the model used by GitHub Gist, gist.github.com,
transfer.sh, and similar tools. Familiar pattern for engineers. Right
defaults for the common case (sharing with team in chat) while still
allowing higher security when needed (sharing diagnosis from a
sensitive production system).

### Default expiry: 7 days

URLs expire after 7 days of creation. Engineers typically share
diagnoses for incident response, code review, or pair-debugging — all
of which complete within a week. Longer retention costs more storage
without proportional benefit.

Power users can override:
- `--share-expire=24h` for shorter retention (sensitive contexts)
- `--share-expire=30d` for longer retention (paid tier only)

### Random URL format

URLs use cryptographic random IDs:

```
https://dashdiag.sh/r/Xk2pQ8mN
```

Path format: `/r/<8-12 char alphanumeric>`. ~50 bits of entropy.
Sufficient to prevent guessing in practice. Short enough to type if
needed (though copy-paste is the expected mechanism).

The `/r/` prefix distinguishes shared diagnosis URLs from other site
paths and reserves the namespace.

### What viewers see

Browsers visiting a shared URL see the **human-readable output**, not
the raw JSON. Specifically:

- Hostname (preserved as-is)
- Timestamp
- Per-check status with messages
- Drilldown tables where present
- Timestamp of share creation
- Expiry date

What they do NOT see by default:
- The full raw JSON output (which contains more detailed fields)
- Internal IPs or network state beyond what's already in the human view
- Process command lines (only process names)

A `--share-format=full` option could expose the full JSON for users
who explicitly want it, with a clear warning about additional data
being included.

### What's NOT in shared output

The following are NEVER included in shared output, even if they exist
in the local raw output:

- File contents (DashDiag doesn't read these anyway)
- Environment variables (DashDiag doesn't read these)
- Memory contents (DashDiag doesn't read these)
- Authentication tokens or credentials (none are collected)

The "what could be sensitive" list is therefore mostly limited to
metadata: hostnames, process names, mount paths, failed unit names,
internal architecture inferences.

### Rate limiting

Free tier: 5 shares per day per source IP (and per host once we have
host identity).

Paid tier: configurable, with team-level quotas.

This prevents abuse (using DashDiag share as a generic Pastebin) and
keeps backend costs predictable.

### View tracking

Every share records:
- Creation time
- View count
- Last viewed time
- Expiry time

The creator can see this metadata via `dsd share list` (a future
command). View counts are NOT shown to viewers — only to the creator.

For paid tier, an audit log shows specific viewer IPs and timestamps
(to help teams understand who's accessing diagnostics).

## Pricing model

**Decision: freemium.**

Free tier (anonymous, no account required):
- Public links only
- 7-day retention
- 5 shares per day per source
- View count visible to creator only
- Cryptographic random URLs

Paid tier (Starter, account-bound):
- Public OR password-protected links
- 30-day retention default, configurable up to 90 days
- 100 shares per day
- Team workspace (shares organized under an org)
- Audit log of viewers
- Email notifications when shares are accessed

Paid tier (Team, multi-seat):
- Everything in Starter
- Unlimited shares
- Custom domain (`shares.yourcompany.com`)
- API access for CI integration
- SSO / SAML

Pricing: TBD with real data. Probably $19-49/month for Starter team,
scaling for larger teams. Don't fix prices until we have signal about
willingness-to-pay.

## Why share is freemium, not all-free or all-paid

**All-free** would be unsustainable. Hosting infrastructure (storage,
bandwidth, compute for rendering) costs money. With no paywall, every
user is a cost without revenue. As share usage grows, costs grow. We
don't have VC funding to absorb this indefinitely — we're bootstrapped.

**All-paid** would kill virality. Engineers won't pay for share before
they're using the tool regularly. Locking share behind paywall means
no shared diagnostic links circulating in chat, means no organic
discovery from "look what dsd showed me on prod-db-01" Slack messages.
Counterproductive at launch.

**Freemium** captures the best of both: free public links drive
virality and tool discovery; paid features capture willingness-to-pay
from teams that have budget. This matches the proven path for tools
like GitHub Gist (free public, paid for advanced), Pastebin (free with
limits, paid Pro), and most modern developer tools.

## Backend architecture sketch

For v0.3 implementation, simplest viable backend:

- Static file storage: S3 or Cloudflare R2 (R2 has no egress fees)
- URL pattern: `dashdiag.sh/r/<id>` with id as the storage key
- Diagnosis stored as JSON blob with metadata wrapper
- Lifecycle policy: auto-delete after expiry
- Static frontend: Astro / Next.js / plain HTML, fetches the JSON,
  renders the human-readable view
- Rate limiting: Cloudflare workers in front of upload endpoint
- Optional: Cloudflare Turnstile or similar to prevent bot abuse

Estimated build: 2-3 weeks of focused work for a minimal viable
version. Not a "swap a domain" change — a real engineering project.

## Why share is NOT in v0.2.0

The launch can't include `--share` because:

1. **Backend doesn't exist.** Shipping the flag without a working
   backend is dishonest. A mockup URL pointing to `example.com` would
   be a credibility hit at exactly the moment we can't afford one.

2. **Share isn't critical for launch virality.** The primary virality
   vector is engineers running `dsd health`, finding the F0 drilldown
   moment compelling, and recommending the tool to colleagues. The
   launch chain (HN post + demo GIF + cheat-sheet content + install
   script) handles this without needing share URLs.

3. **Premature share design risks getting it wrong.** Shipping share
   in v0.3 with real launch feedback informing the design is far
   better than shipping a guess in v0.2.

The flags are hidden, not removed. When v0.3 ships with the backend,
unhide the flags via removing two lines in cmd/root.go. No breaking
change, no migration.

## When to build

Trigger conditions for prioritizing v0.3 share work:

- 3+ GitHub issues asking "how do I share this output?"
- 5+ HN/Reddit comments mentioning the missing share feature
- Direct user emails saying "I want to send this to my team"
- Any indication that customers would pay for team-share features

Without these signals, share isn't the missing piece. Build other
things first.

## Open questions for v0.3 implementation

When the time comes:

1. **Should share require an account, even for free tier?** Anonymous
   shares are simpler but make abuse harder to prevent. GitHub Gist
   allows anonymous gists; pastebin.com requires account for Pro.
   Decision: probably anonymous for free, account for paid.

2. **What happens when free tier user pays?** Should their existing
   shares get extended retention? Probably yes — it's a "thanks for
   paying" moment. Easy to implement: bump expiry on first paid action.

3. **How to handle abuse?** Someone will use share to host phishing
   pages, leaked credentials, or worse. Need a takedown process,
   abuse@ email, automated content scanning for known badness.
   Standard playbook for any user-content service.

4. **Share-from-CI?** A common request will be "share this diagnostic
   from my CI pipeline so I can see it later." API access, secret
   token, programmatic uploads. Probably paid-tier feature. Worth
   building deliberately rather than as afterthought.

5. **Custom domains?** "Our shares should be at `diag.acme-corp.com`."
   Real ask from larger customers. Implementation is non-trivial
   (DNS verification, TLS cert management). Defer to Team tier.

6. **What does the rendered viewer look like?** Plain HTML mimicking
   the terminal output? Rich UI with collapsible sections, syntax
   highlighting, copy-to-clipboard buttons? Time series for accounts
   with multiple shares of the same host? Decide when building.

## What to do now

Nothing. This document is the spec. When v0.3 share work begins, start
here, refine, build.

The decisions captured here represent the result of thinking carefully
about the tradeoffs before launch. Re-litigating them when implementation
starts wastes time. Re-derive only if circumstances meaningfully change
(e.g., new regulatory requirement, fundamentally new threat model).

## References

- GitHub Gist (gist.github.com) — public/secret/private gist model
- transfer.sh — anonymous file sharing with expiry
- Pastebin Pro — freemium tier structure
- HashiCorp Terraform Cloud — free CLI, paid collaboration model

These are precedents for various aspects of the design. Worth
re-reading when implementation starts.
