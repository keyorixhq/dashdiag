# DashDiag Privacy Policy

**Version:** 1.0  
**Last updated:** 2026-05-16  
**Applies to:** `dsd` CLI tool (all versions)

---

## The short version

dsd reads your system. It tells you what it found. Nothing leaves your machine.

No telemetry. No cloud. No account. **Network calls are off by default and
require explicit opt-in** — see "Network calls" below for the full list and
how to enable them.

---

## What dsd reads

dsd reads local system data to perform diagnostics:

- `/proc/*` — CPU load, memory, swap, entropy, file descriptors, processes
- `/sys/class/*` — hardware sensors (thermals, NIC speeds, disk stats)
- `/etc/systemd/*` — journald configuration, systemd unit status
- `/var/log/journal/` — journal size, integrity (archived files only)
- Package manager metadata — pending security advisories (dnf, apt, zypper, pacman)
- `sshd_config` — SSH hardening posture (root login, password auth)
- `/etc/sudoers` — NOPASSWD entries
- `smartctl` output — drive SMART data (if smartmontools installed)
- `ss` / `netstat` output — open ports and listening processes
- SELinux / AppArmor status

All reads are **local and read-only**. dsd never writes to system paths,
never modifies configuration, and never requires write access to anything
outside its own state file.

---

## What dsd stores locally

dsd stores a single state file at `~/.config/dsd/state.json`.

Contents:
- Run count and timestamps (for streak tracking and tips)
- Which milestone messages have been shown
- Last dsd version seen (for changelog nudge)
- NPS score/reason fields (legacy, never sent anywhere)

This file **never leaves the machine**. It is readable only by the user
who runs dsd. It contains no system data, no hostnames, no IPs, no
package lists.

---

## What dsd never does

| Action | Status |
|--------|--------|
| Send data to any remote server | ❌ Never |
| Phone home on install or run | ❌ Never |
| Collect usage analytics | ❌ Never |
| Collect crash reports | ❌ Never |
| Require an account or registration | ❌ Never |
| Read files outside system paths and state file | ❌ Never |
| Modify system configuration | ❌ Never |
| Run as a daemon or background process | ❌ Never |
| Require internet access | ❌ Never |
| Work differently on air-gapped systems | ✅ Works identically |

---

## The --report flag

`dsd health --report` generates a **local markdown file** on disk:
`dsd-report-<hostname>-<date>.md`

This file contains:
- Health check results
- Pending CVE advisories
- System findings and fix commands

The report file is written to the current directory and **never uploaded
automatically**. The admin chooses if and how to share it.

**What the report contains:** hostname, kernel version, distro, pending
CVEs, open ports, package versions, SMART data. Treat it as sensitive —
it is a complete attack surface map of the system.

---

## The --blob report block (shipped)

`dsd health --blob` emits the full report as a compressed, base64-encoded text
block (`-----BEGIN DSD REPORT-----`) for the network-broken support-offload case:
you paste it into your support channel and support runs `dsd decode`.

Be clear on what this is and isn't:

- **Encoded, not encrypted.** The block is gzip + base64. Anyone who has it can run
  `dsd decode` (or decode it by hand) and read the whole report. The `BEGIN/END`
  markers resemble an encrypted PGP block, but there is no key and no encryption.
- **Not redacted.** It carries everything `dsd health --json` does — hostname,
  IP/MAC addresses, open ports and their processes, package and SMART data.
- **So:** send it only through a trusted support channel. Do not paste it into a
  public issue, forum, or chat. The redaction and encryption guarantees below apply
  to the planned `--share` upload, **not** to `--blob`.

---

## The --share flag (planned, not yet implemented)

`--share` is currently a stub (hidden flag, no implementation).

When implemented, the following privacy decisions are locked in:

1. **Explicit consent prompt** — before any upload, dsd will display
   exactly what will be shared and require confirmation.

2. **Redaction by default** — hostname, IP addresses, and MAC addresses
   will be stripped or hashed before upload. Opt-in to include them
   with `--share --include-identity`.

3. **Link expiry** — shared links will expire after 24 hours by default,
   maximum 7 days. No permanent public pastes.

4. **No account required** — anonymous upload only.

5. **EU data residency** — if a share backend is built, data will be
   stored in the EU (GDPR compliance).

6. **End-to-end encrypted** — the report is encrypted locally with
   AES-256-GCM before upload. The decryption key lives only in the
   URL fragment (`#key`) which is never sent to the server. dashdiag.sh
   operators cannot read shared reports. A server breach yields only
   encrypted blobs — no keys, no plaintext, no identity data.

7. **Air-gap alternative** — `--report` (local file) will always remain
   the zero-network alternative for air-gapped environments.

Full technical design: `docs/share-e2e-encryption-design.md`

These decisions are final and will not be changed without a major version
bump and changelog notice.

---

## Network calls

**Off by default.** Every network call dsd can make **on its own initiative —
without you naming a target on the command line** — is gated behind one
policy, `platform.NetworkAllowed()`, which defaults to false. Opt in per-run
with `dsd health --network`, or persistently with `DSD_ALLOW_NETWORK=1` (e.g.
for a cron job). `DSD_OFFLINE=1` is a hard override in the other direction: it
forces offline even if `--network`/`DSD_ALLOW_NETWORK` are also set — an
explicit request to go offline always wins over a request to allow network, so
a script that already sets `DSD_OFFLINE=1` cannot be made to phone out by an
environment that also happens to export `DSD_ALLOW_NETWORK=1` (e.g. a shared
CI image).

A separate, smaller category is **not** gated, deliberately: commands whose
entire purpose is a network action you invoked directly, naming the target
yourself, right now — `dsd fleet <host>` (SSH, your `~/.ssh/config`), `dsd tls
--endpoint <host:port>` (a TLS handshake to the address you just typed), and
`dsd update` (checks/downloads a release because you ran `dsd update`). These
are not "dsd phoning out on its own" — they're the direct effect of a command
whose name says what it does, the same way `--network` gating `curl` itself
would make no sense. Gating them behind an additional flag would be friction
with no privacy benefit: you already named the target in the same breath.

With the default left alone, dsd behaves exactly as this document has always
promised: no telemetry, no DNS lookups, no update checks, no outbound call of
any kind. Every call site below degrades to an explicit "not measured" signal
(never a fabricated pass/fail) when network is disallowed.

The full list, opted into with `--network`/`DSD_ALLOW_NETWORK`:

| Call | Contacts | When |
|---|---|---|
| Connectivity/DNS probe | `8.8.8.8` (ping), `github.com` (resolve) | default `dsd health` network section |
| Cloud-metadata detection | link-local instance metadata service | every dsd command (picks accurate cloud IO thresholds) |
| Update nudge | `api.github.com` | interactive runs, at most once per 24h |
| CVE enrichment | `access.redhat.com` (discloses the CVE ID) | `dsd cve` on RHEL-family distros only |
| NFS reachability | the NFS server from your mount table | default NFS collector, non-loopback mounts |
| SteamOS CDN/update checks | `steamdeck-images.steamos.cloud`, `steamdeck-atomupd.steamos.cloud` | SteamOS only |
| macOS clock drill-down | `time.apple.com` (sntp) | `dsd drilldown clock` on macOS only |
| Configured service probes | the host:port entries under `services:` in `~/.dsd.yaml` | `dsd services`, `dsd services deep` |

Package-manager reads remain local-cache-only regardless of the network
setting — they were never gated by this policy because they were never a
network call to begin with:
- `apt-get -s upgrade` (simulated, reads local cache only — no network)
- `dnf updateinfo` (reads local metadata cache — no network if cache is current)
- `pro security-status` (reads local Ubuntu Pro state — no network if not attached)

If your environment blocks all outbound traffic, dsd works correctly with the
default left alone — nothing above runs unless you opt in.

---

## GDPR / data protection

dsd does not process personal data in the legal sense — it reads
technical system metrics. No individual can be identified from dsd output
alone.

If you use `--report` to generate a file and share it with a third party,
you are responsible for ensuring that sharing complies with your
organisation's data handling policies.

---

## Reporting privacy concerns

If you find a behaviour that contradicts this policy, please open an
issue at https://github.com/keyorixhq/dashdiag/issues with the label
`privacy`.

Security vulnerabilities should be reported via `SECURITY.md`.
