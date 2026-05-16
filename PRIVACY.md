# DashDiag Privacy Policy

**Version:** 1.0  
**Last updated:** 2026-05-16  
**Applies to:** `dsd` CLI tool (all versions)

---

## The short version

dsd reads your system. It tells you what it found. Nothing leaves your machine.

No telemetry. No cloud. No account. No network calls. Ever.

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

## Air-gapped and regulated environments

dsd is designed to work identically in air-gapped environments:

- No DNS lookups
- No package manager network calls during diagnostics
- No certificate validation or OCSP checks
- No update checks

The only network-adjacent operations are:
- `apt-get -s upgrade` (simulated, reads local cache only — no network)
- `dnf updateinfo` (reads local metadata cache — no network if cache is current)
- `pro security-status` (reads local Ubuntu Pro state — no network if not attached)

If your environment blocks all outbound traffic, dsd will still work
correctly. Failed network-adjacent calls degrade gracefully to "no data"
rather than errors.

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
