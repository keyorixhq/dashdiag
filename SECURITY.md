# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ Security fixes |
| Previous minor | ✅ Critical fixes only |
| Older | ❌ Not supported |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **security@dashdiag.sh**

We acknowledge within 48 hours and provide an initial assessment within 7 days.

Include: description, reproduction steps, affected version (`dsd --version`).

## Threat Model

DashDiag is a **read-only local CLI tool**.

### What DashDiag does
- Reads `/proc`, `/sys`, and system files on the local machine
- Executes read-only system commands (`timedatectl`, `systemctl show`, etc.)
- Saves state to `~/.dsd/` (usage metrics, snapshots)
- Optionally uploads snapshots to `dashdiag.sh` (if `--share` is used — not yet implemented, see PRIVACY.md)
- Captures, replays, and diffs portable bundles (`dsd capture`/`replay`/`diff`/
  `migrate certify`), and best-effort redacts them before sharing
  (`dsd capture --sanitize`, `dsd sanitize`); self-updates via a signed,
  fail-closed release channel (`dsd update`)

See **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** for the detailed model of
the three surfaces above where dsd processes data it didn't just read live
off the local host — bundle ingestion, sanitization guarantees/limits, and the
self-update trust chain.

### What DashDiag never does
- Writes to system directories (`/etc`, `/var`, `/sys`, `/proc`) — one opt-in
  exception: `dsd hook install`'s "systemd timer" option writes
  `/etc/systemd/system/dsd-health.{timer,service}`, and only if the operator
  selects it and has (or is granted via `sudo`) the privilege to do so. Every
  other install/update path stays under `~/.dsd/`.
- Runs as a daemon or background service
- Opens listening network ports
- Modifies system configuration
- Requires root privileges (graceful fallback if not available)

### Network egress — stated guarantee, not just an omission

Core diagnostics (`dsd health`, `dsd security`, `dsd disk`, etc.) make **zero
outbound network calls by default** — every collector reads local
files/`/proc`/`/sys` or execs a local tool. Every code path that can dial out
on its own initiative is gated behind one policy,
`platform.NetworkAllowed()`, which defaults to false; a separate, smaller set
of commands (`dsd fleet`, `dsd tls --endpoint`, `dsd update`) dial out
ungated because the network action IS the command the operator just typed,
naming the target themselves.

**[PRIVACY.md's "Network calls" section](PRIVACY.md#network-calls)** is the
authoritative full list of every call site in both categories — this file
doesn't attempt to enumerate them, so it can't fall out of sync as new
gated collectors are added. No telemetry, no phone-home, no background
connections: with the default left alone (no `--network`,
`DSD_ALLOW_NETWORK` unset), dsd makes zero outbound calls of any kind —
verifiable with `strace -f -e trace=network` on a plain `dsd health` run
that doesn't pass `--network`.

## Verifying a Release

Releases are signed with [minisign](https://jedisct1.github.io/minisign/), not
cosign (cosign was never adopted — see `docs/RELEASE_SIGNING.md`). `dsd update`
verifies this in-binary automatically and fails closed on a bad or missing
signature; to verify a downloaded release by hand:

```bash
minisign -Vm checksums.txt -P "<the project's MINISIGN_PUBKEY line, see docs/RELEASE_SIGNING.md>"
sha256sum --check --ignore-missing checksums.txt
```

Every release artifact also carries a GitHub build-provenance attestation,
independent of minisign:

```bash
gh attestation verify dsd-linux-amd64 --owner keyorixhq
```

## Security-Relevant Configuration

`~/.dsd.yaml` — not encrypted, do not put secrets here.
`~/.dsd/state.json` — usage metrics only, no passwords or tokens.

All dependencies must have permissive licenses (MIT, Apache 2.0, BSD).
GPL/AGPL dependencies are not permitted. Verify: `go-licenses check ./...`
