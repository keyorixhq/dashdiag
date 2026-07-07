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
- Writes to system directories (`/etc`, `/var`, `/sys`, `/proc`)
- Runs as a daemon or background service
- Opens listening network ports
- Modifies system configuration
- Requires root privileges (graceful fallback if not available)

### Network egress — stated guarantee, not just an omission

Core diagnostics (`dsd health`, `dsd security`, `dsd disk`, etc.) make **zero
outbound network calls** — every collector reads local files/`/proc`/`/sys` or
execs a local tool. The only code paths that ever dial out are explicit,
operator-opted-in subcommands, each scoped to what it needs and nothing more:

- `dsd fleet` — SSH to hosts the operator names, to run `dsd health --json` remotely.
- `dsd update` / the passive version nudge — HTTPS to the GitHub releases API only.
- `dsd tls --endpoint <host:port>` — a TLS handshake against an endpoint the operator specifies.
- `dsd cve` / package-manager-backed security scans — queries the distro's
  already-configured package repos (same network access `apt`/`dnf`/`zypper`
  already have), not a dsd-operated service.
- `dsd capture --share` — not yet implemented (see above); when it ships, it
  will be the one path that sends a capture off-host, and only when invoked.

No telemetry, no phone-home, no background connections. This list is the
concrete claim behind "read-only local CLI tool" above — verifiable by
`strace -f -e trace=network` on any plain `dsd health` run.

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
