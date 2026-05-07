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
- Optionally uploads snapshots to `dashdiag.sh` (if `--share` is used)

### What DashDiag never does
- Writes to system directories (`/etc`, `/var`, `/sys`, `/proc`)
- Runs as a daemon or background service
- Opens listening network ports
- Modifies system configuration
- Requires root privileges (graceful fallback if not available)

## Verifying a Release

```bash
cosign verify-blob \
  --key https://raw.githubusercontent.com/keyorixhq/dashdiag/main/cosign.pub \
  --signature dsd-linux-amd64.sig \
  dsd-linux-amd64

sha256sum --check --ignore-missing checksums.txt
```

## Security-Relevant Configuration

`~/.dsd.yaml` — not encrypted, do not put secrets here.
`~/.dsd/state.json` — usage metrics only, no passwords or tokens.

All dependencies must have permissive licenses (MIT, Apache 2.0, BSD).
GPL/AGPL dependencies are not permitted. Verify: `go-licenses check ./...`
