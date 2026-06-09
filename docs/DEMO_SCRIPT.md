# DashDiag — 60-Second Demo Recording Script

A tight script for an asciinema cast / screen recording (LinkedIn video or GIF).
Goal: from "never seen it" to "I want this" in under a minute. Three beats:
**install → run → it caught something real.**

## Setup (before recording)
- Clean terminal, dark theme, large font (≥16pt), ~100×30.
- Pick the host that shows a real finding. Best options:
  - A real machine with an actual issue, **or**
  - `dsd mock fixtures/<name>.yaml` for a deterministic, guaranteed-good take.
- `asciinema rec demo.cast` (or screen-record). Type at a human pace.

## Beat 1 — Install (10s)
Narration: *"DashDiag installs in one line — no agent, no daemon, no account."*
```bash
curl -fsSL https://dashdiag.sh/install.sh | sh
```
*(let it finish; the one-liner prints the installed version)*

## Beat 2 — Run (10s)
Narration: *"One read-only command checks about thirty things in a few seconds."*
```bash
dsd health
```
*(the verdict table fills in; pause on the colored rows)*

## Beat 3 — The catch (25s)
Narration: *"And it doesn't just dump data — it tells you what's wrong, and the fix."*

Point at the worst finding as it's read aloud. Example (Proxmox backup gap):
```
PVE ⚠️ 4 VM/CT have no backup while others on this node do: gitlab, postgres-prod, mail, vault — no recovery point
   → to inspect: Datacenter -> Backup — confirm every guest is in a backup job
```
Narration: *"Your dashboard said backups were fine. Four guests had none — hidden
behind the node's healthy overall age. dsd found it in five seconds."*

## Beat 4 — Close (10s)
Narration: *"Works on bare metal, VMs, containers, Proxmox, VMware, even a Steam
Deck. One command. dashdiag.sh."*
```bash
dsd health --report   # optional: show the shareable markdown report
```

## Alternate cold-opens (pick per audience)
| Audience | Fixture to record | One-liner |
|---|---|---|
| VMware/enterprise | `vmware-guest-scsi-timeout.yaml` | "Your VMs will go read-only on the next vMotion." |
| SRE/on-call | `failing-drive.yaml` | "This disk is dying and it's buried in a log." |
| Security | `cve-actively-exploited.yaml` | "Anything actively exploited? One command." |
| Docker | `docker-host-meltdown.yaml` | "Three fires, one screen." |
| Steam Deck | `steamdeck.yaml` | "It even speaks SteamOS." |

## Notes
- Keep it under 60s; LinkedIn autoplay drops off fast.
- The "it caught something real" beat is the whole point — don't rush it.
- Record once with a real host (credibility) and once with a `mock` fixture
  (deterministic backup take).
