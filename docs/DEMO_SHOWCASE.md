# DashDiag — Demo Showcase & Marketing Angles

Repeatable, hardware-free demo scenarios for screenshots, asciinema casts, and
LinkedIn/marketing copy. Every output below is produced by the **real render
pipeline** via `dsd mock <fixture>` — no staging hardware, no Photoshop, fully
reproducible by anyone who installs dsd.

```bash
# reproduce any scenario:
dsd mock fixtures/<name>.yaml
```

The pitch in one line: **DashDiag reads your server's health in seconds and tells
you what's wrong — not what to go read.** Zero agents, one command, a clear verdict.

How to turn these into assets:
- **Screenshot**: run the command in a terminal with a clean theme, screenshot the output.
- **asciinema**: `asciinema rec` → run the command → publish the cast (great for LinkedIn video/GIF).
- **Carousel/copy**: each scenario below ships a ready hook + body.

---

## 1. The VMware data-integrity gotcha — pilot/enterprise angle

`dsd mock fixtures/vmware-guest-scsi-timeout.yaml`

```
CPU Load     ✅  38% (load avg 3.1 across 8 CPUs)
Memory       ✅  22/32 GB (69%)
Network      ⚠️  NIC eth0 on an emulated driver (e1000) — vmxnet3 (paravirtual) gives higher throughput at lower host CPU
Hardening    ⚠️  SSH allows password authentication — key-based auth recommended
VMware       ❌  SCSI disk command timeout below VMware's recommended 180s (sda 30s) — the guest filesystem may go read-only during a vMotion or storage failover
────────────────────────────────────────────────────────
❌  VMware: SCSI disk command timeout below VMware's recommended 180s (sda 30s) — the guest filesystem may go read-only during a vMotion or storage failover
   → to fix now: echo 180 > /sys/block/sda/device/timeout
   → to persist: install open-vm-tools (ships a udev rule)
```

**Why it lands:** a VMware admin instantly recognizes this as a real, specific,
credible finding (the default 30s Linux SCSI timeout vs vSphere's 180s
recommendation) that almost no monitoring tool surfaces. Pairs the gotcha with the
paravirtual-NIC tuning advice → signals genuine VMware-guest expertise.

**LinkedIn hook:** *"Your Linux VMs on vSphere will go read-only during the next
vMotion — and you won't know until it happens. One command tells you today."*

---

## 2. The backup that isn't — Proxmox / homelab angle

`dsd mock fixtures/proxmox-backup-gap.yaml`

```
Drives       ✅  4 drives  healthy
LVM          ✅  2 VGs, thin pool 44%
ZFS          ✅  pool tank ONLINE
KVM          ✅  11 VMs running
PVE          ⚠️  4 VM/CT have no backup while others on this node do: gitlab, postgres-prod, mail, vault — no recovery point
────────────────────────────────────────────────────────
⚠️  PVE: 4 VM/CT have no backup while others on this node do: gitlab, postgres-prod, mail, vault — no recovery point
   → note: a healthy node-wide backup age hides individual guests that were never added to a job
```

**Why it lands:** the Proxmox dashboard shows backups "recent" and everything green
— but four guests (incl. postgres-prod) were never added to a job. The relatable
*"I would never have noticed"* moment for the huge Proxmox/homelab audience on
LinkedIn. (This is a real finding — caught live on the test node during validation.)

**LinkedIn hook:** *"Your Proxmox backups are green. Four of your VMs have no
backup at all. The node-wide age hides it — here's the 5-second check."*

---

## 3. The drive that's about to die — universal/SRE angle

`dsd mock fixtures/failing-drive.yaml`

```
IO           ⚠️  nvme0n1 await 24 ms — elevated disk latency
Drives       ❌  /dev/sdb SMART health FAILED — drive may be failing, back up immediately
Logs         ⚠️  12 disk I/O errors in dmesg in the last hour (sdb)
────────────────────────────────────────────────────────
❌  Drives: /dev/sdb SMART health FAILED — drive may be failing, back up immediately
   → note: a FAILED self-assessment means the drive predicts its own failure — replace it
```

**Why it lands:** the highest-stakes finding stated plainly, with corroborating
signals (SMART verdict + rising I/O errors in dmesg) correlated into one screen.
The drive told the kernel it's dying; dsd makes sure a human sees it.

**LinkedIn hook:** *"This disk told the kernel it's failing. It was sitting in a
log nobody reads. `dsd health` puts it on the first screen — back up now."*

---

## Bonus scenarios (existing fixtures)

| Fixture | Story |
|---|---|
| `all-green.yaml` | What a healthy production host looks like — the reassurance shot |
| `rhel101-lvm-broken.yaml` | A full cascade: OOM risk, thin pool 100%, degraded RAID, crash-looping container, SELinux denials |
| `opensuse-btrfs-degraded.yaml` | btrfs device errors surfaced as CRIT |
| `k8s-node.yaml` | Kubernetes node OS-layer + workload view |

---

## Campaign notes

- All fixtures live in `fixtures/` and render identically on any machine — anyone
  who runs the install one-liner can reproduce the exact screenshot.
- To refresh the version string in a screenshot, set `version:` in the fixture
  (currently v0.6.10).
- Real captured fixtures (from a live host) carry more credibility than authored
  ones — capture with the live tool where possible and drop the YAML here.
