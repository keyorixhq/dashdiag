# DashDiag — LinkedIn Post Drafts

Ready-to-schedule posts for the launch campaign. Each: a hook, a short body, a
`dsd` output snippet (screenshot the matching `dsd mock fixtures/<name>.yaml` for
the image), and a CTA. Keep one consistent CTA + link. Tone: practical, no hype.

**Standing CTA:** `One command, zero agents, a clear verdict → https://dashdiag.sh`
**Hashtags (rotate 3–5):** #sysadmin #devops #homelab #linux #proxmox #vmware #sre #infosec

---

### Post 1 — VMware (pilot/enterprise)
> Your Linux VMs on vSphere can go **read-only** during the next vMotion — and you won't know until it happens.
>
> The default Linux SCSI timeout is 30s. VMware recommends 180s. Almost nobody checks it, and no dashboard shows it.
>
> `dsd health` does, in one read-only command:
>
> `VMware ❌ SCSI disk command timeout below VMware's recommended 180s (sda 30s) — the guest filesystem may go read-only during a vMotion or storage failover`
>
> It also nudges you off emulated NICs onto vmxnet3. No agent, no account.
>
> [CTA] · *(image: `dsd mock fixtures/vmware-guest-scsi-timeout.yaml`)*

### Post 2 — Proxmox / homelab (the relatable one)
> Your Proxmox backups are green. Four of your VMs have **no backup at all.**
>
> The node-wide "last backup" age looks healthy — so the guests nobody ever added to a job stay invisible. Until you need to restore one.
>
> `PVE ⚠️ 4 VM/CT have no backup while others on this node do: gitlab, postgres-prod, mail, vault — no recovery point`
>
> Real output from a real node. `dsd health` — 5 seconds, no agent.
>
> [CTA] · *(image: `dsd mock fixtures/real-proxmox.yaml`)*

### Post 3 — Failing drive (universal/SRE)
> This disk told the kernel it was dying. The warning sat in a log nobody reads.
>
> `Drives ❌ /dev/sdb SMART health FAILED — drive may be failing, back up immediately`
>
> A FAILED SMART self-assessment means the drive predicts its own failure. `dsd health` puts it on the first screen, next to the rising I/O errors that confirm it.
>
> [CTA] · *(image: `dsd mock fixtures/failing-drive.yaml`)*

### Post 4 — Docker (the footgun)
> A crash-looping container, OOM kills, and a container mounting `/var/run/docker.sock` (= host root). Three problems, one screen.
>
> `Docker ❌ container "payments-api" is crash looping; 3 OOM kill(s) in the last hour`
>
> `dsd health` correlates the noise into a verdict you can act on.
>
> [CTA] · *(image: `dsd mock fixtures/docker-host-meltdown.yaml`)*

### Post 5 — Security / CVE
> "Are we exposed to anything actively exploited?" — answered in one command.
>
> `dsd health --cve` folds your package manager's CVE scan into the verdict and escalates anything in CISA's Known Exploited Vulnerabilities catalog to CRIT:
>
> `CVE ❌ 2 actively-exploited CVE(s) present (CISA KEV): CVE-2024-3094, CVE-2023-44487 — patch immediately`
>
> No cloud, no registration — the KEV catalog ships as a local sidecar.
>
> [CTA] · *(image: `dsd mock fixtures/cve-actively-exploited.yaml`)*

### Post 6 — Cloud / cloud-init
> Your cloud VM booted. cloud-init **errored halfway** — so keys, mounts, or config may be missing, and nothing told you.
>
> `CloudInit ❌ cloud-init failed — instance configuration incomplete (datasource: ec2)`
>
> `dsd health` reads cloud-init's real state (even when it exits non-zero) so a half-provisioned instance doesn't reach production silently.
>
> [CTA] · *(image: `dsd mock fixtures/cloud-vm-cloudinit-failed.yaml`)*

### Post 7 — Steam Deck (top-of-funnel)
> Yes, it runs on your Steam Deck — and it speaks SteamOS: RAUC A/B slots, read-only rootfs, gamescope, shader cache.
>
> `SteamOS ⚠️ inactive RAUC slot B is marked bad — update rollback safety net is gone`
>
> One AppImage, no install dance. `dsd health`.
>
> [CTA] · *(image: `dsd mock fixtures/steamdeck.yaml`)*

### Post 8 — The pitch (pinned/intro post)
> Most "monitoring" tells you *what to go read*. DashDiag tells you *what's wrong.*
>
> One read-only command. No agent, no daemon, no account. It checks ~30 things — disks, memory, network, containers, k8s, security, VMware/Proxmox — and prints a verdict with the fix:
>
> `curl -fsSL https://dashdiag.sh/install.sh | sh && dsd health`
>
> Built for the moment something's off and you need an answer in seconds, not a dashboard to go spelunk.
>
> [CTA] · *(image: `dsd mock fixtures/all-green.yaml` or `rhel101-lvm-broken.yaml` for contrast)*

---

**Posting tips**
- Lead with the output image; LinkedIn rewards the visual. Use a clean dark terminal theme.
- One CTA per post; put the link in the first comment if reach matters.
- Posts 1/2/5 are the strongest openers (specific, credible, "I'd have missed that").
