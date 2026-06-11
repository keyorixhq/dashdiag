# Platform Coverage Matrix

Every platform DashDiag supports, and the depth at which each has been validated — so
you can see exactly how it maps to your own environment.

The depth tier on each row tells you precisely what was exercised: a full real-hardware
run (T1) covers everything including SMART, thermal and IPMI; a VM or container run (T2)
covers the complete software stack; a code-path validation (T3) confirms the
platform-specific logic. Everything claimed about DashDiag traces back to a row here.

## Depth tiers

| Tier | Meaning | What was exercised | What was NOT |
|------|---------|--------------------|--------------|
| **T1 — Real hardware** | Ran on physical hardware | Full collector set incl. SMART, thermal, GPU, firmware, battery | — |
| **T2 — VM / container** | Ran in a VM or LXC/OCI container | Full software stack: OS, kernel, network, security, package, CVE, container/virt detection | Hardware-layer collectors return virtual/absent data (SMART, IPMI, EDAC, real thermal) |
| **T3 — Code-path / spoofed** | Platform-specific code path fired via spoofed identity (e.g. `ID=steamos`, DMI override) | The platform-specific *logic* (detection + heuristics) | Representative hardware AND a genuine instance of that platform |

`dsd` version recorded per row so refreshes are tracked. Most current captures are
`v0.6.11` (`v0.6.11-1-g54769ef`); older captures predate that and are flagged.

## Table 1 — Distro coverage

Linux distributions (plus macOS) the tool has been run on, by package/init family.

| # | OS / distro | Family | dsd version | Environment | Tier | Evidence | Notes |
|---|-------------|--------|-------------|-------------|------|----------|-------|
| 1 | Ubuntu 24.04 | Debian/apt | v0.6.11 | PVE LXC (CT202) | T2 | `captures/ubuntu24-lxc-data/` | also ubuntu26, 2604 captures |
| 2 | Debian 12/13 | Debian/apt | mixed | PVE VM (101) + LXC | T2 | `captures/debian13-*` | CI smoke-tests debian:13 |
| 3 | Linux Mint 22 | Debian/apt | v0.5.x | bare/VM | T2 | `captures/mint22-data/` | full capture set + screenshots |
| 4 | Kali Rolling | Debian/apt | v0.6.11 | OrbStack (kali-dsd) | T2 | `captures/kali-data/` | captured 2026-06-10 |
| 5 | RHEL 10 / 10.1 | RHEL/rpm | mixed | bare metal + VM | T1/T2 | `captures/rhel*` | RHEL 10.1 validated on real hardware (T1); current captures are VM-based (T2) |
| 6 | AlmaLinux 9 / 10 | RHEL/rpm | v0.6.11 (9) | PVE LXC (CT213) | T2 | `captures/almalinux9-lxc-data/`, `almalinux10-data/` | |
| 7 | Rocky 10 | RHEL/rpm | v0.6.11 | PVE LXC (CT203) | T2 | `captures/rocky10-session13-data/` | CI smoke-tests rockylinux:9 |
| 8 | CentOS Stream 10 | RHEL/rpm | v0.5.x | VM | T2 | `captures/centos-stream10-data/` | |
| 9 | Fedora 44 | RHEL/rpm | v0.5.x | VM | T2 | `captures/fedora44-session13-data/` | refresh to v0.6.11 pending |
| 10 | openSUSE Leap 16 | SUSE/zypper | v0.6.11 | PVE LXC (CT204) | T2 | `captures/opensuse-leap16-session12-data/` | |
| 11 | openSUSE Tumbleweed | SUSE/zypper | v0.5.x | VM | T2 | `captures/tumbleweed-data/` | |
| 12 | SLES 16 | SUSE/zypper | v0.5.x | VM | T2 | `captures/sles16-final-data/` | incl. podman variant |
| 13 | Arch Linux | Arch/pacman | v0.6.11 | OrbStack (arch-dsd) | T2 | `captures/arch-data/` | captured 2026-06-10; covers Manjaro at family level |
| 14 | Gentoo | source/portage | v0.6.11 | OrbStack (gentoo-dsd) | T2 | `captures/gentoo-data/` | captured 2026-06-10 |
| 15 | NixOS 25.05 | independent | v0.5.x | PVE VM (212) | T2 | `captures/nixos-25-05-data/` | |
| 16 | Alpine | independent/musl/OpenRC | v0.6.11 | PVE LXC (CT210) | T2 | `captures/alpine-data/` | captured 2026-06-10; non-systemd |
| 17 | Amazon Linux 2023 | RHEL-family/dnf | v0.6.11 | real EC2 (t3.micro) | T2 | `captures/amazonlinux2023-data/` | captured 2026-06-10; AWS-native distro, cloud-aware NVMe handling verified; runs clean on both kernel-6.1 (LTS) and kernel-6.18 |
| 18 | macOS (arm64) | Darwin | v0.6.11 | real hardware (M-series) | **T1** | live run 2026-06-10 | reduced coverage (27 collectors vs 70+); no SMART/IPMI/ZFS |

**Family coverage:** apt/dpkg, rpm/dnf, zypper, pacman, portage — all major Linux
package managers. Both init systems (systemd + OpenRC via Alpine). Plus Darwin.

## Table 2 — Platform / environment awareness

Not distros — environments and runtimes whose *specifics* dsd detects and diagnoses.
This is the specialized intelligence, separate from the distro count.

| Platform | What dsd detects / diagnoses | Validation method | Tier | Evidence |
|----------|------------------------------|-------------------|------|----------|
| **Proxmox VE** | PVE host detection, PVE task errors, cluster/storage state | Real Proxmox host (`pve01`, PVE 9.1.1) | **T1**\* | `captures/pve-data/`, `proxmox-data/` |
| **VMware guest** | VMware guest detection (DMI), SCSI cmd-timeout <180s (vMotion read-only risk), e1000-vs-vmxnet3 NIC | DMI-spoofed VM, **not** real ESXi/vSphere | **T3** | `screenshots/vmware-guest-scsi-timeout.txt` |
| **SteamOS / Steam Deck** | `ID=steamos` gate, RAUC A/B update-slot health, Deck APU/GPU profile, shader-cache disk | Spoofed `ID=steamos` on PVE VM (`steamos-validate`), **not** real Deck HW | **T3** | `screenshots/steamdeck.txt` |
| **AWS EC2** | Cloud-env detection (real AWS DMI/IMDS), cloud-init, Graviton arm64 on real silicon | Real EC2: t3.micro (x86_64) + t4g.small (arm64/Graviton), Ubuntu 26.04, 2026-06-10 | T2 | `captures/aws-x86-data/`, `aws-graviton-data/` |
| **Azure** | Cloud-env detection (Azure DMI/metadata), azure-kernel flavor, Azure-default user posture (NOPASSWD sudo, non-expiring pw) flagged | Real Azure VM: Standard_B-series x86_64, Ubuntu 24.04, 2026-06-10 | T2 | `captures/azure-x86-data/` |
| **Cloud guests** | cloud-init status, cloud metadata (AWS/Azure/GCP DMI fingerprints) | VM captures w/ cloud markers | T2/T3 | `screenshots/cloud-vm-cloudinit-failed.txt` |
| **Containers** | Docker (events, quadlet), containerd, container-aware resource limits | Real containers on multiple hosts | T2 | mint/pve/sles docker captures |
| **KVM** | KVM host/guest detection | Real KVM on PVE | T2 | per-distro `kvm.json` |

\* Proxmox T1 is for the **PVE-specific logic** on a genuine PVE host. Caveat: single
host, not a multi-node cluster — cluster-quorum / corosync paths are not yet HW-validated.

## Roadmap — validated as demand pulls it

DashDiag already *detects* and reasons about the environments below; what's listed here
is the next depth of **real-hardware or real-platform** validation. We deliberately
validate these in the order customers actually ask for them — if your environment is on
this list, tell us and it moves to the front.

- **Real vSphere / ESXi** — the VMware-guest checks (SCSI timeout, NIC type, tools) run
  today via DMI detection; next step is validation on a live vSphere guest. *A VMware
  pilot is the natural trigger.*
- **Multi-node Proxmox cluster** — validated on a single PVE host today; cluster-quorum /
  corosync paths are the next layer, validated against a real multi-node cluster.
- **Server-grade hardware (ECC/EDAC, IPMI/BMC, NUMA)** — these collectors are built and
  fire on server-class hardware; a customer running this class of box is what brings the
  real-data validation.
- **ARM bare-metal** — arm64 is validated in software and on AWS Graviton (virtualized);
  bare-metal aarch64 (SMART/thermal/IPMI on real silicon) is the next step.
- **SteamOS on a physical Deck** — the SteamOS code path (RAUC slots, Deck profile) is
  validated; a run on real Deck hardware is the follow-up.

The principle throughout: we don't claim a depth we haven't reached, and we prioritize
reaching it by what real users need first. Everything claimed elsewhere in this file is
backed by an evidence row above.

## Coverage at a glance

- **17 Linux distributions** (Table 1, rows 1–17) spanning every major family —
  apt/dpkg, rpm/dnf, zypper, pacman, portage — plus both init systems (systemd and
  OpenRC) and macOS.
- **Platform awareness** (Table 2) — Proxmox VE, VMware-guest, SteamOS, AWS EC2
  (including Graviton/arm64), and Azure each have environment-specific detection and
  diagnostics, validated at the depth shown in the Tier column.
