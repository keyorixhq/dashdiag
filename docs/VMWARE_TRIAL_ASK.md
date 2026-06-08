# VMware trial — what to ask for

The resource + access request for the time-boxed VMware design-partner trial
(ADR-0002 Decision 6). Scoped so the trial can **trigger the conditions dsd
detects**, not just run clean — a clean run proves nothing; a correctly
diagnosed *induced* fault is the demo that makes the contact a believer.

Scope is guest-side Linux only (ADR-0002: Linux guest VMs IN; ESXi host /
vSwitch OUT). Bare metal (IPMI/ECC/SMART/RAID) is a **separate, later ask**
(~10 days) — do not bundle it; the VMware VMs alone exercise everything built
for the pilot.

---

## The ask (paste-able to the contact)

> For a ~1-month technical trial I'd need, roughly:
>
> **VMs**
> - **3–4 small Linux guests** — 2 vCPU / 4 GB RAM / 40 GB disk each (the tool is
>   light; I'm testing diagnosis, not running workloads).
> - Distro spread to match my test matrix: **Ubuntu 24.04, AlmaLinux/Rocky 9,
>   Debian 12/13**.
> - At least **2 guests on the same port group** (for the network
>   blame-attribution path).
> - A mix of **open-vm-tools installed on some, absent on others**.
>
> **Access / permissions (the important part)**
> - **vCenter or console access to change each VM's settings and reboot it** —
>   specifically to: set a per-VM **CPU limit (MHz)**, set a per-VM **memory
>   limit/reservation**, switch the **NIC type between VMXNET3 and E1000**,
>   switch the **SCSI controller between PVSCSI and LSI Logic**, and change a
>   vNIC's **port group / VLAN / MTU**.
> - Ability to **deliberately overcommit a host** (or put one guest under memory
>   pressure) so I can observe ballooning/swap from inside the guest.
> - Confirmation I'm **allowed to induce fault conditions** (fill a disk,
>   saturate IO, misconfigure the network) on these throwaway VMs.

---

## Why each item is there — maps to a specific dsd check

| What you ask for | dsd check it lets you trigger |
|---|---|
| Set a per-VM **CPU limit (MHz)** + reboot | **CPU-limit WARN** — the headline demo ("host is throttling this VM at N MHz — that's your slowness, not the box") |
| Set a per-VM **memory limit** | **memory-limit WARN** (invisible paging cause) |
| **Overcommit the host** / squeeze a guest | **balloon + host-swap WARNs** + **CPU steal** — the host-pressure exoneration story |
| Flip **NIC to E1000**, then back to VMXNET3 | **emulated-NIC WARN** — closes the one gap that can't be tested on KVM (no e1000 driver on the spoof rig) |
| Flip **SCSI to LSI Logic / PVSCSI** | confirms **pvscsi module detection** on a real driver load |
| A guest **without open-vm-tools** + one with it **stopped** | **tools-not-installed / not-running WARNs**, and lets the `stat`-based rows populate on the tools-running guests |
| Default-config guest (no open-vm-tools udev rule) | **SCSI timeout < 180s WARN** (already a live true-positive on the rig; here confirm the 180s *clear* after the udev rule) |
| **2 guests, same port group**, change MTU / detach vNIC / wrong port group | the network **blame-attribution** scenario — raw material to validate whether guest-side evidence is enough (the open question for the head of networking; the directional path-trace is not built yet — validate before building) |

---

## Flag to him explicitly

Ask whether you can **set the CPU/memory _Limit_ fields specifically** (not just
reservations) — some orgs lock resource settings. That single permission unlocks
the strongest demo. If he can't grant it, the CPU-limit and memory-limit checks
stay theoretical for the trial, and you lean on the ballooning / CPU-steal path
(which only needs host overcommit) instead.

---

## Trial discipline (from ADR-0002 — do not skip)

1. **Week 1 — deploy and observe, build nothing.** Run the full suite on the
   guests; watch what fires and especially what it gets **wrong** on real VMware.
   False positives only reveal themselves on real hardware.
2. **Week 1–2 — fix what's wrong before adding what's new.** A demo where dsd
   says something *wrong* about his infrastructure is worse than one that says
   less but is right. Ops credibility is fragile.
3. **Week 2–3 — tune the thresholds/messages** on the checks already built
   (esp. whether a bare `BalloonMB > 0` is too noisy or needs a floor), and add
   small VMware-specific sharpening only where Week-1 observation showed a gap.
4. **Week 3–4 — deliberately induce the fault scenarios above and capture the
   wins** as an evidence library for the eventual deck.

Deliverable: dsd catching 3–5 genuinely VMware-relevant things correctly and
impressively, plus the evidence library — **not** a VMware product.

See `docs/VMWARE_VALIDATION.md` for the per-check reproduction steps and current
validation status.
