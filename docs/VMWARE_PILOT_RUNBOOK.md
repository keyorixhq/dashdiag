# VMware pilot — fault-injection & evidence-capture runbook

The trial (ADR-0002, Signal 1) is technical validation: make `dsd` demonstrably
catch real, VMware-relevant problems on the contact's infrastructure, and walk
out with an **evidence library** to build the management deck *from* (not from
hypotheticals). A clean run proves nothing; a correctly-diagnosed **induced**
fault is the demo that turns goodwill into advocacy.

This runbook is the missing half of `VMWARE_TRIAL_ASK.md`: for each signal `dsd`
detects, the exact way to **induce** it and the exact command + expected output
to **capture**. It is lab-independent — read it now, run it when access lands
(~June 17). Scope is guest-side Linux only (ADR-0002: ESXi/vSwitch internals OUT).

---

## Pre-flight (once per guest)

1. **Install** (uses the fixed one-liner — see PR #123):
   ```
   curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/install.sh | sh
   ```
   or pre-position the static binary (golden-image / `scp`) — no network needed.
2. **Confirm the VMware gate fires:** `dsd health` should show a `VMware` line.
   No line = DMI not detected as VMware (wrong env). Record the product string.
3. **Baseline:** capture a clean `dsd health --blob --out baseline-<host>.txt`
   before inducing anything, so each win is a clean before/after.

---

## Week-by-week discipline (from ADR-0002 — do NOT skip)

1. **Week 1 — deploy & observe, build nothing.** Run the full suite on every
   guest; log what fires and especially what it gets **wrong** on real VMware.
   False positives only reveal themselves on real hardware.
2. **Week 1–2 — fix what's wrong before adding anything.** A demo where `dsd`
   says something *wrong* about his infra is worse than one that says less but is
   right. Ops credibility is fragile.
3. **Week 2–3 — tune thresholds/wording** on what observation revealed (esp.
   balloon/steal floors).
4. **Week 3–4 — induce the faults below and capture the wins** into the evidence
   library.

---

## The fault matrix

For each: **induce** (vSphere/console) → **run** (`dsd`) → **expect** → **why it
matters to the customer** → **capture**.

### 1. Host-imposed CPU limit — THE headline demo
The canonical invisible cause of "my VM is slow" that the customer blames on the
network/box. `dsd` reads it from *inside* the guest via open-vm-tools.
- **Induce:** vSphere → VM → Edit Settings → CPU → **Limit = 500 MHz** → OK (no reboot needed).
- **Run:** `dsd health` (or `dsd cpu`).
- **Expect:** `WARN … a host-imposed CPU limit of 500 MHz is set on this VM — the guest is throttled below its vCPU capacity regardless of host load`.
- **Why:** proves the slowness is the host config, not the guest or network. Get-the-team-off-the-hook material.
- **Capture:** `dsd health --blob --out evidence/cpu-limit.txt`. Remove the limit, re-run, show it clears.

### 2. Host-imposed memory limit
- **Induce:** VM → Memory → **Limit** below configured RAM (e.g. 1 GB on a 4 GB VM).
- **Expect:** `WARN … host-imposed memory limit of N MB … RAM above the limit is ballooned/swapped even when the host has free memory`.
- **Why:** invisible, common cause of guest paging.
- **Capture:** `evidence/mem-limit.txt`.

### 3. Active ballooning (host memory pressure)
- **Induce:** overcommit the host — power on other memory-hungry VMs on the same host until ESXi reclaims, OR set a low memory **reservation** + pressure. (Needs open-vm-tools running.)
- **Run:** `dsd health`.
- **Expect:** `WARN … host is reclaiming N MB of this guest's RAM via the balloon driver — the ESXi host is under memory pressure`.
- **Why:** the memory analog of CPU steal — host pressure squeezing this guest, exonerating it.
- **Capture:** `evidence/balloon.txt`. (Tune the floor in Week 2–3 if a tiny balloon over-fires.)

### 4. Host swapping guest memory
- **Induce:** severe host memory contention (heavier overcommit than #3).
- **Expect:** `WARN … host has swapped N MB of this guest's memory to disk — severe host memory pressure`.
- **Why:** hypervisor-level swap = large unpredictable latency spikes inside the guest.

### 5. CPU steal (host CPU overcommit)
- **Induce:** saturate CPU on other VMs sharing the host so this guest is starved.
- **Run:** `dsd health` / `dsd cpu`.
- **Expect:** `WARN` at steal ≥10%, `CRIT` at ≥20% — "hypervisor is withholding CPU time from this VM".
- **Why:** the headline overcommit signal; exonerates the guest.

### 6. Emulated NIC (silent perf killer)
- **Induce:** VM → Network adapter → change type to **E1000** → reboot guest.
- **Run:** `dsd health` / `dsd net`.
- **Expect:** `WARN … NIC(s) on an emulated driver (ens160 (e1000)) — vmxnet3 (paravirtual) gives higher throughput at lower host CPU`.
- **Then:** switch to **VMXNET3**, reboot → the WARN clears to the INFO recognition line. (This also closes the one unit-tested-but-not-live-validated gap from #113.)
- **Capture:** `evidence/emulated-nic-before.txt` + `-after.txt`.

### 7. SCSI command timeout (FS-goes-read-only risk)
- **Induce:** a guest **without** open-vm-tools' udev rule → kernel default 30s.
- **Run:** `dsd health` / `dsd disk`.
- **Expect:** `WARN … SCSI disk command timeout below VMware's recommended 180s (sda (30s)) — the guest filesystem may go read-only during a vMotion or storage failover`.
- **Then:** `apt install open-vm-tools` (ships the 180s udev rule), reboot → clears.
- **Why:** a real outage cause during storage maintenance/migration.

### 8. open-vm-tools missing / stopped
- **Induce:** `apt remove open-vm-tools` (missing) or `systemctl stop vmtoolsd` (stopped).
- **Expect:** `WARN … open-vm-tools not installed …` / `… installed but not running — quiesced snapshots/backups and graceful guest shutdown will fail`.
- **Why:** no quiesced backups, time sync, graceful shutdown, ballooning.

### 9. Network blame-attribution (the partial-but-valuable slice)
The pain that opens the head-of-networking conversation: a client's VM "doesn't
work," they blame the network, the team must prove it isn't them.
- **Induce:** on the VM, or a 2nd VM on the same port group, misconfigure virtual
  networking (wrong port group / VLAN, MTU mismatch, detach vNIC).
- **Run:** `dsd net deep`.
- **Expect (today):** the guest's *own* stack reported healthy (interface, MTU,
  gateway, DNS, conntrack) → evidence the fault is the vSwitch/fabric/customer
  side, not the guest. This is the **passive ~40% exoneration**.
- **OPEN — do not over-promise:** the *directional* path-trace ("the packet died
  before leaving the virtual layer") is **not built** — it's gated on the
  head-of-networking confirming directional guest-side evidence is what gets his
  team off the hook (ADR-0002 Decision 6 / `~/dashdiag-outreach-head-of-networking.md`,
  on HOLD until this pilot produces wins). Sell only the guest-side slice.

---

## Evidence-capture template (one per win)

Record each induced-and-caught fault as:

```
## <signal> — e.g. "Host CPU limit caught"
Induced:    <exact vSphere/console change>
Command:    dsd health   (on <guest>, <distro>, VMware <product>)
dsd said:   <the exact WARN/CRIT line>
Customer translation: "<one sentence the customer/manager understands>"
Artifact:   evidence/<file>.txt   (and a screenshot of the terminal)
```

Goal (ADR-2): **3–5 genuinely VMware-relevant catches**, correct and impressive,
plus the artifacts. Build the deck FROM these, after they exist — not before.

---

## Notes
- Validation status of each check (what's live-validated vs needs real VMware) is
  in `docs/VMWARE_VALIDATION.md`. The CPU/mem-limit, balloon, swap rows need real
  VMware to exercise (KVM has no VMware backdoor); the SCSI-timeout and gate/tools
  rows are already live-validated on the KVM-spoof rig.
- The strongest single permission to confirm with the contact: the per-VM **CPU
  Limit / Memory Limit** fields (some orgs lock resource settings) — they unlock
  #1 and #2, the best demos. See `docs/VMWARE_TRIAL_ASK.md`.
