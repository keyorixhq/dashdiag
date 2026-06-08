# VMware-guest collector — validation runbook

Step-by-step plan to validate `dsd`'s VMware-guest checks on a **real VMware
guest** (the design-partner pilot's environment). Scope is guest-side only
(ADR-0002: Linux guest VMs IN; ESXi host / vSwitch OUT — not visible from inside
a guest).

The collector is `internal/collectors/vmware_linux.go`; the verdict logic is
`checkVMware` in `internal/analysis/heuristics.go`. Everything is gated behind
`VMwareGuestAvailable()` (DMI `sys_vendor`/`product_name` contains "vmware"), so
it is silent on non-VMware hosts.

## What each check does, and how to exercise it

| # | Insight | Fires when | Reproduce on a real guest | Expected output |
|---|---------|-----------|---------------------------|-----------------|
| 1 | gate (silent on non-VMware) | DMI is not VMware | run `dsd health` on the guest | a `VMware` line appears at all = gate fired |
| 2 | `WARN` tools not installed | `vmtoolsd` binary absent | `apt remove open-vm-tools` (or never install) | `open-vm-tools not installed … no time sync, quiesced backups, graceful shutdown, or ballooning` |
| 3 | `WARN` tools installed, not running | binary present, no `vmtoolsd` process | `apt install open-vm-tools && systemctl stop vmtoolsd` | `open-vm-tools installed but not running — quiesced snapshots/backups and graceful guest shutdown will fail` |
| 4 | `INFO` recognition (all clean) | tools running + no emulated NIC | `systemctl start vmtoolsd`, NIC = VMXNET3 | `VMware guest (<product>) — open-vm-tools running, paravirtual NIC drivers in use` |
| 5 | `WARN` emulated NIC | any NIC driver ∈ {e1000, e1000e, vlance, pcnet32} | in vSphere set the adapter type to **E1000**, reboot guest | `NIC(s) on an emulated driver (eth0 (e1000)) — vmxnet3 … higher throughput at lower host CPU` |

## Validation status (as of 2026-06-07)

Validated **live** on a KVM VM with spoofed VMware SMBIOS (pve01 VM 103,
192.168.10.63 — `sys_vendor="VMware, Inc."`, `product_name="VMware7,1"`):

- ✅ #1 gate fires; collector runs without crash; DMI product read.
- ✅ #2 tools-not-installed → WARN.
- ✅ #3 tools-installed-but-not-running → WARN (vmtoolsd inactive on KVM — no
  VMware backdoor).
- ✅ #4 INFO recognition — exercised by spoofing a `vmtoolsd`-named process
  (`cp /usr/bin/sleep /tmp/vmtoolsd && /tmp/vmtoolsd 600 &`) so the comm-name scan
  in `vmwareToolsRunning` matches; confirmed the INFO line renders.
- ✅ NIC driver read from `/sys/class/net/<if>/device/driver` (eth0 → virtio_net,
  correctly **not** flagged emulated — virtio is paravirtual).

**Still needs a real VMware guest** (the only remaining gaps):

- ⏳ #5 emulated-NIC WARN — the classification (`nicDriverEmulated`) is
  unit-tested, but no live host has an e1000 NIC: VM 103's cloud kernel lacks the
  `e1000` module. Confirm on real VMware that an E1000 adapter surfaces driver
  name `e1000` in `/sys` and trips the WARN; then flip to VMXNET3 and confirm it
  clears.
- ⏳ `vmw_pvscsi` / `vmw_balloon` module detection — needs a real VMware guest
  where those modules load. See open decision below.

## Recreate the KVM-spoof rig (no VMware needed)

VM 103 on pve01 ([[vmware-validation-vm]] in memory). The spoof:

```
qm set 103 --smbios1 manufacturer=<b64 "VMware, Inc.">,product=<b64 "VMware7,1">,base64=1
```

→ trips `VMwareGuestAvailable()`. Deploy `dsd`: build linux-amd64 → scp to pve01 →
scp pve01 → `debian@192.168.10.63:/tmp/dsd`. This rig validates everything except
the e1000 driver name and the pvscsi/balloon modules (which require real VMware
hardware/drivers).

## Real-VMware test procedure (when the resources land)

1. Provision a throwaway Linux guest (Debian/Ubuntu or RHEL-family) on vSphere.
2. Deploy `dsd` and run `dsd health` + `dsd health --json`. Confirm the `VMware`
   line appears (gate) — record the product string.
3. Walk rows #2–#5 above, changing one variable at a time and re-running
   `dsd health` after each, confirming the expected insight.
4. For #5: default adapter is often E1000 → expect the WARN immediately; switch to
   VMXNET3 in vSphere, reboot, confirm it clears to the #4 INFO.
5. Capture `dsd health --json` for the `vmware` object and verify
   `tools_installed`, `tools_running`, `nic_drivers`, `emulated_nics`,
   `pvscsi_loaded`, `balloon_loaded` reflect reality.

## Resolved — pvscsi / balloon now surfaced in the INFO line

**Decision (founder, 2026-06-07): enrich the recognition line.** The #4 INFO line
now reads, e.g.:

```
VMware guest (VMware7,1) — open-vm-tools running; NICs: vmxnet3; paravirtual SCSI: yes; balloon: yes
```

Informational, no WARN (avoids the LSI-Logic / built-in-module false-positive
risk). `kernelModulePresent` now checks `/sys/module/<name>` in addition to
`/proc/modules`, so a built-in (non-module) `vmw_pvscsi`/`vmw_balloon` is not
misreported as absent. Verified live on VM 103 (shows the KVM values
`virtio_net; … : no; … : no`); the real-VMware test (#5 + module rows) confirms
the demo-worthy `vmxnet3; … yes; … yes`.

## Runtime resource pressure + SCSI timeout (added 2026-06-08)

These move the collector from *config hygiene* to *blame-attribution* — the
memory/CPU analog of CPU steal, plus a documented storage-resilience check.
Built ahead of the time-boxed VMware trial so the trial window is spent inducing
faults, not writing collectors.

| # | Insight | Source | Fires when | Reproduce on real VMware |
|---|---------|--------|-----------|--------------------------|
| 6 | `WARN` host ballooning | `vmware-toolbox-cmd stat balloon` | balloon > 0 MB | overcommit host memory so ESXi inflates this guest's balloon |
| 7 | `WARN` host swapping guest RAM | `stat swap` | swap > 0 MB | severe host memory contention (host-level swap) |
| 8 | `WARN` host memory limit set | `stat memlimit` | finite limit (not "Unlimited") | set a per-VM memory **Limit** in vSphere resource settings |
| 9 | `WARN` host CPU limit set | `stat cpulimit` | finite limit (not "Unlimited") | set a per-VM CPU **Limit** (MHz) in vSphere — the invisible "slow VM" cause |
| 10 | `WARN` SCSI timeout < 180s | `/sys/block/sd*/device/timeout` | any sd* below 180s | default 30s on a non-open-vm-tools guest; clears after the udev rule sets 180 |

Rows 6–9 require **open-vm-tools running** (gated on `ToolsRunning`), so they are
silent on a guest whose tools are stopped — which is itself already a WARN (#3).
The `stat` interface is probed via `balloon`; if that call fails the whole block
is skipped and `stat_available=false` (no phantom WARNs from zero values).

### Validation status (2026-06-08)

- ✅ **#10 SCSI timeout — live true-positive on VM 103.** The cloud image's `sda`
  sits at the kernel-default 30s; `dsd health` correctly emits the WARN naming
  `sda (30s)`, and `scsi_timeouts`/`low_scsi_timeouts` serialize in `--json`. The
  sysfs path (`/sys/block/sd*/device/timeout`) is identical on KVM SCSI and
  VMware, so the read path is fully exercised; only the *180s-after-udev* clear
  needs confirming on a real open-vm-tools guest.
- ✅ Collector runs without crash on the spoofed-DMI rig; new fields serialize.
- ⏳ **#6–#9 need a real VMware host** — VM 103 has no working open-vm-tools stat
  interface (KVM, no VMware backdoor), so balloon/swap/memlimit/cpulimit cannot
  be exercised here. The parsers (`parseLeadingInt`, `vmwareStatLimit`'s
  "Unlimited" handling) are unit-tested; the values + thresholds (esp. whether a
  bare `BalloonMB>0` is too noisy vs. needing a floor) must be tuned in Week 1 of
  the trial. **#9 (CPU limit) is the headline demo target** — a host-imposed CPU
  cap is the canonical invisible cause of a "slow VM" the guest gets blamed for.
