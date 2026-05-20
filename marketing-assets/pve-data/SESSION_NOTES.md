# PVE Session Notes — 2026-05-20

## Hardware
- Host: `root@192.168.10.20`
- PVE 9.1.1, kernel 6.17.2-pve
- CPU: i7-6700 (4c/8t), 32GB RAM
- Storage: local (39GB), local-lvm (54GB lvmthin), local-hdd (1.8TB dir)

## Guests during sweep
- VM 100 `linuxtst` — stopped (started briefly for kvm test, restored to stopped)
- CT 200 almalinux-lxc — running
- CT 201 debian13-lxc — running
- CT 202 ubuntu24-lxc — running
- CT 203 rocky10-lxc — running
- CT 204 opensuse16-lxc — running

## dsd pve highlights
- ❌ vCPU ratio 40 vCPUs / 4 cores (10:1) — CRIT overcommit
- ❌ No successful backup found
- ⚠️  pveperf fsyncs/sec: 297–302 (< 500 threshold) — spinning disk
- ✅ Storage all healthy (0–14%)
- ✅ Cluster quorate (single node)
- ℹ️  No subscription (community edition)

## Graceful-handling confirmed ✅
- `dsd docker` — "no Docker or Podman socket found"
- `dsd k8s`    — "No Kubernetes installation detected"
- `dsd tls`    — "no certificates found"
- `dsd gpu`    — minimal output (no discrete GPU)

## Bugs found

### BUG-1: `dsd kvm` blind on PVE
- **Symptom**: `"detected": false` even with VM running
- **Root cause**: kvm collector uses libvirt/virsh — PVE has neither
- **PVE reality**: QEMU processes at `/var/run/qemu-server/*.pid`, `/usr/bin/kvm`
- **Fix**: Add PVE-aware detection path — check `/var/run/qemu-server/` dir or
  `ps aux | grep kvm` as fallback when libvirt absent + `pveversion` present

### BUG-2: `dsd security` / `dsd health` false-positive ports
- **Symptom**: 8006/tcp, 3128/tcp, 111/tcp flagged as "unexpected"
- **Root cause**: No PVE-aware port whitelist
- **PVE reality**: 8006 = pveproxy (web UI), 3128 = spiceproxy, 111 = rpcbind (NFS)
- **Fix**: When `pveversion` detected, whitelist these ports with PVE annotations

### BUG-3: `dsd health` Firewall false positive on PVE
- **Symptom**: WARN "nftables is installed but no rules are active"
- **Root cause**: PVE manages firewall via `pve-firewall` service, not raw nftables
- **Fix**: When PVE detected, check `pve-firewall status` instead of nftables rules

### BUG-4: `dsd health` SSH root login CRIT on PVE
- **Symptom**: CRIT "SSH permits root login"
- **Root cause**: No PVE context — root SSH is required for PVE management
- **Fix**: When PVE detected, downgrade to WARN/INFO with note "expected on PVE hosts"

### BUG-5: `dsd health` PVE row missing backup CRIT
- **Symptom**: health PVE row shows subscription WARN but "no backup" CRIT from
  `dsd pve` is not surfaced
- **Fix**: `dsd health` PVE check should also report backup status as CRIT

## Marketing angles
- **10:1 vCPU overcommit on 4 cores** — silent death trap, proved in 8s
- **pveperf fsync 297/s** — VM disk I/O under threshold, spinning HDD confirmed
- **LXC AppArmor denials** — PVE containers generating denials, visible instantly
