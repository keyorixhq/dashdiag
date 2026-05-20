# DashDiag (`dsd`)

**OBD diagnostics for your Linux server.**

Your car has had a health scanner since 1996. Plug it in, get:
*"cylinder 3 misfire, coolant temp sensor reading high."* No guessing.

`dsd` does the same for Linux. One command. Full picture. 1–3 seconds.

```
$ sudo dsd health

CPU Load     ✅  3%
CPU Thermal  ✅  44°C
Memory       ✅  0.6/13 GB (4%)
Swap         ✅  0 MB used
Disk         ✅  4 mounts, max 28% (/boot)
IO           ✅  0.6 ms (nvme1n1)
Drives       ✅  2 drives  healthy
LVM          ✅  1 VG
Network      ✅  bond0 1Gbps  gw <1 ms
Bonding      ✅  bond0  2/2 slaves up  active-backup
Systemd      ✅  boot 30s
Processes    ✅  304 running
FDLimits     ✅  1k open
Entropy      ✅  256/256 bits
Clock        ✅  ±0 ms
Logs         ⚠️  journald volatile — logs lost on reboot
Sysctl       ⚠️  vm.swappiness=60 (recommended: ≤10 for servers)
KernelSec    ℹ️  SELinux enforcing
Hardening    ✅
Battery      ✅  100%
OOM          ✅  0 events
Sessions     ✅  2 sessions  1 remote
CPUFreq      ✅  performance  3820/4465 MHz
────────────────────────────────────────────────────────
⚠️  Sysctl: vm.swappiness=60 is high for a server
   → to fix:    sysctl -w vm.swappiness=10
   → to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf
done in 1.3s
```

No agents. No cloud. No registration. Single binary over SSH.

---

## Install

```bash
# Linux (amd64)
curl -sSL https://github.com/keyorixhq/dashdiag/releases/latest/download/dsd-linux-amd64 \
  -o /usr/local/bin/dsd && chmod +x /usr/local/bin/dsd

# macOS (Apple Silicon)
curl -sSL https://github.com/keyorixhq/dashdiag/releases/latest/download/dsd-darwin-arm64 \
  -o /usr/local/bin/dsd && chmod +x /usr/local/bin/dsd

# macOS (Intel)
curl -sSL https://github.com/keyorixhq/dashdiag/releases/latest/download/dsd-darwin-amd64 \
  -o /usr/local/bin/dsd && chmod +x /usr/local/bin/dsd
```

Or build from source (requires Go 1.22+):

```bash
git clone https://github.com/keyorixhq/dashdiag
cd dashdiag && make install
```

---

## Commands

| Command | What it does | Time |
|---|---|---|
| `dsd health` | Full system snapshot — CPU, memory, disk, network, security | ~1–3s |
| `dsd cpu` | Load, frequency, temperature, top processes | ~1s |
| `dsd disk` | Filesystems, SMART, ZFS, LVM RAID, btrfs health | ~3s |
| `dsd net` | Interfaces, bond slaves, latency, DNS, TCP states | ~5s |
| `dsd gpu` | GPU temperature, VRAM, utilisation (NVIDIA + AMD) | ~5s |
| `dsd hardware` | Physical drives, thermals, memory, NVMe | ~5s |
| `dsd cve` | CVE scan via dnf/apt/zypper advisories | ~3s |
| `dsd cve --oval-scan` | CVSS-scored scan against OVAL feed | ~10s |
| `dsd docker` | Container health, volumes, crash loops | ~5s |
| `dsd k8s` | Kubernetes nodes, pods, restarts, OS-layer checks | ~15s |
| `dsd timeline` | Unified incident timeline — journal + dmesg + load | ~5s |
| `dsd security` | SSH config, SELinux/AppArmor, sudoers, failed logins | ~3s |
| `dsd services` | Check TCP/HTTP endpoints are actually reachable | ~5s |
| `dsd logs` | OOM kills, segfaults, crash loops, journal errors | ~3s |
| `dsd proc <pid>` | Deep process inspect — memory map, FDs, connections | ~3s |

Every command supports `--json` for scripting and `--plain` for CI output.

---

## When things break

When a check fires WARN or CRIT, `dsd` tells you what's causing it — not just that something is wrong:

```
$ sudo dsd health

Memory       CRIT  RAM at 94% (1.0 GB free of 16 GB)
   Top processes by memory:
   PID    MEM%  RSS     COMMAND
   12345  31.4  5.0 GB  postgres
   23456  18.2  2.9 GB  java

Disk         CRIT  /var/log at 97% (2.1 GB of 50 GB used)
   Largest directories:
   18 GB   /var/log/nginx
    3 GB   /var/log/syslog.1

LVM          CRIT  volume group data-vg is 100% full — 1 missing PV(s), data at risk
   → to add PV: pvcreate /dev/sdb && vgextend data-vg /dev/sdb
```

No "check your logs." No copy-paste detour. The cause is where the verdict is.

---

## Incident timeline

After an overnight incident, `dsd timeline` reconstructs what happened:

```
$ sudo dsd timeline

02:17  Memory ↓ CRIT — RAM at 97% (0.3 GB free)
02:17  IO     ↓ CRIT — disk latency 28.5ms (10× baseline)
02:17  Logs   ↓ CRIT — 5 OOM kills: postgres, coredns, traefik
02:18  Logs   ↓ CRIT — kernel: EXT4 error on sda1 (I/O error)
02:31  Memory ↑ OK — recovered after OOM kills
02:31  IO     ↑ OK
03:15  Disk   ↓ WARN — /var/log at 89% (OOM logs accumulated)
```

One command. No log diving. Full post-mortem in seconds.

---

## CVE scanning

```bash
# Check pending advisories via package manager
sudo dsd cve --all

# CVSS-scored scan against OVAL feed (air-gap friendly)
sudo dsd cve --oval-scan

# Check a specific CVE
sudo dsd cve CVE-2024-3094
```

Works on RHEL, Fedora, Rocky, AlmaLinux, CentOS (dnf), Debian, Ubuntu (apt/dpkg),
openSUSE, SLES (zypper). Supports RHEL, Ubuntu/Debian, and SUSE OVAL feeds.

---

## Disk health

```bash
$ sudo dsd disk

Filesystems (4)
  ✅  /              xfs    14.0G / 100.0G   (14%)
  ✅  /boot          xfs     0.3G /   1.0G   (28%)
  ⚠️  /var/log       xfs    44.8G /  50.0G   (90%)  ← high usage
  ✅  /data          ext4    2.1G / 200.0G    (1%)

LVM (2 VGs)
  ✅  data-vg        200.0GB total  197.9GB free  (99%)
  ❌  root-vg        100.0GB total    0.0GB free  (0%)  ← CRIT: VG full
  RAID/mirror LVs (1):
  ❌  root-vg/mirror_root  raid  DEGRADED
       ❌ 1 missing PV(s) — data at risk

NVMe drives (2)
  ✅  nvme0n1  SK Hynix  1TB   SMART: healthy  temp: 38°C  written: 12.4 TB
  ✅  nvme1n1  SK Hynix  1TB   SMART: healthy  temp: 36°C  written: 11.2 TB
```

Detects: LVM RAID degradation, missing PVs, thin pool saturation, btrfs missing
devices, ZFS pool faults, SMART pre-failure, high I/O latency.

---

## Network bonding

```bash
$ sudo dsd net

Interfaces (1)
  ✅  bond0   192.168.1.100   1000 Mbps  ← primary

Bond interfaces (1)
  ⚠️   bond0   active-backup   DEGRADED — 1/2 slaves up
      ❌  eno1          MII:down  1000 Mbps  18 link failures
      ✅  enp6s0f3u1   MII:up    1000 Mbps  [USB]  ← active

Connectivity
  ✅  Gateway ping:     0.8 ms
  ✅  Internet ping:    6.0 ms
  ✅  DNS resolution:   3.0 ms
```

Detects RAID1 bonding degradation, missing slaves, USB NICs in production bonds,
link failure counts, active slave tracking.

---

## CI / scripting

`dsd` follows Unix conventions by design:

```bash
# Gate a deploy on server health
ssh deploy@$SERVER 'dsd health' || exit 1

# Parse CRIT checks from JSON
ssh $SERVER 'dsd health --json' | jq '.checks[] | select(.status == "CRIT")'

# Multi-server sweep
for host in web1 web2 db1 db2; do
  echo "=== $host ==="
  ssh $host 'dsd health --plain'
done
```

**Exit codes:** `0` = healthy, `1` = warnings, `2` = critical issues.

No agent. No port. No registration. Works wherever SSH works.

---

## Distro support

Validated on: RHEL 10, Rocky Linux 10, AlmaLinux 10, CentOS Stream 10,
Fedora 44, Debian 13, Ubuntu 26.04, openSUSE Leap 16, SLES 16, Linux Mint 22.

Requires: Linux kernel 4.18+ or macOS 12+. Single binary, no dependencies.

---

## Design principles

- **Read-only** — no writes to the system, ever
- **No agent** — binary runs on demand, nothing stays resident
- **No cloud** — all data stays on the machine
- **Fast** — most commands complete in 1–3 seconds
- **Distro-aware** — detects package manager, init system, and container runtime automatically
- **Composable** — `--json`, `--plain`, exit codes designed for scripting

---

## Built by

[Keyorix SL](https://keyorix.io) — Madrid, Spain.

---

## License

MIT
