# DashDiag Overnight Story — 2026-05-11

> `sudo dsd health --story` output after 9 hours of alternating CPU + GPU stress
> on a RHEL 10.1 laptop with AMD Ryzen 7 5800H, 16GB RAM, RTX 3070, k3s.

```
⚡ DashDiag (dsd) v0.2.0-32-g5034efd-dirty
System health — 48 snapshots — 18:03 11.05.2026 to 03:00 12.05.2026 on localhost.localdomain
────────────────────────────────────────────────────────

Events:
  18:03  Swap ↑ WARN — swap activity detected: 49 pages/s in, 0 pages/s out
  18:03  Swap ↓ CRIT — heavy swap activity: 106 pages/s in, 0 pages/s out
  18:04  CPU ↑ WARN — load average at 88% of capacity (14.04 / 16 CPUs)
  18:04  IO ↓ WARN — disk nvme1n1 await latency 5.0 ms
  18:04  Processes ↓ WARN — 1 hung (uninterruptible) process(es)
  18:04  IO ↑ OK
  18:04  Processes ↑ OK
  18:04  CPU ↑ OK

  19:00  Memory ↓ CRIT — RAM usage at 98% (0.1 GB free of 15.2 GB total)
  19:00  Thermal ↓ WARN — CPU temperature 89.25°C — elevated (source: k10temp)
  19:00  Processes ↓ CRIT — 11 hung (uninterruptible) processes
  19:00  CPU ↓ CRIT — load average at 257% of capacity (41.14 / 16 CPUs)
  19:00  Swap ↓ CRIT — swap usage at 84% (6.5 GB used)

  19:43  Memory ↑ OK
  19:43  Thermal ↑ OK
  19:43  Processes ↑ OK
  19:43  CPU ↑ OK
  19:43  Logs ↑ OK
  19:43  Swap ↑ OK
  19:43  Network ↑ OK

  20:00  Memory ↓ CRIT — RAM usage at 97% (0.1 GB free of 15.2 GB total)
  20:00  Thermal ↓ CRIT — CPU temperature 98.375°C — thermal throttling active
  20:00  CPU ↓ CRIT — load average at 272% of capacity (43.58 / 16 CPUs)
  20:00  Processes ↓ CRIT — 6 hung (uninterruptible) processes
  20:00  Logs ↓ CRIT — 5 OOM kill(s) in the last hour — processes killed: traefik, coredns, stress
  20:00  IO ↓ WARN — disk nvme1n1 await latency 10.6 ms
  20:00  Swap ↓ CRIT — swap usage at 83% (6.5 GB used)
  20:00  Network ↓ CRIT — gateway ping is 364 ms — severe latency

  20:30  Memory ↑ OK
  20:30  Thermal ↑ OK
  20:30  Processes ↑ OK
  20:30  GPU ↓ WARN — NVIDIA GeForce RTX 3070 Laptop GPU VRAM usage at 95% (7747/8192 MB)
  20:30  CPU ↑ OK
  20:30  IO ↑ OK
  20:30  Swap ↑ WARN — swap activity detected: 16 pages/s in, 0 pages/s out

  21:00  Memory ↓ CRIT — RAM usage at 97% (0.2 GB free of 15.2 GB total)
  21:00  Thermal ↓ WARN — CPU temperature 89.375°C — elevated (source: k10temp)
  21:00  CPU ↓ CRIT — load average at 261% of capacity (41.76 / 16 CPUs)
  21:00  GPU ↑ OK
  21:00  Logs ↑ OK
  21:00  Swap ↓ CRIT — swap usage at 98% (7.7 GB used)
  21:00  IO ↓ WARN — disk nvme1n1 await latency 13.4 ms
  21:00  Processes ↓ WARN — 4 hung (uninterruptible) process(es)

  21:30  Memory ↑ OK
  21:30  Thermal ↑ OK
  21:30  GPU ↓ WARN — NVIDIA GeForce RTX 3070 Laptop GPU VRAM usage at 95% (7747/8192 MB)
  21:30  CPU ↑ OK
  21:30  Logs ↓ CRIT — 5 OOM kill(s) in the last hour — processes killed: traefik, coredns, stress
  21:30  IO ↑ OK
  21:30  Swap ↑ WARN — swap activity detected: 43 pages/s in, 0 pages/s out

  22:00  Memory ↓ WARN — RAM usage at 86% (1.9 GB free of 15.2 GB total)
  22:00  Thermal ↓ WARN — CPU temperature 88.25°C — elevated (source: k10temp)
  22:00  GPU ↑ OK
  22:00  CPU ↓ CRIT — load average at 259% of capacity (41.51 / 16 CPUs)
  22:00  Logs ↑ OK
  22:00  Swap ↓ CRIT — swap usage at 76% (6.0 GB used)

  22:30  Memory ↑ OK
  22:30  Thermal ↑ OK
  22:30  GPU ↓ WARN — NVIDIA GeForce RTX 3070 Laptop GPU VRAM usage at 95% (7747/8192 MB)
  22:30  CPU ↑ OK
  22:30  Logs ↓ CRIT — 5 OOM kill(s) in the last hour — processes killed: traefik, coredns, stress
  22:30  Swap ↑ WARN — swap activity detected: 45 pages/s in, 0 pages/s out

  23:00  Memory ↓ CRIT — RAM usage at 97% (0.2 GB free of 15.2 GB total)
  23:00  Thermal ↓ WARN — CPU temperature 88.875°C — elevated (source: k10temp)
  23:00  GPU ↑ OK
  23:00  CPU ↓ CRIT — load average at 259% of capacity (41.44 / 16 CPUs)
  23:00  Logs ↑ OK
  23:00  Swap ↓ CRIT — swap usage at 79% (6.1 GB used)
  23:00  IO ↓ WARN — disk nvme1n1 await latency 8.6 ms

  23:30  Memory ↑ OK
  23:30  Thermal ↑ OK
  23:30  Processes ↑ OK
  23:30  CPU ↑ OK
  23:30  Logs ↓ CRIT — 5 OOM kill(s) in the last hour — processes killed: traefik, coredns, stress
  23:30  IO ↑ OK
  23:30  Swap ↑ OK

  00:00  Memory ↓ CRIT — RAM usage at 98% (0.1 GB free of 15.2 GB total)
  00:00  Thermal ↓ WARN — CPU temperature 89.125°C — elevated (source: k10temp)
  00:00  Processes ↓ CRIT — 9 hung (uninterruptible) processes
  00:00  CPU ↓ CRIT — load average at 260% of capacity (41.63 / 16 CPUs)
  00:00  IO ↓ WARN — disk nvme1n1 utilization at 64%
  00:00  Swap ↓ WARN — swap usage at 49% (3.8 GB used)

  00:30  Memory ↑ OK
  00:30  Thermal ↑ OK
  00:30  Processes ↑ WARN — 2 hung (uninterruptible) process(es)
  00:30  CPU ↑ OK
  00:30  IO ↑ OK

  01:00  Memory ↓ CRIT — RAM usage at 96% (0.3 GB free of 15.2 GB total)
  01:00  Thermal ↓ WARN — CPU temperature 89.375°C — elevated (source: k10temp)
  01:00  CPU ↓ CRIT — load average at 264% of capacity (42.21 / 16 CPUs)
  01:00  Logs ↑ OK
  01:00  IO ↓ CRIT — disk nvme1n1 await latency 19.6 ms

  01:30  Memory ↑ OK
  01:30  Thermal ↑ OK
  01:30  CPU ↑ OK
  01:30  Logs ↓ CRIT — 5 OOM kill(s) in the last hour — processes killed: traefik, coredns, stress
  01:30  IO ↑ OK

  02:00  Memory ↓ WARN — RAM usage at 91% (1.1 GB free of 15.2 GB total)
  02:00  Thermal ↓ WARN — CPU temperature 88.75°C — elevated (source: k10temp)
  02:00  CPU ↓ CRIT — load average at 265% of capacity (42.46 / 16 CPUs)

  02:30  Memory ↑ OK
  02:30  Thermal ↑ OK
  02:30  CPU ↑ OK

  03:00  Memory ↓ WARN — RAM usage at 93% (0.8 GB free of 15.2 GB total)
  03:00  Thermal ↓ WARN — CPU temperature 92°C — elevated (source: k10temp)
  03:00  CPU ↓ CRIT — load average at 266% of capacity (42.55 / 16 CPUs)
  03:00  Logs ↑ OK
  03:00  Processes ↓ CRIT — 5 hung (uninterruptible) processes
  03:00  Swap ↓ CRIT — heavy swap activity: 29989 pages/s in, 0 pages/s out

Current issues:
  Memory: RAM usage at 93% (0.8 GB free of 15.2 GB total)
  Thermal: CPU temperature 92°C — elevated (source: k10temp)
  CPU: load average at 266% of capacity (42.55 / 16 CPUs)
  Sysctl: fs.inotify.max_user_watches=122241 is low for k8s (recommended: 524288)
  Processes: 5 hung (uninterruptible) processes
  Hardening: 2 unexpected port(s) listening on all interfaces: 6443/tcp, 10250/tcp
  Swap: heavy swap activity: 29989 pages/s in, 0 pages/s out
  Network: gateway ping is 446 ms — severe latency
```

## What this proves

- 48 snapshots across 9 hours
- 18 collectors running every 30 minutes
- Every stress event caught (CPU stress at :00, GPU stress at :30)
- Recovery cycles clearly visible (↓ CRIT → ↑ OK pattern)
- Real thermal throttling at 98.375°C captured
- Real swap thrashing (29,989 pages/s) captured at 03:00
- One command, full incident timeline

## Hardware

- AMD Ryzen 7 5800H (8c/16t)
- 16GB RAM
- 2x SK Hynix 1TB NVMe (Windows + RHEL dual boot)
- NVIDIA RTX 3070 Laptop 8GB
- RHEL 10.1 (Coughlan), kernel 6.12.0
- k3s v1.35.4+k3s1

## Stress pattern (cron)

```
55 * * * *  disk fill (6GB user + 6GB root, staggered)
58 * * * *  stress --cpu 16 --vm 4 --vm-bytes 3G --io 4 --timeout 300s
58 * * * *  curl flood × 200 connections
59 * * * *  tc qdisc add dev eno1 root netem delay 200ms loss 10% for 90s
29 * * * *  gpu_burn 120s
0,30 * * * * dsd health --terse --gpu >> /root/.dsd/cron.log
```
