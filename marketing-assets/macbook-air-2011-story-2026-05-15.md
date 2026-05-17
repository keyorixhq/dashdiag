# DashDiag 2011 MacBook Air Story — 2026-05-15

> Ubuntu 24.04 LTS on a 2011 MacBook Air (MacBookAir4,2).
> Intel Core i5-2557M Sandy Bridge. 4GB DDR3. 128GB Apple SSD.
> 14 years old. Still serving.

## The findings

### Drives
```
dsd hardware (as root, with smartmontools installed)

/dev/sda — APPLE SSD SM128C
  SMART:       ✅  PASSED
  Temperature: ✅  33°C
  Power-on:    ✅  7733 h (322 days)
  Wear:        ❌  3491877946276% used   ← Apple SSD firmware quirk, ignore
  Bad sectors: ❌  reallocated:794  pending:0  uncorrectable:0
```

794 reallocated sectors. The SSD is remapping bad blocks.
It's not failing. It's already failed — slowly, one sector at a time.

### The thermal story

**At rest (idle):**
```
CPU Thermals
  Package id 0:  ⚠️  61°C — high at 7% load  (coretemp)
  Core 0:        ⚠️  60°C — high at 7% load  (coretemp)
  Core 1:        ✅  58°C  (coretemp)
```

dsd detects high temp at low load — the load-aware thermal check.
Normal servers don't run at 61°C idle. This one does. Dried thermal paste.

**Under moderate stress (2 cores):**
```
CPU Thermals
  Package id 0:  ⚠️  94°C — elevated  (coretemp)
  Core 0:        ⚠️  92°C — elevated  (coretemp)
  Core 1:        ⚠️  94°C — elevated  (coretemp)
```

94°C. Sandy Bridge Tjmax is 100°C. This machine is one sustained
workload away from thermal throttling.

**After stress, back at rest:**
```
CPU Thermals
  Package id 0:  ⚠️  64°C — high at 7% load  (coretemp)
```

Recovered — but still too hot for idle. The system is balancing on the edge.

### dsd health summary (full picture)
```
CPU Load     ✅  19%
CPU Thermal  ⚠️  high at idle
Drives       ⚠️  794 reallocated sectors — early sign of drive failure
Hardening    ⚠️  docker-proxy on port 30000 exposed on all interfaces
Sysctl       ⚠️  inotify watches low for k8s
```

## What this proves

- Load-aware thermal check: WARN fires when temp is high at low load
- CPU Load and CPU Thermal are separate checks — no ambiguity
- SMART bad sector detection on real aging hardware
- dsd works on Apple hardware running Linux
- All findings are real — nothing fabricated for a demo

## Can it be fixed?

**RAM — soldered.** 4GB permanently on the board. No upgrade path.

**CPU — soldered BGA.** Not replaceable by any practical means.

**SSD — technically replaceable**, but Apple used a proprietary blade connector.
OWC made compatible drives for years. That market has dried up.
Finding a replacement now is hard, expensive, and not worth it.

## The verdict

This machine cannot be meaningfully repaired. The SSD is dying and
can't be practically replaced. The RAM can't be expanded. The CPU
can't be replaced.

dsd doesn't just find problems — it gives you the data to make the
right call: **replace or repair**.

In this case: replace.

## The hardware is Apple. The story is universal.

Every sysadmin running Linux on aging servers — Dell, HP, Lenovo, whatever —
has exactly this machine somewhere. Dried paste, dying drive, ports nobody
remembers opening. The brand is irrelevant. The findings are not.

## The thermal arc (for social/demo use)

1. Idle: 61°C at 7% load → ⚠️ high at idle
2. Load applied: climbs to 94°C → ⚠️ elevated
3. Load removed: drops to 64°C → ⚠️ still high at idle
4. System is balancing on the edge — looks almost OK when idle,
   falls apart under load

## Machine

- Apple MacBookAir4,2 (Mid 2011)
- Intel Core i5-2557M @ 1.70GHz (2c/4t, Sandy Bridge)
- 4 GB DDR3 @ 1333 MT/s
- APPLE SSD SM128C (128GB, SATA)
- Ubuntu 24.04.4 LTS, kernel 6.8.0-111-generic
- USB ethernet dongle (asix) — no built-in ethernet on MBA
- WiFi down (brcmsmac — old Broadcom, poor Linux support)
- Docker running, k8s sysctl hints present
- 192.168.10.10
