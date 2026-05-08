# DashDiag — Linux Compatibility Test Plan
# Priority-sorted. Work top to bottom. Do not move to next until current passes.
# Binary locations: dist/dsd-linux-amd64 (x86) | dist/dsd-linux-arm64 (ARM)
# Last updated: 2026-05-08

---

## HOW TO RUN EACH TEST

### Physical machine or VM
```bash
# Copy binary
scp dist/dsd-linux-amd64 user@host:/tmp/dsd
ssh user@host
chmod +x /tmp/dsd

# Run basic checks
/tmp/dsd --version
/tmp/dsd health
/tmp/dsd health --json | python3 -m json.tool
/tmp/dsd health --plain
echo "Exit code: $?"

# Run full stress suite (SSH-safe)
scp scripts/stress/stress.sh user@host:/tmp/stress.sh
DSD_BIN=/tmp/dsd sudo bash /tmp/stress.sh all

# Run physical-access tests (only with console access)
DSD_BIN=/tmp/dsd sudo bash /tmp/stress.sh --physical all
```

### Docker (for distros you do not have physical access to)
```bash
# amd64
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  <IMAGE> \
  sh -c "dsd health --plain && echo EXIT:$?"

# arm64 (from Apple Silicon Mac)
docker run --rm \
  --platform linux/arm64 \
  -v $(pwd)/dist/dsd-linux-arm64:/usr/local/bin/dsd \
  <IMAGE> \
  sh -c "dsd health --plain && echo EXIT:$?"
```

### What counts as PASS
- [ ] `dsd --version` exits 0
- [ ] `dsd health` exits 0, 1, or 2 (never 3+)
- [ ] `dsd health --json` produces valid JSON (python3 -m json.tool)
- [ ] `dsd health --plain` has no ANSI codes
- [ ] No `panic:` or `runtime error:` in output
- [ ] No collector hangs beyond 35 seconds
- [ ] Slow collectors return gracefully (no crash) when binary unavailable

---

## PRIORITY 1 — Physical machines (do first, most valuable)

### P1.1 — Ubuntu MacBook amd64 (physical access)
**Machine:** Old Intel MacBook with Ubuntu Server
**Binary:** dsd-linux-amd64
**Why first:** Real amd64 hardware, real /proc, can run --physical stress tests
**Has:** systemd, AppArmor, timedatectl, physical NIC

```bash
# Basic verification
/tmp/dsd --version
/tmp/dsd health
/tmp/dsd health --json | python3 -m json.tool
/tmp/dsd health --plain
/tmp/dsd health --diff      # run twice — first creates baseline
/tmp/dsd net
/tmp/dsd services           # expect "no services configured" message
/tmp/dsd examples
echo "Exit: $?"

# Full stress suite — physical access available
DSD_BIN=/tmp/dsd sudo bash /tmp/stress.sh --physical all
```

**Specific things to check on 4GB RAM machine:**
- [ ] Memory collector shows WARN or CRIT (expected on 4GB)
- [ ] Exit code is 1 (WARN) not 0
- [ ] --diff creates ~/.dsd/baselines/ directory
- [ ] --since-deploy detects last service restart
- [ ] All 12 checks appear in --json output
- [ ] Clock shows synced (or graceful WARN if NTP is off)

**Status:** [x] PASS
**Notes:**
Session 1 (2026-05-08): Clock fix (Ubuntu 24.04 NTPOffsetUsec removed), render arch
violation (--plain/--json disagree), exit code, Systemd false WARN, insights:[] in JSON.
Session 2 (2026-05-08): CPU invalid status, zombie detection, disk Bfree→Bavail,
network collectors (NIC down, packet loss, DNS failure), DNS status promotion to CRIT,
FDLimits check name fix, stress suite stabilised (20 fixes total).
Machine: Ubuntu 24.04.4 LTS, kernel 6.8, 4 cores, 3.7GB RAM, kind k8s cluster running.
Result: 16/16 stress tests passing.

---

### P1.2 — Proxmox host (physical access)
**Machine:** Your Proxmox server
**Binary:** dsd-linux-amd64
**Why:** Real hypervisor environment, ZFS IO, Proxmox systemd units

```bash
# Basic verification
/tmp/dsd --version
/tmp/dsd health
/tmp/dsd health --json | python3 -m json.tool

# Proxmox-specific checks
/tmp/dsd health --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    print(f\"{c.get('name'):20} {c.get('status'):8} {c.get('value','')[:60]}\")
"

# Systemd should detect pvedaemon, pvestatd
/tmp/dsd health --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if 'Systemd' in c.get('name',''):
        print('Systemd check:', json.dumps(c, indent=2))
"
```

**Specific things to check:**
- [ ] IO collector detects ZFS devices (zd*, sda* depending on setup)
- [ ] Systemd collector: Available=true, lists pvedaemon/pvestatd
- [ ] Memory reflects host RAM (not a VM's limit)
- [ ] Network shows correct interfaces (not VM bridges as primary)
- [ ] MACPolicy: no crash (Proxmox may have SELinux disabled)

**Status:** [x] PASS
**Notes:**
2026-05-08: 12/12 stress tests passing. Machine: 8-core Intel, 32GB RAM,
119GB SSD (LVM), 1.8TB data disk, no ZFS. Proxmox VE hypervisor.
Fixes needed: stress suite self-calibration (CPU cores*2, swap 150% free RAM,
IO LVM device detection), run_stress.sh sudo check for root-only environments.
No collector bugs found — all 12 checks work correctly on Proxmox.

---

### P1.3 — Colima arm64 VM (your Mac)
**Machine:** Apple Silicon Mac via Colima
**Binary:** dsd-linux-arm64
**Why:** arm64 Linux validation, fast to test, safe to --physical

```bash
# Setup
colima start --cpu 4 --memory 4 --disk 20
colima cp dist/dsd-linux-arm64 /tmp/dsd
colima cp scripts/stress/stress.sh /tmp/stress.sh
colima ssh

# Inside Colima VM:
chmod +x /tmp/dsd /tmp/stress.sh
/tmp/dsd --version
/tmp/dsd health
/tmp/dsd health --json | python3 -m json.tool

# Colima uses Lima VM — no systemd, uses OpenRC
# Systemd collector MUST return Available=false cleanly (not crash)
/tmp/dsd health --json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if 'Systemd' in c.get('name',''):
        print(json.dumps(c, indent=2))
"

# Stress suite — safe to --physical in a VM
DSD_BIN=/tmp/dsd sudo bash /tmp/stress.sh --physical all
```

**Specific things to check:**
- [ ] arm64 binary executes without SIGILL
- [ ] Systemd: Available=false, status=OK (not crash, not CRIT)
- [ ] Clock: fallback path works (no timedatectl in Lima)
- [ ] All non-systemd checks work normally
- [ ] Stress suite completes all tests

**Status:** [x] PASS
**Notes:**
2026-05-08: 14/15 stress tests (IO skipped — no iostat in Lima VM).
Fixes: lima-cidata disk excluded, cloud-init services excluded,
container clock fix (inherit host). arm64 binary confirmed working.

---

## PRIORITY 2 — Docker amd64 (different distros, no physical needed)

Build first:
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -o dist/dsd-linux-amd64 ./cmd/dsd
```

Run all at once to get a quick overview:
```bash
for image in \
  "rockylinux:9" \
  "debian:12" \
  "amazonlinux:2023" \
  "alpine:3.19" \
  "opensuse/leap:15" \
  "archlinux:latest" \
  "ubuntu:20.04" \
  "fedora:40"
do
  echo ""
  echo "=== $image ==="
  docker run --rm \
    -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
    "$image" \
    sh -c "dsd health --plain 2>&1; echo EXIT:$?" 2>&1 \
  || echo "CONTAINER FAILED TO START"
done
```

---

### P2.1 — Rocky Linux 9 (Docker amd64)
**Image:** rockylinux:9
**Why critical:** RHEL clone, SELinux enforcing by default, chronyd not timedatectl

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  rockylinux:9 \
  sh -c "
    dsd --version
    dsd health --plain
    dsd health --json | python3 -m json.tool
    echo EXIT:\$?
  "
```

**Things that will be different from Ubuntu:**
- [ ] Clock: timedatectl fallback → chronyc tracking path fires
- [ ] MACPolicy: SELinux present (getenforce returns Permissive/Enforcing)
- [ ] No AppArmor
- [ ] All checks exit without crash

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.2 — Debian 12 (Docker amd64)
**Image:** debian:12
**Why:** Ubuntu base but diverges on NTP (uses chronyd by default)

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  debian:12 \
  sh -c "
    dsd health --plain
    dsd health --json | python3 -m json.tool
  "
```

**Things to check:**
- [ ] Clock collector: chronyc fallback (or graceful if neither present)
- [ ] No panic from any collector

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.3 — Amazon Linux 2023 (Docker amd64)
**Image:** amazonlinux:2023
**Why:** AWS default, high install base, uses chronyd, different device names on EC2

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  amazonlinux:2023 \
  sh -c "
    dsd health --plain
    dsd health --json | python3 -m json.tool
  "
```

**Things to check:**
- [ ] Clock: chronyd fallback
- [ ] IO: no crash when no physical disks visible in container
- [ ] MACPolicy: SELinux permissive (AL2023 default)

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.4 — Alpine 3.x (Docker amd64)
**Image:** alpine:3.19
**Why critical:** Most popular container base image. No systemd, no bash, no python3
**Warning:** Uses musl libc and ash shell not bash

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  alpine:3.19 \
  sh -c "
    dsd --version
    dsd health --plain
    echo EXIT:\$?
  "
```

**Things to check:**
- [ ] Binary executes (CGO_ENABLED=0 means musl is not an issue)
- [ ] Systemd: Available=false, status=OK
- [ ] Clock: no timedatectl, no chronyc — graceful degradation
- [ ] MACPolicy: no getenforce — graceful degradation
- [ ] No crash from missing commands

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.5 — SUSE Linux Enterprise 15 (Docker amd64)
**Image:** registry.suse.com/suse/sle15:latest
**Why:** Azure enterprise workloads, AppArmor, chronyd

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  registry.suse.com/suse/sle15:latest \
  sh -c "
    dsd health --plain
    dsd health --json | python3 -m json.tool
  "
```

**Things to check:**
- [ ] Clock: chronyc fallback works
- [ ] AppArmor: detected if enabled in container
- [ ] No crash

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.6 — Arch Linux (Docker amd64)
**Image:** archlinux:latest
**Why:** Popular with developers who will find DashDiag on HN

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  archlinux:latest \
  sh -c "
    dsd health --plain
    echo EXIT:\$?
  "
```

**Expected result:** Should just work. Arch is standard systemd Linux.
- [ ] All checks pass without crash
- [ ] Exit code 0, 1, or 2

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.7 — Ubuntu 20.04 (Docker amd64)
**Image:** ubuntu:20.04
**Why:** Still widely deployed, slightly different systemd version

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  ubuntu:20.04 \
  sh -c "
    dsd health --plain
    dsd health --json | python3 -m json.tool
  "
```

- [ ] All checks pass
- [ ] No version-specific crashes

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

### P2.8 — Flatcar Container Linux (Docker amd64)
**Image:** ghcr.io/flatcar/flatcar-sdk:latest
**Why critical:** Azure AKS default node OS, immutable, no systemd, no shell tools
**Warning:** Very different from standard Linux

```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  ghcr.io/flatcar/flatcar-sdk:latest \
  sh -c "
    dsd health --plain 2>&1
    echo EXIT:\$?
  "
```

**Expected:** Multiple collectors degrade gracefully (no systemd, no timedatectl)
- [ ] Binary executes (no crash on startup)
- [ ] Systemd: Available=false, status=OK
- [ ] Clock: graceful degradation
- [ ] MACPolicy: graceful degradation
- [ ] No panic from any collector

**Status:** [ ] PASS  [ ] FAIL  [ ] PARTIAL
**Notes:**

---

## PRIORITY 3 — Docker arm64 (Apple Silicon validation)

Build first:
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -o dist/dsd-linux-arm64 ./cmd/dsd
```

```bash
# Quick arm64 sweep
for image in \
  "ubuntu:22.04" \
  "rockylinux:9" \
  "alpine:3.19" \
  "debian:12"
do
  echo "=== arm64: $image ==="
  docker run --rm \
    --platform linux/arm64 \
    -v $(pwd)/dist/dsd-linux-arm64:/usr/local/bin/dsd \
    "$image" \
    sh -c "dsd health --plain 2>&1; echo EXIT:\$?" 2>&1
done
```

### P3.1 — Ubuntu 22.04 arm64
- [ ] PASS  [ ] FAIL

### P3.2 — Rocky Linux 9 arm64
- [ ] PASS  [ ] FAIL

### P3.3 — Alpine 3.x arm64
- [ ] PASS  [ ] FAIL

### P3.4 — Debian 12 arm64
- [ ] PASS  [ ] FAIL

---

## PRIORITY 4 — Container context (cgroup detection)

These validate that dsd correctly detects it is inside a container
and adjusts memory/CPU limits accordingly.

### P4.1 — Standard unprivileged container
```bash
docker run --rm \
  --memory=512m \
  --cpus=1.0 \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  ubuntu:22.04 \
  sh -c "
    apt-get update -qq && apt-get install -y -qq python3 2>/dev/null
    dsd health --json | python3 -c \"
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    if c.get('name') in ['CPU','Memory']:
        print(c.get('name'), ':', json.dumps(c, indent=2))
\"
  "
```

**Things to check:**
- [ ] Container banner printed: "Running inside a container"
- [ ] Memory: TotalGB reflects 512MB limit (not host RAM)
- [ ] CPU: NumCPU reflects 1.0 limit (not host cores)
- [ ] InContainer=true in JSON

**Status:** [ ] PASS  [ ] FAIL
**Notes:**

---

### P4.2 — Privileged container (sees host /proc)
```bash
docker run --rm \
  --privileged \
  --pid=host \
  --network=host \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  ubuntu:22.04 \
  sh -c "
    apt-get update -qq && apt-get install -y -qq python3 2>/dev/null
    dsd health --json | python3 -m json.tool
  "
```

**Things to check:**
- [ ] Memory: shows host RAM (not container limit)
- [ ] All 12 checks present and returning data
- [ ] Processes: can see host processes
- [ ] Network: can see host interfaces

**Status:** [ ] PASS  [ ] FAIL
**Notes:**

---

## PRIORITY 5 — Fedora and Oracle Linux (lower urgency)

### P5.1 — Fedora 40
```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  fedora:40 \
  sh -c "dsd health --plain; echo EXIT:\$?"
```
- [ ] PASS  [ ] FAIL  **Notes:**

### P5.2 — Oracle Linux 9
```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  oraclelinux:9 \
  sh -c "dsd health --plain; echo EXIT:\$?"
```
- [ ] PASS  [ ] FAIL  **Notes:**

### P5.3 — AlmaLinux 9
```bash
docker run --rm \
  -v $(pwd)/dist/dsd-linux-amd64:/usr/local/bin/dsd \
  almalinux:9 \
  sh -c "dsd health --plain; echo EXIT:\$?"
```
- [ ] PASS  [ ] FAIL  **Notes:**

---

## PRIORITY 6 — Deferred (do not block launch)

These do NOT block v0.1.0. Test after first public release.

### P6.1 — Talos Linux
Not testable via Docker/SSH. Requires a k8s cluster on Talos.
DashDiag on Talos runs as a privileged pod, not a shell command.
This is the dsd k8s command use case — deferred until that sprint.

### P6.2 — Raspberry Pi OS (arm64)
Real Pi hardware only. Not blocking launch.
Community will report issues if they arise.
Colima arm64 covers 95% of what Pi would test.

### P6.3 — Amazon Linux 2 (legacy)
EOL June 2026. Low priority. If user reports issue, fix then.

---

## KNOWN EXPECTED FAILURES (not bugs)

These behaviours are correct and expected — do not file bugs for them:

| Distro | Collector | Expected | Reason |
|---|---|---|---|
| Alpine | Systemd | Available=false, OK | No systemd |
| Flatcar | Systemd | Available=false, OK | No systemd |
| Colima/Lima VM | Systemd | Available=false, OK | Uses OpenRC |
| Any container | Systemd | Available=false, OK | No systemd in containers |
| Alpine | Clock | OffsetMs=-1 or graceful | No timedatectl/chronyc |
| Flatcar | Clock | Graceful degradation | No shell tools |
| macOS | Swap | SwapInPerSec=-1 | vm_stat no rate |
| macOS | Clock | OffsetMs=-1 | systemsetup no offset |
| Any container | IO | Empty or 0 values | No physical disks |

---

## BUG REPORT TEMPLATE

When a test fails, record it here before opening a GitHub issue:

```
Distro:       
Version:      
Binary arch:  amd64 / arm64
Command run:  
Exit code:    
Output:       

Expected:     
Actual:       

Collector:    (which check failed)
Error type:   panic / crash / wrong value / hang / wrong exit code
```

---

## PROGRESS TRACKER

| Priority | Test | Status | Date | Notes |
|---|---|---|---|---|
| P1.1 | Ubuntu MacBook amd64 | ✅ PASS | 2026-05-08 | 16/16 stress tests. 20 bugs fixed across 2 sessions. kind k8s running. |
| P1.2 | Proxmox host | ✅ PASS | 2026-05-08 | 12/12 stress tests. 8-core Intel, 32GB RAM, LVM storage. Stress suite self-calibration fixes. |
| P1.3 | Colima arm64 VM | ✅ PASS | 2026-05-08 | 14/15. arm64 confirmed. Lima fixes applied. |
| P2.1 | Rocky Linux 9 Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.2 | Debian 12 Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.3 | Amazon Linux 2023 Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.4 | Alpine 3.x Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.5 | SUSE 15 Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.6 | Arch Linux Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.7 | Ubuntu 20.04 Docker | ✅ PASS | 2026-05-08 | All checks OK. |
| P2.8 | Flatcar Docker | ⏳ Deferred | | Registry access denied. |
| P3.1 | Ubuntu 22.04 arm64 | ✅ PASS | 2026-05-08 | Native arm64. |
| P3.2 | Rocky Linux 9 arm64 | ✅ PASS | 2026-05-08 | via QEMU. |
| P3.3 | Alpine arm64 | ✅ PASS | 2026-05-08 | via QEMU. |
| P3.4 | Debian 12 arm64 | ✅ PASS | 2026-05-08 | via QEMU. |
| P4.1 | Container: unprivileged | ✅ PASS | 2026-05-08 | Memory WARN on 512MB expected. |
| P4.2 | Container: privileged | ✅ PASS | 2026-05-08 | All checks OK. |
| P5.1 | Fedora 40 | ⬜ Todo | | |
| P5.2 | Oracle Linux 9 | ⬜ Todo | | |
| P5.3 | AlmaLinux 9 | ⬜ Todo | | |
| P6.1 | Talos Linux | ⏳ Deferred | | Needs dsd k8s |
| P6.2 | Raspberry Pi OS | ⏳ Deferred | | Post-launch |
| P6.3 | Amazon Linux 2 | ⏳ Deferred | | EOL June 2026 |

---

## LAUNCH GATE

P1 and P2 must all PASS (or PARTIAL with documented known issues) before
announcing on Hacker News or any community. P3-P5 can be in progress.

P1.1 Ubuntu MacBook is the most critical — it tests the amd64 binary on
real Linux hardware with real /proc. If this fails, nothing else matters.
