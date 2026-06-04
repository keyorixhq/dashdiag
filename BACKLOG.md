# DashDiag Backlog

This file tracks all planned features not yet implemented.
Items in cmd/*.go files are also tagged `TODO(backlog)` inline.
Build order rule: **never build deep before fast is in production use.**

**Last updated: 2026-06-05 — btrfs I/O-error CRIT (branch btrfs-io-crit)**

---

## ✅ Recently Completed (June 5, 2026 — btrfs I/O-error severity, live-validated)

| Item | Notes |
|---|---|
| btrfs device read/write I/O errors → CRIT (corruption stays WARN) | `checkBtrfsVolume` in heuristics.go; branch `btrfs-io-crit`. Unit-tested + **live-validated on VM 214** (openSUSE Leap 16, kernel 6.12, btrfs-progs 6.14). |

**Live validation (Jun 5, VM 214 / 192.168.10.56):** deployed binary, injected faults
on fresh loop-backed btrfs volumes:
- **WARN path:** corrupted data region + buffered read → `corruption_errs=257`,
  read/write=0 → `dsd health` reported `WARN  btrfs /root/m1 has 257
  checksum/corruption error(s) — may be scrub-correctable`.
- **CRIT path:** `dm-error` table flip to fail all I/O, triggered writes, restored
  the device (counters persist) → `write_io_errs=8`, corruption=0 → `dsd health`
  reported `CRIT  btrfs /root/m2 has 8 device I/O error(s) — failing storage or cabling`.
- Existing degraded fixture `/mnt/btrfs-test` (missing device) stayed CRIT/DEGRADED.
- Testbed cleaned: loops/dm/imgs removed, fixture intact, binary removed.
Note: `btrfs scrub` csum errors do NOT bump `device stats` counters; only buffered
reads do — relevant when writing future btrfs tests.

## ✅ Recently Completed (Sessions 1–12, May 2026)

| Item | Session | Commit |
|---|---|---|
| `dsd services deep` — failed units, boot offenders, journal health | S1 | e192915 |
| `dsd health` active sessions (Spec H1) — `w -h`, root SSH CRIT, idle WARN | S1 | e192915 |
| SSH hardening via `sshd -T` — effective config, weak cipher/MAC/KEX | S2 | e192915 |
| User account audit — `/etc/shadow` empty passwords, password expiry, sticky bit | S2 | e192915 |
| `dsd cron` — daemon, failure scan, crontab quality, anacron staleness | S2 | e192915 |
| `dsd net dns` — resolv.conf audit, NM/resolved detection, live resolution test | S2 | e192915 |
| `dsd gpu` — AMD amdgpu sysfs + NVIDIA nouveau detection, `NoDriver` field | S3 | e192915 |
| `dsd health deep` cgroup v2 — slice CPU throttle, mem limits, OOM kills | S3 | e192915 |
| Journal persistence — `Storage=persistent`, `SyncIntervalSec=30s` on Legion | S3 | e192915 |
| LVM thin snapshot fix — `attr[9]='k'`, `findLVOrigin()` for blank data% | S3 | e192915 |
| Docker/Podman crash-loop fix — `RestartCount` at top level, not in `State` | S4 | 0b53299 |
| Docker wired into `dsd health` — gated on `DetectContainerSocket()` | S4 | 0b53299 |
| Container network backend detection (netavark vs CNI) + MTU mismatch check | S4 | 0b53299 |
| SELinux AVC grouping — `parseAVCGroups()`, boolean-first fix suggestion | S4 | 0b53299 |
| `dsd k8s` — JSON API, events, PVCs, workloads, OS-layer deep (Spec 23) | S5 | a248bd0 |
| `dsd proc <PID>` — smaps_rollup, FD map, socket conns, D-state (Spec 10) | S5 | a248bd0 |
| k3s v1.35.4 installed on Legion, wired into `dsd health` | S5 | infra |
| `dsd logs` — severity summary, crash file detection, log source (Spec 3) | S6 | 9822a57 |
| `dsd disk` — SMART (Linux+macOS), ZFS pools, I/O rate, physical drives model | S6 | 9822a57 |
| macOS SMART via `diskutil` — no external tools, `disk_darwin.go` | S6 | f1a8296 |
| `dsd kvm` — VM/network/pool/disk error diagnostics (Spec 15) | S7 | 2e05b0e |
| Package integrity in `dsd health deep` — `NewPackagesDeepCollector` wired (Spec 12) | S7 | aa14092 |
| NFS mount health in `dsd net deep` — non-blocking stale detection (Spec 11) | S7 | 3bef93a |
| BIND/named health in `dsd net deep` — config/zone/query/rndc checks (Spec 16) | S8 | d8351a9 |
| `dsd docker` exit code labels (7a), events (7e), plaintext secrets (7o) | S9 | b6bc7e0 |
| `dsd docker` root user detection (7m), socket mount detection (7n) | S9 | e39382f |
| `dsd docker` daemon health — version, storage driver, journal errors (7c) | S9 | 01401f0 |
| `dsd docker --deep` log driver + json-file size check (7b) | S9 | d8b99d7 |
| `dsd docker` IP forwarding check (7f), firewalld nftables backend (7k) | S9 | 6a5109f |
| `dsd health deep` cgroup scope labels — `system:k3s`, `container:<id>`, `k8s` (Spec 5) | S10 | 4ed11b8 |
| `dsd security` permission disambiguation — booleans, AppArmor groups, autorelabel, PAM (Spec 6) | S10 | 1e99158 |
| `dsd disk` LVM RAID/mirror health — degraded CRIT, resyncing INFO (Spec 21) | S10 | fbb170d |
| `dsd timeline` — unified incident timeline, dedup, journal+dmesg+load | S10 | 67ff3a7 |
| Correlation engine: Container OOM Cascade — kernel OOM + Podman die+137, 5-min window | S11 | eaec50a |
| Docker 7g: DNS trap — host resolv.conf loopback breaks container DNS | S11 | 57754c2 |
| Docker 7h: socket permission diagnosis (group membership, session refresh) | S11 | 57754c2 |
| Docker 7i: image architecture mismatch — arm64 image on amd64 host | S11 | 57754c2 |
| CVE: fix dnf severity parser — `Critical/Sec.` format, Important bucket bug | S11 | 8f04e08 |
| `dsd timeline` hint system — 18 kernel/systemd patterns, explain/inspect/fix/persist | S11 | 65dd20c |
| `dsd cve --oval-scan` — CVSS-scored OVAL package scan (RHEL 9 OVAL, 1,772 findings) | S11 | 247f6e5 |
| CVE: RHSA→CVE ID enrichment from subscribed RHEL `dnf updateinfo info` | S11 | 2638fda |
| CVE: subscription detection — not-root / not-registered / expired hints | S11 | 0c42bb6 |
| Fix: LVM `debian-vg` → `debian--vg` dm path — VG falsely inactive on Debian/Ubuntu | S12 | 1c7b64d |
| Fix: `Launchd ✅` row showing on all Linux — macOS-only, return nil on non-Darwin | S12 | 10dd73f |
| Fix: rsyslog hint now includes `zypper install rsyslog` for openSUSE | S12 | 79e0361 |
| Fix: NVIDIA install hint — Debian/Ubuntu first, RHEL/Fedora second | S12 | d83281c |
| Ubuntu/Debian OVAL parser — `oval_debian.go`, dpkg, priority→CVSS mapping | S12 | 1c8688e |
| SUSE/openSUSE OVAL parser — patch class, RPM, title severity, platform marker filter | S12 | ce85170 |
| btrfs device health — `btrfs_linux.go`, missing devices + I/O errors, DEGRADED CRIT | S12 | 0f16b76 |
| microk8s detection — `/snap/bin/microk8s kubectl` added to k8sDetectBin() | S12 | 7bd0a63 |
| btrfs DEGRADED now surfaces in `dsd health` heuristics (not just `dsd disk`) | S12 | a580f34 |
| Ubuntu 26.04 LTS (Resolute Raccoon) validation — all paths clean, 0 bugs | S12 | 2e6278a |
| Ubuntu LVM break test — `ubuntu-vg` dash-name fix confirmed, RAID1 DEGRADED detected | S12 | 7bd0a63 |

## ✅ Recently Completed (June 3, 2026 — Bug fixes + GTM unblocking)

| Item | Commit |
|---|---|
| Fix: journald `SyncIntervalSec` fix hint NixOS-aware → `services.journald.extraConfig` | 04fea7b |
| Fix: SMART false positive on virtual disks (QEMU/virtio/VMware) — gate via `isVirtualDisk()` | 04fea7b |
| NixOS 25.05 marketing assets re-captured clean at v0.6.0-38 | bb872b2 |
| Landing page built — `landing/index.html`, "DashDiag by Keyorix", animated terminal proof | 48e5826 |
| Landing page updated — real `install.sh` one-liner, removed "Coming soon" stubs | d2356fe |

## ✅ Recently Completed (June 3, 2026 — Session 2: CI green + repo public + PVE hardware validation)

| Item | Commit |
|---|---|
| fix(ci): `TestSELinuxAbsent` skip on Linux — CI green after 2 days red | — |
| All 7 Dependabot PRs merged (actions/checkout v6, actions/setup-go v6, action-gh-release v3, gopsutil 3.24.5, viper 1.21.0, cobra 1.10.2, go-ping 1.2.0) | — |
| Repo made public (`github.com/keyorixhq/dashdiag`) | — |
| v0.6.1 released — 4 binaries + `checksums.txt`, install one-liner verified working | — |
| `landing/` moved to separate repo `keyorixhq/dashdiag-landing` (Netlify deploy pending) | — |
| Branch protection ruleset deleted (solo founder, no contributors yet) | — |
| BUG-015–019 fixed and verified on live PVE hardware | 4f5e668 |

## ✅ Recently Completed (June 3, 2026 — Session 3: Sprint 1+2+3 + PVE deep)

| Item | Commit |
|---|---|
| BUG-020: SMART suppressed inside LXC containers — `NewDiskCollector(ctrCtx)` gate | d89324f |
| Ubuntu 24.04 LXC validation — clean run, 0 bugs, marketing assets captured | d89324f |
| AlmaLinux 9 LXC (CT 213, 192.168.10.8) added to test matrix — replaces Legion | 9724e23 |
| Spec 2: DNS resolver audit block for `dsd net deep` — resolved/NM/stub/DNSSEC/VPN | 9724e23 |
| Spec 2 verified: Ubuntu 24.04 (resolved path) + AlmaLinux 9 (NM fallback path) | 9724e23 |
| Spec 3: `dsd logs` — `--json` flag, `TopCritical` with source+age, `/var/log` fallback | 9a25127 |
| Fix: RFC3339 timestamp parse in `TopCritical` (`age_min` was always -1) | 9a25127 |
| Fix: `/var/log` fallback now sets `LogSource` even on clean system (observability) | 9a25127 |
| Fix: `--since` flag now reaches journalctl error/warning calls (`lookbackToSince`) | 2cf65f4 |
| Spec 24: `dsd pve` complete — node overview, task errors, per-VM backup audit, bridges, `--json` | ae9c4c4 |
| Spec 24 verified live on pve01: all 5 new sections, fast + deep + json | ae9c4c4 |
| CLAUDE.md updated — Legion retired, AlmaLinux LXC test matrix, v0.6.1 ref | cfdcb9d |

## ✅ Recently Completed (June 3, 2026 — Session 4: Sprint 4 items + PVE backup fix)

| Item | Commit |
|---|---|
| fix(pve): backup audit scans dump dir filenames — vzdump --all bulk task had no VMID | 21963e4 |
| pve01: full backup of all 9 VMs/CTs — `dsd pve` now shows ✅ healthy | 21963e4 |
| Spec H1: active session list verified already implemented — `w -h`, root SSH CRIT, idle WARN | 9476109 |
| Spec 7j: Docker Swarm INFO in daemon section — role (manager/worker) from ControlAvailable | b0d5c28 |
| CRI-O socket detection — `/var/run/crio/crio.sock` added to candidate list (OpenShift/RHEL k8s) | 9476109 |

## ✅ Recently Completed (June 3, 2026 — Session 5: Podman quadlets + marketing + capture)

| Item | Commit |
|---|---|
| Podman quadlet detection — `dsd docker` + `dsd health`, socket-active and socket-inactive | ac26dd8 |
| `podmanInstalled()` fallback — quadlets surface even when socket down | ac26dd8 |
| `PodmanQuadletsPresent()` fast file-existence gate — `dsd health` includes docker collector on quadlet hosts | ac26dd8 |
| Verified live: AlmaLinux 9 LXC, socket inactive, test-nginx.container → WARN in both commands | ac26dd8 |
| Marketing Story 10: Podman quadlet blind spot — socket assumption, social media angles, evidence | 032a488 |
| `dsd capture` preserves disk raw data — Disk/Drives/LVM/ZFS/IO raw JSON in fixture YAML | 4e0b943 |
| `dsd mock` replays disk raw data via model type map (DiskInfo/LVMInfo/ZFSInfo/IOInfo) | 4e0b943 |
| Backward compat: old fixtures without raw replay via text-only stub unchanged | 4e0b943 |

## ✅ Recently Completed (June 4, 2026 — Session 6: Spec 8 + containerd + btrfs VM)

| Item | Commit |
|---|---|
| Spec 8: `platform.Profile` distro normalization layer — Detect(), 10 distro cases, --debug print | 1fb1004 |
| `platform.Profile` wired into `cmd/health.go`, logs/docker/security collectors migrated | 1fb1004 |
| Live validation: PVE01 (ifupdown+AppArmor ✅), openSUSE 16 (SELinux enforcing ✅), AlmaLinux LXC (SELinux not-present in LXC ✅) | 1fb1004 |
| Standalone containerd health check (`dsd health` Containerd row) | ded30f4 |
| VM 214 (opensuse16-btrfs, 192.168.10.56): btrfs test node, healthy + DEGRADED fixtures | db1d0be |
| `dsd capture --cve / --timeline` + `dsd timeline --json` + cve stdout pollution fix | 83e17e6 |
| BTRFS-TEST-INFRA logged to backlog; BTRFS-HEALTH stale checkbox closed | 1575fcc |
| Spec 18: `dsd gpu` standalone — TDP, VRAM, clocks, utilization, Mesa, `--deep`, `--json` | cf9df4f |
| Intel HD 530 (i915) live tested on PVE01; no-GPU path verified on openSUSE VM | cf9df4f |
| AMD sysfs path covered by unit tests; field validation pending AMD hardware / Steam Deck | cf9df4f |
| V2 correlation rules: ruleEntropyTLSFailure, ruleIOSingleDeviceDegradation, ruleSysctlNotPersisted | 04638ec |
| models/sysctl.go: UptimeSeconds; CorrelateDeep +IOInfo +SysctlInfo params; 13 new tests | 04638ec |
| Live verified: AlmaLinux CT 213 — DIAGNOSIS "Sysctl Parameter Not Persisted" fires after reboot | 04638ec |

## ✅ Recently Completed (June 4, 2026 — Session 7: Spec close-out + BUG-021)

| Item | Commit |
|---|---|
| Spec 7d: Docker Compose v1/v2 detection — ComposePlugin/Standalone fields, daemon section output | 6058936 |
| `dsd tls` remote endpoint expiry — `--endpoint host:port`, `--endpoints-file`, `--json` | 6058936 |
| `collectors/tls_remote.go`: TLS dial + InsecureSkipVerify to read expired certs, 5s timeout | 6058936 |
| `ruleServiceMemoryLeak`: same process OOM-killed 2+ times → memory leak, not pressure | 6058936 |
| BUG-021 zombie subprocess: investigated, no offending code found — likely ps sampling artifact | eca49bf |
| `deploy.sh` gitignored (local internal tool) | a073503 |
| V2 backlog audit: kernel instability ✅, network deep ✅, CPU scheduling partial (steal+iowait done) | 3f46283 |

## ✅ Recently Completed (June 4, 2026 — Session 8: Security drift)

| Item | Commit |
|---|---|
| `dsd security --save-baseline`: SHA-256 hashes SSH configs, records known SUIDs/sudo/crons | 7e3fb6b |
| `dsd security --drift`: compares current state vs baseline; new SUID=CRIT, SSH/sudo/cron change=WARN | 7e3fb6b |
| `internal/baseline/security_baseline.go`: SecurityBaseline, SecurityDiff, atomic JSON store in `~/.dsd/` | 7e3fb6b |
| Fix: `findUnexpectedSUIDs` was dead code (never called) — added exported `ScanSUIDBinaries()` | 7e3fb6b |
| `ScanSUIDBinaries()` called on --save-baseline/--drift paths only (no impact to `dsd health` speed) | 7e3fb6b |
| Live verified: PVE01 + AlmaLinux 9 — baseline save ✅, no-drift ✅, SUID injection CRIT ✅, SSH change WARN ✅ | 7e3fb6b |

## ✅ Recently Completed (June 4, 2026 — Session 9: --json flag fix + flag design)

| Item | Commit |
|---|---|
| Fix: `--json` now works in `disk`, `docker`, `k8s`, `security`, `thermal`, `processes` | 17656b8 |
| Pattern: read global flag → pass to `DetectMode` as `outputFmt` → `ModeJSON` branch | 17656b8 |
| Deviation: reused `outputJSON()` helper from `disk.go` instead of repeating encoder boilerplate | 17656b8 |
| Deviation: `processes.go` used `*models.ProcessInfo` / `procInfo` not `ProcessesInfo` / `info` | 17656b8 |
| `FLAG_DESIGN.md`: full flag audit — current state, problems, target matrix, prioritised fix list | 5ae0da0 |

## ✅ Recently Completed (June 4, 2026 — Session 10: Flag unification)

| Item | Commit |
|---|---|
| `timeline --hours` → `--since` (duration string e.g. "1h", "24h"); reuses `parseSinceDuration()` | 0a464ca |
| `k8s --deep` wired to existing `NewK8sDeepCollector()` (OS-layer: kubelet, CNI, iptables, certs) | 0a464ca |
| `security --suid` → `--deep`; `--suid` kept as hidden backward-compat alias | 0a464ca |
| `--out` now redirects stdout for every command via `PersistentPreRun` in `root.go` | 0a464ca |
| `thermal --watch` (5s default, `--watch-interval` override) — clear-screen refresh loop | 0a464ca |
| `processes --watch` (same pattern) | 0a464ca |

## ✅ Recently Completed (June 4, 2026 — Session 11: PVE port dedup + run-queue collector)

| Item | Commit |
|---|---|
| Consolidated `{8006, 3128, 111}` PVE service-port set — exported `analysis.IsPVEServicePort` as single source | 68927d4 |
| Removed duplicate `isPVEServicePort` from `cmd/security.go`; both call sites now use `analysis.IsPVEServicePort` | 68927d4 |
| Moved `TestIsPVEServicePort` to `internal/analysis/heuristics_test.go` (follows the function); cmd renderer test kept | 68927d4 |
| Resolves CLAUDE.md "Known duplicate to clean up" note — flagged for next time PVE code was touched | 68927d4 |
| Corrected stale BACKLOG: `ruleServiceMemoryLeak` was already shipped (6058936) — correlation engine v1 complete | e404bc6 |
| Run-queue saturation collector — `procs_running`/`procs_blocked`/`ctxt` from `/proc/stat`, `CPU/RunQueue` heuristic + `ruleRunQueueSaturation` correlation | — |
| Run-queue live-verified on pve01 — WARN at 24 runnable/8 CPUs under load, silent when idle (load avg still 0.92, run queue caught it) | — |
| Proxmox-host validation pass on pve01 — SMART (SSD+HDD), LVM thin pool low-space WARN, disk I/O rate (deep), 20+ collectors | — |
| ZFS pool health validated on pve01 (Jun 4) — file-backed mirror: ONLINE caught, DEGRADED→`dsd health` CRIT with `zpool replace`/`online` hints, `--json` zfs_pools surface clean. Host left clean (pool destroyed) | — |
| **BUG found during ZFS test:** `dsd disk` + `dsd disk --json` exit 0 on a CRIT (DEGRADED pool); only `dsd health` returns exit 2. Standalone subcommands don't propagate worst-insight severity to exit code — breaks documented `0/1/2` convention the CI/CD story relies on. See BUG-022 below | — |

## 🐞 Known Bugs

### ~~BUG-022 — standalone subcommands don't set exit code from worst insight~~ ✅ FIXED (2026-06-04)

**Fix:** centralised in `cmd/exitcode.go` — `pendingExitCode` + `recordResultSeverity()`
runs collected results through the same `analysis.ApplyThresholds` heuristics `dsd health`
uses, records the worst level (CRIT→2, WARN→1), and `Execute()` applies it *after* the
command returns (so progress/`--out` defers still run — unlike a mid-command `os.Exit`).
Wired into `disk`, `security` (report + `--drift`), `docker`, `k8s`, and `cve` (all four
paths: `--all`, single-CVE, `--oval`, `--oval-scan`). Applies in JSON mode too. Standalone
exit codes now agree with `dsd health`. Unit tests in `cmd/exitcode_test.go`.
**Note uncovered during fix:** on macOS the docker collector reads the Linux
`/proc/.../ip_forward` path (absent on Darwin) and falsely reports "IP forwarding disabled"
as CRIT — so `dsd docker` *and* `dsd health` both exit 2 on a Mac with OrbStack. Pre-existing,
Linux-concept-on-macOS heuristic bug, unrelated to the exit-code wiring (the wiring correctly
propagated it). macOS support is low-priority (defer-until-demand); logged here, not fixed.

**Found:** 2026-06-04, during ZFS pool-health validation on pve01 (file-backed DEGRADED mirror).

**Symptom:** with a ZFS pool in DEGRADED state (a CRIT condition):
- `dsd health` → exit **2** ✅ (correct)
- `dsd disk` → exit **0** ❌ (renders ❌ DEGRADED + CRIT insight in output, but exit code is 0)
- `dsd disk --json` → exit **0** ❌

**Why it matters:** the documented Unix exit-code convention (`0 OK, 1 WARN, 2 CRIT`)
is a core part of the CI/CD positioning (MARKETING.md "CI/CD Integration — The SSH
Signal"). A pipeline gating on `dsd disk` would report success on a pool with
compromised data protection. The standalone subcommands render severity correctly
but don't propagate the worst insight's level to `os.Exit`.

**Scope:** likely affects all standalone subcommands that produce insights
(`disk`, `cve`, `tls`, `security`, etc.), not just `disk`. `health` already does it
right — the fix is to apply the same worst-insight→exit-code mapping in the
subcommand runners (or centralise it).

**Fix sketch:** wherever each subcommand finishes rendering, compute the max insight
level and set the process exit code (2 for any CRIT, 1 for any WARN, else 0), the
same way `health` does. Centralising in a shared helper avoids per-command drift.

**Priority:** Medium. Not a GTM blocker, but it undercuts a stated marketing claim,
so worth fixing before leaning on the CI/CD angle publicly. Verify with a DEGRADED
ZFS pool or any reliably-CRIT condition.

---

### ~~BUG-023 — AppArmor profile names mangled on Debian (JSON parsed as text)~~ ✅ FIXED (2026-06-04)

**Fix:** `internal/drilldown/kernelsec.go` now parses `aa-status --pretty-json` as real
JSON (`profiles` map → filter `mode == "complain"`) via `parseAAStatusJSON`, with a clean
sectioned plain-text fallback (`parseAAStatusText`) for releases without `--pretty-json`.
Names come back clean (`Xorg`, not `"Xorg":`). Unit tests in `kernelsec_test.go`.
Verify on the Debian 13 VM (VM 101).

**Found:** 2026-06-04, first `dsd health` run on a Debian 13 (Trixie) VM (VM 101, pve01).

**Symptom:** the KernelSec "complain mode" drilldown lists profile names with raw
JSON punctuation attached:
```
"Xorg":    "complain",
"plasmashell":    "complain",
"sbuild":    "complain",
```
instead of clean names (`Xorg`, `plasmashell`, `sbuild`).

**Root cause:** `internal/drilldown/kernelsec.go` `policiesLinux()` runs
`aa-status --pretty-json` (JSON), then parses the output **line-by-line looking for
the substring `complain`** and takes the whole trimmed line as the profile name. On
JSON output that line is `"Xorg": "complain",` — so the JSON quotes/colon/comma get
captured verbatim. The plain-text fallback (`aa-status` with no flag) would parse
cleaner with this line logic, but `--pretty-json` succeeds on Debian so the fallback
never runs.

**Why it surfaced on Debian and not RHEL/Ubuntu:** RHEL family uses SELinux (this
path isn't hit). Ubuntu has AppArmor but the prior validation evidently didn't
exercise the complain-mode drilldown with a profile set like Debian's. Debian 13
ships 106 profiles, 23 in complain mode (desktop profiles like Xorg/plasmashell are
part of Debian's default apparmor-profiles package — not a sign of a non-minimal
image).

**Fix sketch:** either (a) parse the `--pretty-json` output as actual JSON
(`profiles` is a map of name→mode; filter `mode == "complain"`), or (b) drop the
`--pretty-json` flag and parse the plain `aa-status` text, which is already cleanly
sectioned ("23 profiles are in complain mode." followed by one indented name per
line — track which section you're in). Option (a) is more robust. Cosmetic severity
(the count and detection are correct; only the displayed names are mangled).

**Priority:** Low-medium. Cosmetic but visibly wrong in output a user would see.
Verify on the Debian 13 VM (VM 101).

---

### ~~Debian-family note — ruleSysctlNotPersisted false positive on stock defaults~~ ✅ FIXED (2026-06-04)

The `ruleSysctlNotPersisted` correlation rule fired on the fresh Debian VM:
"system rebooted 3 minutes ago and sysctl parameters are still at non-recommended
values — the previous fix was applied with sysctl -w but not written." But nothing
was applied — these are the **stock defaults** (`vm.swappiness=60`).

**Fix (`internal/analysis/correlate.go`):** two changes. (1) The summary is now
*conditional* — "if a fix was applied last boot with `sysctl -w` it did not survive the
reboot" — instead of asserting a past action that can't be proven from current state
(a lost `sysctl -w` reverts to the same default a never-touched box shows). (2) Added
`sysctlAllAtStockDefaults()`: the rule is suppressed when the flagged values are at
version-stable kernel defaults (swappiness=60, dirty_ratio=20) — the "nobody tuned this"
signal. Deliberately excludes version-dependent defaults (somaxconn, tcp_tw_reuse) where a
"still at default" test would misfire. The underlying Sysctl WARN is untouched and still
fires. A fully reliable verdict still needs the history-aware v2 (compare vs a prior
snapshot). Regression test: `TestSysctlNotPersistedDoesNotFireOnStockDefaults`.

---

## 🚨 GTM Blockers (revenue-blocking, do these first)

> **Validation method:** `docs/GTM_VALIDATION.md` (instrumented landing page —
> single email field, UTM-tagged links, fake-door priced button off the capture
> path). **Decisions:** `docs/adr/0002-monetisation-paths-and-landing-page-validation.md`
> and `docs/adr/0001-persistence-is-the-platform-foundation.md`.

| Item | Status | Notes |
|---|---|---|
| Register `dashdiag.sh` | **PENDING** | ~$35/yr, confirmed available at Namecheap. Card ready. |
| Make repo public | **✅ DONE** | Public at `github.com/keyorixhq/dashdiag` (June 3) |
| Create GitHub release | **✅ DONE** | v0.6.1 published — 4 binaries + `checksums.txt`, install one-liner verified |
| Wire Formspree/Tally email capture | **PENDING** | Search `STUB` in `landing/index.html` — one-line swap |
| Deploy landing page | **PENDING** | Static single file, no build step. Cloudflare Pages or GitHub Pages. DNS swap after domain. |

---

## Candidate features (gated on a real request — do NOT build speculatively)

Recorded so they aren't lost; explicitly NOT committed work. Each is demand-unvalidated
per COMPANY_PRINCIPLES.md Principle 3 — build only when a real user/buyer asks.

### OpenStack guest checks — cloud-init health + metadata reachability (candidate — gated on a real request)

Anticipated: some clients will run `dsd` on OpenStack instances. An OpenStack instance is
a KVM guest (Nova → KVM/QEMU/libvirt), so the baseline is **already covered** by the
validated KVM-guest paths (CPU steal, run-queue collector, virtio detection, SMART
suppression on virtual disks). Nothing new needed for the generic case.

The only OpenStack-specific guest-side candidates:
- **cloud-init health (build this first if built at all).** `cloud-init status` →
  completed vs error/degraded. Catches the common "instance booted but never configured"
  failure. **Generic to every cloud-init platform** (AWS/GCP/Debian VM 101), not
  OpenStack-only — so it pays off broadly. Testable on existing KVM VMs; no OpenStack
  cloud required to develop or validate it.
- **Metadata service reachability** (169.254.169.254) — cheap guest-side check; modest value.
- virtio/paravirtual driver detection — generic KVM, largely already present.

**Out of scope:** Nova/Neutron/Cinder control plane, hypervisor-host state, OpenStack API —
that would make `dsd` an OpenStack monitoring product, not a guest diagnostician. Diagnostician
on the node, never the control plane.

**Status: anticipated, demand-unvalidated (Principle 3). Plan recorded, build deferred** —
do not build until a real OpenStack user asks. Full rationale: ADR-0002 Decision 6
"Candidate environment — OpenStack".

---

### Major-cloud guests (AWS / GCP / Oracle) + ARM64 servers (Graviton/Ampere) — validation plan (gated)

Anticipated: clients will run `dsd` on the big clouds. Two strands, different urgency.

**Strand A — cloud guest validation (deferred, same as OpenStack).** AWS EC2 (Nitro/KVM),
GCE (KVM), Oracle Compute (KVM) are all KVM-family Linux guests → the x86 baseline is
**already covered** by validated KVM-guest paths. The cloud-specific surface is identical
to the OpenStack entry above: **cloud-init health** (the one worth building, generic to all
of them) + per-cloud **metadata-service reachability** (each cloud has its own endpoint:
AWS/GCP `169.254.169.254`, with cloud-specific quirks like GCP's `Metadata-Flavor` header).
Out of scope: each cloud's control plane / API (that's a cloud-monitoring product, not a
guest diagnostician). **Status: demand-unvalidated (Principle 3), build deferred** — gated
on a real client on that cloud. Not urgent: an x86 cloud guest is just a KVM guest.

**Strand B — ARM64 *server* validation (the real near-term gap, NOT a cloud-control-plane
thing).** `dsd` ships an arm64 binary but, until Jun 4, had only ever run on x86 Linux. The
arch — not the provider — is the gap: arm64 has different `/proc`/`/sys`/SMART/sensor/CPU-
feature behaviour. **Preliminary arm64-Linux smoke test DONE (Jun 4, OrbStack native
aarch64):** binary runs, core /proc collectors parse, arch detection + exit codes correct
(see ARM64 testbed entry). That closes the highest-probability risk cheaply. **Still open:**
arm64 *hardware* paths (SMART, thermal, IPMI, GPU) and real ARM *server* kernels — none of
which a container exposes. Cheapest way to close without AWS: an **Oracle Cloud always-free
Ampere instance** (a real arm64 server VM, $0) or a Raspberry Pi. Graviton specifically is
not required to validate the architecture — Ampere/Pi exercise the same aarch64 paths.
**Priority:** the arm64 *server* run is worth doing relatively soon (it's the one arch we
ship blind on the hardware paths); the cloud guests (Strand A) stay demand-gated. Both still
behind the GTM blockers (domain + two messages).

---

### `--export` / CMDB inventory feed (candidate — gated on a real request)

DashDiag already collects hardware inventory (disk model/serial/capacity, CPU, DIMM
layout, installed software, etc.) as a byproduct of diagnosis — on every run, on every
box — then discards it. An export flag could emit this already-collected inventory in a
format an external CMDB can ingest.

- **Additive integration, not a CMDB product.** Feeds the *technical-facts* columns of a
  CMDB record only (model / serial / specs / installed software). Does NOT supply the
  administrative layer (owner, asset tag, purchase/warranty date, physical location,
  licence entitlements) — none of that is visible from the box. It populates part of a
  record; the CMDB still sources the admin layer elsewhere.
- **Cheap.** The data is already collected — a serialisation/format question, not new
  collection. Consistent with the `--json`-as-platform-API direction.
- **Why it matters.** CMDBs are chronically starved of fresh, accurate data because they
  rely on manual entry (exactly why Yuri built his Access tool). A tool already running on
  every box emitting current ground-truth hardware facts solves the CMDB's worst problem:
  staleness. Strengthens the provider/infra-team value prop (ADR-0002 Decision 6).
- **Origin:** co-founder Yuri (ex-Microsoft IT manager, CIS subsidiaries; built a homemade
  MS Access CMDB because even Microsoft's inventory tooling was a nightmare). Spotted the
  connection from a DashDiag demo.
- **Status: demand-unvalidated (Principle 3).** A smart connection from a co-founder is a
  hypothesis, not a confirmed request — and a homemade-tool builder is a harder sell, not
  an easier one. **Do not build until a real user/buyer asks.**

---

## Container Runtimes

### ~~[CONTAINER-CRIO] Add CRI-O socket detection to dsd docker collector~~ ✅ DONE (June 3, commit 9476109)

**Current state:** `dsd docker` auto-detects Docker and Podman sockets. CRI-O is not detected.
CRI-O is the default runtime on OpenShift and RHEL-based Kubernetes clusters.

**What to add:** One line in `collectors/docker.go` socket candidate list:
```go
{"/var/run/crio/crio.sock", "crio"},
```

**Priority:** Low-medium. Quick win (~1h). Do before first OpenShift/RHEL k8s customer.

---

### ~~[CONTAINER-PODMAN-SYSTEMD] Detect systemd-managed Podman containers (quadlets)~~ ✅ DONE (June 3, commit ac26dd8)

**Current state:** Podman socket detection works. But RHEL admins increasingly use Podman
via systemd unit files (`podman generate systemd`, quadlets in `/etc/containers/systemd/`).
These containers are not visible via the Podman socket — they're managed as systemd services.

**What to add:**
- Scan `/etc/containers/systemd/` and `~/.config/containers/systemd/` for `.container` / `.pod` files
- Cross-reference with `systemctl list-units --type=service` for units named `podman-*`
- Surface stopped/failed quadlet containers as WARN in `dsd docker` output

**Priority:** Medium. Relevant on RHEL 9/10, Rocky, AlmaLinux. ~4h.

---

### ~~[CONTAINER-CONTAINERD] Standalone containerd health check~~ ✅ DONE (June 4, commit ded30f4)

**Completed June 4:** Socket detection, service state via systemctl, version + namespace/
container counts via `ctr`/`containerd-ctr` (multi-binary probe handles openSUSE, Debian,
k3s). Gate: `ContainerdAvailable() && !K8sAvailable()` — no double-counting with `dsd k8s`.
Inline: `v1.7.27  default:1`. CRIT when socket present but service non-active (crashed).
Verified live on VM 214 (openSUSE Leap 16, containerd 1.7.27) with alpine container.

---

## Tooling

### ~~[CAPTURE] dsd capture — extend to support dsd disk, dsd cve, dsd timeline~~ ✅ DONE (disk: June 3 commit 4e0b943; cve+timeline: June 4 commit 83e17e6)

**Completed June 4:** `dsd capture --cve <file>` / `--timeline <file>` fold standalone
report JSON into the fixture. `dsd mock` replays both sections via real print functions,
output byte-identical to a live run. `dsd timeline --json` added as prerequisite.
Strict validation (`DisallowUnknownFields`) rejects cross-fed/garbage files at capture time.
Bonus fix: `dsd cve --all --json` stdout banner pollution (broke piping) fixed in same commit.
9 unit tests in `cmd/capture_sections_test.go`.

---

### ~~[BTRFS-HEALTH] Wire btrfs volume health into dsd health~~ ✅ DONE (Session 12, commit a580f34)

**Verified June 3:** `checkDisk()` → `checkDiskExtras()` walks `disk.BtrfsVolumes` —
`MissingDevs > 0` emits CRIT (DEGRADED, data at risk), `Status == "errors"` emits WARN
(device I/O / corruption). Runs in the health heuristics dispatch path
(`heuristics.go:161,163` → `checkDisk` → `checkDiskExtras` → btrfs loop at L715),
so it surfaces in `dsd health`, not just `dsd disk`. Backlog checkbox was stale.

---

### [GPU-AMD-VALIDATION] Live AMD amdgpu path validation for dsd gpu

**Current state (June 4, commit cf9df4f):** `dsd gpu` AMD sysfs path (hwmon power1_cap*,
pp_dpm_sclk, mem_info_vram_*, gpu_busy_percent, temp2/3_input) was written to spec and
covered by unit tests against documented sysfs formats. It has NOT been exercised against
live amdgpu hardware — the test matrix only has Intel i915 (PVE01) and GPU-less VMs.

**What to validate when AMD hardware is available (Steam Deck or AMD workstation):**
- `dsd gpu` shows correct TDP current/limit/max (compare against MangoHud or radeontop)
- Junction temperature matches `sensors` amdgpu hwmon output
- Clock speed parsing of `pp_dpm_sclk` `*`-marked line is correct
- VRAM used/total matches `radeontop` or `/sys/class/drm/card*/device/mem_info_*`
- GPU utilization 1s sample matches MangoHud GPU% reading
- `dsd gpu --deep` shows PowerDPMLevel correctly (`auto`, `low`, `high`)
- Throttling flag fires when `power1_input` ≥ 95% of `power1_cap` (run gpu-burn to trigger)
- IsAPU=true on Steam Deck (VRAM < 2GB + GTT pool present)

**Priority:** Medium — blocks Steam Deck field validation of Spec 18.
**Blocked on:** Access to AMD GPU hardware (Steam Deck, Radeon workstation, or AMD laptop).
**Estimated:** 1–2h once hardware is available (deploy binary, compare against MangoHud).

---

### [BTRFS-TEST-INFRA] Proper reproducible btrfs RAID1 DEGRADED test on VM 214

**Current state (June 4):** VM 214 (`opensuse16-btrfs`, 192.168.10.56) has a single-device
btrfs volume at `/mnt/btrfs-test`. DEGRADED path was validated manually using a loop
device + RAID1 conversion + `losetup -d`. Setup is ephemeral (loop file in `/tmp`,
dies on reboot) and requires manual steps each session.

**What to build:**
- Add a second persistent virtual disk to VM 214 via `qm set 214 --scsi2 local-lvm:4`
- Format both `/dev/sdb` + `/dev/sdc` as btrfs RAID1 at provision time
- Update `/etc/fstab` to mount the RAID1 array
- DEGRADED trigger: `qm set 214 --delete scsi2` from PVE → VM boots with genuine
  missing device, btrfs auto-mounts degraded, `dsd health` fires CRIT — no manual setup
- Device error path: `dd if=/dev/urandom of=/dev/sdc bs=4K count=1000` before detach
  to seed non-zero `btrfs device stats` counters, validating the WARN path too

**Why deferred:** Collector logic already validated and fixtures captured. Only matters
when test reproducibility is needed for contributors or CI. No code change required.

**Priority:** Low. Test infra only. ~30min when ready.
**Blocked on:** Nothing — VM 214 is running, just needs a second scsi disk added.

---

**Gap found:** During the Session 11 LVM break test (4 simultaneous failures), we cleaned
up before running `dsd capture`. The health fixture is now hand-crafted. The `dsd disk`
detail was never captured.

**What to build:**
- `dsd capture --disk` — reads `dsd disk --json` from stdin, appends disk insights into the fixture
- OR: `dsd capture --all` — runs all collectors internally, writes a multi-section fixture
- The fixture format already handles arbitrary checks — just need ingestion paths for other commands

**Priority:** Medium. Do before first public demo so every session produces a replayable artifact.

**Estimated:** ~0.5d

---

## Commands

### ~~[GAP-SPEC] dsd services deep~~ ✅ DONE (Session 1)
Failed units + last journal lines, boot offenders, daemon-reload detection, masked units.
Collector: `internal/collectors/services_deep_linux.go`. Commit: e192915.

---

### ~~[GAP-SPEC] dsd health — Active Session List (Spec H1)~~ ✅ DONE (Session 1)
`w -h` parser, root SSH CRIT, idle >8h WARN, concurrent session count, remote IP INFO.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd net deep — DNS Resolver Audit~~ ✅ DONE (Session 2)
resolv.conf audit, NM/resolved/static detection, live resolution test.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd cron~~ ✅ DONE (Session 2)
crond/anacron daemon detection, 24h failure scan, crontab quality, anacron staleness.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SSH hardening + user account audit~~ ✅ DONE (Session 2)
`sshd -T` effective config, weak cipher/MAC/KEX, empty passwords, expiry, sticky bit.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd gpu~~ ✅ DONE (Session 3)
AMD amdgpu sysfs metrics + NVIDIA nouveau detection with per-distro install hints.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd health deep — cgroup v2~~ ✅ DONE (Session 3)
Slice CPU throttle %, memory current/limit/%, OOM kills. Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SELinux AVC grouping~~ ✅ DONE (Session 4)
`parseAVCGroups()` with boolean-first fix order. Commit: 0b53299.

---

### ~~dsd docker — crash-loop fix + health wiring~~ ✅ DONE (Session 4)
`RestartCount` fixed, netavark/CNI detection, MTU mismatch WARN. Commit: 0b53299.

---

### ~~[GAP-SPEC] dsd k8s — Kubernetes Cluster + OS-Layer Diagnosis~~ ✅ DONE (Session 5)
Full JSON API rewrite covering Spec 23 + addendums 23a–23g.
- Node conditions, Warning events with flannel subnet.env detection
- PVC health, Deployments/StatefulSets, stuck Terminating pods
- OS-layer deep: kubelet, CNI bins, IP forwarding, KUBE-FORWARD, cert expiry
- Wired into `dsd health` via `K8sAvailable()`; absolute path for sudo
- Live: `FailedCreatePodSandBox×3` + flannel subnet.env CRIT with fix hint
Commit: a248bd0.

---

### ~~[GAP-SPEC] dsd proc \<PID\>~~ ✅ DONE (Session 5)
`/proc`-only inspector: smaps_rollup, FD map, socket connections, D-state guide.
Live: k3s — 322 FDs, 518 MB Private_Dirty, 244 sockets. Commit: a248bd0.

---

### ~~[GAP-SPEC] dsd logs — Cross-Source Triage Improvements~~ ✅ DONE (Session 6)
**Spec 3. Commits: 9822a57.**
- Severity summary: ERROR + WARNING counts from `journalctl` in last hour
- Top 5 deduplicated error messages (`×count` format)
- Crash file detection: `/var/crash/`, `/var/lib/systemd/coredump/`, `/sys/fs/pstore/`
  — files from last 30 days with size + age
- Log source detection: `journald` / `journald+syslog` / `syslog`
- Heuristics: crash dumps WARN; ErrorCount >50 WARN; >10 INFO
- `checkJournalHealthInsights` split: `checkJournalConfig` + `checkJournalActivity`
- Renderer split into 6 sub-functions (all ≤90 stmts)
- Live RHEL 10.1: 38k errors (SELinux/Podman BPF flood), `journald+syslog` detected

---

### ~~[GAP-SPEC] dsd disk — Standalone Disk + I/O Diagnostics~~ ✅ DONE (Session 6)
**Spec 4 + 4a + 4b. Commits: 9822a57 + f1a8296.**

**Linux (`disk_linux.go`):**
- Physical drive enumeration from `/proc/partitions` → `collectPhysicalDrives()`
- SMART via `smartctl -H -A`: health, wear%, spare%, temp, media errors
  NVMe parser: handles `"Percentage Used: 0%"` / `"Temperature: 51 Celsius"` format
- ZFS gate: zero overhead (`zpool` binary + `/proc/mounts` zfs entry)
  `collectZFSPools`: list with size/cap/frag/health; per-pool vdev errors + scrub age
- I/O rate (`--deep` only): `/proc/diskstats` delta 1s sample

**macOS (`disk_darwin.go`):**
- Physical drive enumeration via `diskutil list` (ships with every macOS)
- Per-drive: model, size, type (Apple Fabric→NVMe, SATA→SSD, rotational→HDD)
- SMART health from `diskutil info` → `SMART Status: Verified` — **no smartctl needed**
- APFS container label instead of "not mounted" for Apple internal disks
- Live: `disk0  500GB  NVMe  APFS container  [APPLE SSD AP0512R]  ✅ SMART: PASSED`

**Model:** `DriveType`, `SMARTInfo`, `PhysicalDrive`, `DiskIOStat`; `ZFSPool` from `models/zfs.go`
**Heuristics:** `checkDiskExtras` — SMART FAIL CRIT, wear ≥90% WARN, ZFS DEGRADED CRIT,
  vdev errors WARN, scrub age INFO
**Renderer split:** `printDiskDrives`, `printDiskZFS`, `printDiskFilesystems`, `printDiskIO`

---

### ~~[GAP-SPEC] dsd net deep — NFS Mount Health~~ ✅ DONE (Session 7)
**Spec 11. Commit: 3bef93a.**
Non-blocking stale detection: `syscall.Statfs` in goroutine + 2s timeout — no D-state hang.
Server reachability via TCP probe (port 111/2049, no ICMP required).
Mount option audit: soft-without-timeo, nolock, vers=2/3, `_netdev` missing from fstab.
rpcbind status + `/proc/net/rpc/nfs` stats.
`nfs_linux.go` + `nfs_notlinux.go` stub. `models/nfs.go`: `NFSMount` + `NFSInfo`.
Live: `STALE (timeout after 2s)` fires in 2.36s — no hang validated.

---

### ~~[GAP-SPEC] dsd net deep — BIND/named server health~~ ✅ DONE (Session 8)
**Spec 16. Commit: d8351a9.**
Gate: `pgrep named` or `systemctl is-active named` — section absent when BIND not running.
Config file auto-detected: `/etc/named.conf` (RHEL) or `/etc/bind/named.conf` (Debian).
`named-checkconf` validation. `include` directives followed (depth-limited to 5).
Zone file parsing: skips `hint`/`forward`/`stub` types, resolves relative paths.
`named-checkzone` per primary zone (3s timeout each, cap 20 zones).
Port 53 check: TCP + UDP separately via `ss -tulpn`.
Live DNS query test: `dig @127.0.0.1 localhost A +time=2 +tries=1`.
`rndc status`: version, uptime, query count (graceful if not configured).
Heuristics: service inactive CRIT, port 53 WARN, config error CRIT, zone failures CRIT.
Live BIND 9.18.33: 5 zones pass, hint zone excluded, includes followed.

---

### ~~[GAP-SPEC] dsd pve — Proxmox VE Node Diagnostics~~ ✅ DONE (June 3, commit ae9c4c4)
**Sprint 9. Full spec in DashDiag_Gap_Specs.md § Spec 24.**
Fast: node overview, VM/CT status, storage pool health, recent task errors, cluster quorum.
Deep: PVEPerf benchmark, VM resource over-commitment, backup audit, network bridge health.
Verified live on pve01 (Debian 13 / PVE 9.1.1): all 5 sections, fast + deep + `--json`.
Backup-audit dump-dir filename fix in commit 21963e4.

---

### ~~[GAP-SPEC] dsd kvm — KVM/libvirt diagnostics~~ ✅ DONE (Session 7)
**Spec 15. Commit: 2e05b0e.**
Gate: `virsh version --daemon` (libvirtd reachable). `KVMAvailable()` exported for `dsd health`.
VM status: running/paused/shut-off/crashed via `virsh dominfo`. `domblkerror` for disk I/O errors.
`/var/log/libvirt/qemu/<name>.log` scanned for last error line.
Network: `virsh net-list --all` + virbr* bridge link state via `ip link show`.
Storage pools: `virsh pool-info` capacity/available → `UsedPct`.
Heuristics: crashed CRIT, paused WARN, down+autostart WARN, I/O errors CRIT,
  inactive networks WARN, pools >85% WARN.
Wired into `dsd health` via `KVMAvailable()`. `KVMVMState` typed constants.
`domblkerror` false positive fix: `"No errors found"` correctly excluded.
Live: libvirt 11.10.0 / QEMU 10.1.0, test-vm running, virbr0 up.

---

### ~~[GAP-SPEC] Package dependency integrity~~ ✅ DONE (Session 7)
**Spec 12. Commit: aa14092.**
`NewPackagesDeepCollector` was built but never wired — now included automatically in
`dsd health deep` (no `--packages` flag needed). Fast path unchanged.
Covers: `dnf check`, `dpkg --audit`, missing `.so` lib detection on canary binaries.
Live RHEL 10.1: shows 7 critical security updates, clean integrity (no broken deps).

---

## Collectors (dsd health additions)

### ~~CVE exposure check~~ ✅ DONE (June 4)
Shipped as `dsd health --cve` (CVEHealthCollector): folds the package manager's
pending security advisories into health as live WARN/CRIT insights.
WARN CVSS ≥ 7.0 (Important), CRIT CVSS ≥ 9.0 (Critical) or CISA KEV match.
CISA KEV integration (`internal/cvedata/kev.go`): a local sidecar catalog
(`/var/lib/dsd/kev/`) escalates actively-exploited CVEs to CRIT in both
`dsd cve` and `dsd health --cve`. No cloud registration. Live-verified on
AlmaLinux CT 213 (94 real advisories, KEV escalation + severity mapping).

---

## Strategic Discussions Required

### [DISCUSS] Team mode — how should it work?
Before building any paid tier, answer sharing model, team workspace, fleet view,
identity/auth, monetisation boundary, privacy/trust questions.

### [DISCUSS] Pricing strategy
Anchor price, per-host fee, open source core + paid cloud model.

### --share flag
Upload to dashdiag.sh and return shareable URL. Requires dashdiag.sh backend.

### --badge flag
shields.io-compatible badge endpoint. Requires dashdiag.sh backend.

### Team workspace MVP (paid tier)
Shared snapshot history across a team.
Requires dashdiag.sh backend, auth, billing. Estimated scope: ~10d.

### ~~dsd policy (CI gate)~~ ✅ DONE

---

## Polish

### [LOW] External bug reports — upstream kernel / distro issues
**ELAN touchpad dead on Lenovo Legion 5 15ACH6H — kernel i2c_designware**
File: `bug-reports/elan-touchpad-i2c-lenovo-legion.md`
Root cause: ACPI DSDT 400kHz vs driver 100kHz mismatch.

### CIS/STIG compliance checks
Enterprise-only. After core health stable + paying customers.
Estimated scope: ~2 weeks.

### [TESTBED] openSUSE Leap 16 + SLES validation
zypper, btrfs, YaST, AppArmor enforcing.

---

## [STRATEGIC] V2 Diagnostic Engine

Do NOT start before first paying customer is acquired.

### ~~[V2-CORRELATION] Symptom correlation engine~~ ✅ DONE (v1 complete — all 8 rules shipped)
**v0 SHIPPED (commit dc729d4)** — 4 hardcoded rules + GPU context rule live.
**June 4 (commit 04638ec)** — 3 more rules shipped:
- ✅ Entropy low + TLS signals → crypto bootstrapping failure (`ruleEntropyTLSFailure`)
- ✅ IO CRIT on one device + other OK → single drive degradation (`ruleIOSingleDeviceDegradation`)
- ✅ Sysctl drift + recent reboot → parameter not persisted (`ruleSysctlNotPersisted`)
**June 4 (commit 6058936)** — final v1 rule shipped:
- ✅ Multiple OOM kills + same service → memory leak in specific service (`ruleServiceMemoryLeak`)
  Wired into `CorrelateDeep` → `dsd health --deep`; 5 unit tests in `correlate_test.go`.
Correlation engine v1 is complete. Next batch (v2, history-aware across snapshots) deferred post-customer.

### ~~[V2-COLLECTOR] Kernel instability extensions~~ ✅ DONE (shipped across multiple sessions)

Soft lockups: `logs_linux.go` lines 181–185, `LogsInfo.SoftLockups`, heuristics `1720–1724`.
Hard lockups: `logs_linux.go` lines 186–189, `LogsInfo.HardLockups`, heuristics `1726–1730`.
Kernel panics: `logs_linux.go` `countPstorePanics()` + pstore scan, `LogsInfo.KernelPanics`,
heuristics `1732–1735`. MCE hints: `timeline_hints.go` lines 136–144.
All surface as CRIT insights in `dsd health` and `dsd timeline`.

---

### ~~[V2-COLLECTOR] Network deep diagnostics~~ ✅ DONE (shipped across multiple sessions)

TCP retransmissions: `network_deep.go` reads `TCPSynRetrans`, `ListenOverflows`,
`TCPRetransFail` from `/proc/net/netstat`. `NetworkInfo.SynRetransCount`,
`ListenOverflows`, `RetransFailCount`. Heuristics: lines 1157–1179.
Conntrack: reads `/proc/sys/net/netfilter/nf_conntrack_{count,max}`.
`NetworkInfo.ConntrackUsedPct`. CRIT when full. All in `dsd net deep` + `dsd health`.

---

### ~~[V2-COLLECTOR] CPU scheduling pathology~~ ✅ DONE (steal + iowait + run queue)

**Done:** `cpu.go` two-sample `/proc/stat` for `StealPct` and `IOwaitPct`.
`CPUInfo.StealPct`, `CPUInfo.IOwaitPct`. Heuristics: CRIT at 20%/40%, WARN at 10%/20%.
Correlation rules `ruleIODrivenLoad` and `ruleCPUStealUnderLoad` cross-correlate.
**Run queue (June 4):** same two-sample `/proc/stat` read now also captures
`procs_running` (run-queue depth), `procs_blocked` (D-state count), and `ctxt`
(→ context-switch rate). `CPUInfo.RunQueue/ProcsBlocked/ContextSwitchRate`.
Heuristic `CPU/RunQueue`: WARN ≥2× cores, CRIT ≥4× cores. Correlation rule
`ruleRunQueueSaturation` flags genuinely CPU-bound load (run queue saturated while
iowait + steal both clear). Context-switch rate surfaces as a supporting hint, not
a standalone threshold — reliable *spike* detection needs the history-aware v2.
Used `/proc/stat procs_running` rather than `/proc/schedstat nr_running` (simpler,
version-stable, and the read was already happening). Live-verified across 3 hosts:
- **pve01** (8-core Debian host): silent at run-queue 1, WARN at 24 runnable while
  load avg still read 0.92 — proving run queue catches saturation load avg lags on.
- **AlmaLinux 9 LXC** (RHEL family, 2-core limit): CRIT at 13 runnable. Crucially
  reported "on 2 CPUs" (the container limit via `ContainerCtx.CPULimitCores`), not
  the host's 8 — lxcfs virtualizes `/proc/stat procs_running` to container scope, so
  the heuristic is container-aware and does **not** false-positive against host cores.
- **openSUSE Leap 16 KVM** (1-core, real kernel): CRIT at 13 runnable on 1 CPU.
Single-core grammar fix: "1 CPU" not "1 CPUs" (`pluralize` helper).

### [V2-COLLECTOR] Storage performance diagnostics
Write amplification, queue depth, fsync latency (eBPF — v3).

### ~~[V2-COLLECTOR] TLS / certificate health~~ ✅ DONE (June 4, commit 6058936)

`dsd tls`: local cert file scan (pre-existing) + remote endpoint expiry
(`--endpoint host:port`, `--endpoints-file`, `--json`). `collectors/tls_remote.go`
dials with InsecureSkipVerify to read expired certs. Verified: github.com:443 + PVE01:8006.

### ~~[V2-COLLECTOR] Security drift detection~~ ✅ DONE (June 4, commit 7e3fb6b)

`dsd security --save-baseline` + `--drift`. SHA-256 SSH config hashes, known SUID list,
sudoers NOPASSWD entries, suspect cron entries. New SUID=CRIT, SSH/sudo/cron change=WARN.
`internal/baseline/security_baseline.go` — atomic JSON in `~/.dsd/security-baseline.json`.
Fix: `findUnexpectedSUIDs()` was dead code; `ScanSUIDBinaries()` added for drift path only.
Live verified: PVE01 + AlmaLinux 9 LXC.

### [V2-COLLECTOR] Process-to-network anomaly mapping
Unknown processes on ports, reverse shell heuristics.
CAUTION: drifts toward EDR territory — strategic decision required.

### [V2-COLLECTOR] macOS additions
Lower priority. Defer until macOS user demand exists.

---

## [TESTBEDS] Hardware Validation

### RHEL 10 Laptop (192.168.1.145) — active Linux testbed
**Sessions 1–10 validated:**
- `dsd services deep` ✅ | `dsd health` sessions ✅ | SSH hardening ✅
- User account audit ✅ | `dsd cron` ✅ | `dsd net dns` ✅
- `dsd gpu` AMD + NVIDIA nouveau ✅ | cgroup v2 ✅ | LVM thin snapshots ✅
- Docker/Podman crash-loop ✅ | SELinux AVC grouping ✅
- k3s `dsd k8s` — flannel CRIT, workloads degraded ✅
- `dsd proc <k3s>` — 518 MB Private_Dirty, 244 sockets ✅
- `dsd logs` — 38k errors (SELinux/Podman), journald+syslog ✅
- `dsd disk` — SK Hynix NVMe SMART PASSED, wear:0%, spare:100%, temp:51°C ✅
- `dsd disk --deep` — nvme0n1 1.5 MB/s write I/O rate ✅
- `dsd kvm` — libvirt 11.10.0 / QEMU 10.1.0, test-vm healthy ✅
- `dsd health deep` package integrity — 7 critical security updates surfaced ✅
- `dsd net deep` NFS — healthy mount (1ms) + stale detection (2.36s, no hang) ✅
- `dsd net deep` BIND — BIND 9.18.33, 5 zones OK, includes followed ✅
- `dsd docker` — exit:137 (OOM kill), socket mount ❌, root user ⚠️, secrets ⚠️ ✅
- `dsd docker` daemon — version: 5.6.0 (API 1.41) ✅ Storage: overlay ✅
- `dsd docker` firewalld nftables WARN fires in `dsd health` ✅
- `dsd health deep` cgroup scopes — `system:k3s.service`, `k8s`, `user:1000` ✅
- `dsd security` SELinux booleans, AVC groups (init_t → container_runtime_t) ✅
- `dsd disk` LVM — 2 VGs, thin pool, snapshot, RAID API tested ✅
- `dsd timeline` — veth0 failure ×402 deduplicated, load avg shown ✅

**Still to test on Legion:**
- Suspend/resume cycle | Battery vs AC transitions | GPU power state transitions

### Debian 13 VM (VM 101 on pve01) — reusable Debian testbed (NEW Jun 4)

Persistent cloud-image VM for Debian-family validation. Reachable from the Proxmox
host (internal subnet); relay via the host for Mac access.
- **VMID:** 101 (`debian13-vm`), 2 vCPU / 2 GB / 20 GB on `local-hdd`, cloud-init.
- **IP:** 192.168.10.69 (DHCP). **User:** `debian` (sudo, host SSH key authorised).
- **Reach:** `ssh root@192.168.10.20 'ssh debian@192.168.10.69 "..."'`
- **Image:** debian-13-genericcloud-amd64 (kernel 6.12, Trixie). Minimal — `smartctl`,
  `zfsutils`, etc. not installed (useful for testing graceful "tool absent" paths).
- **First run (Jun 4):** 26 collectors clean; correctly caught swappiness/rmem sysctl
  WARNs, SSH weak-MAC + X11/agent-forwarding hardening, no-firewall-rules WARN,
  NOPASSWD-sudo + never-expire-password for `debian`. Found BUG-023 (AppArmor name
  mangling) and the sysctl-default false-positive note (both logged above).
- **Reusability:** `qm clone 101 <newid>` for a fresh identical Debian box, or
  `qm stop/start 101`. Not destroyed.

### ARM64 Linux via OrbStack (MacBook M-series) — preliminary arch testbed (NEW Jun 4)

The Mac is arm64 hardware; OrbStack runs **native aarch64 Linux containers** (near-zero
overhead), so this is real ARM64-Linux execution, not emulation. Closes the highest-
probability arm64 risk — "does the binary run and do the /proc collectors parse on ARM" —
at zero cost. Method:
```
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/dsd-linux-arm64 ./cmd/dsd
docker run --rm --platform linux/arm64 -v "$PWD/dist/dsd-linux-arm64:/dsd:ro" debian:13 /dsd health
```
Two tiers run on the Mac, both native aarch64 (Apple Virtualization.framework, not emulation):

**Tier 1 — bare container** (`docker run --platform linux/arm64 debian:13`): binary runs;
arch detected `Apple ARM (aarch64)`; core /proc collectors all parsed (CPU, memory, load,
run-queue, processes, FD, entropy, clock, sysctl, cpufreq, network); `disk --json` valid;
exit codes propagate (health=2 w/ DBus CRIT, cpu=0 clean — BUG-022 fix not x86-specific).
The DBus CRIT is a true reading of a bare container (no init), not an arm bug.

**Tier 2 — OrbStack machine** (`orb create debian dsd-arm`, Debian 12 bookworm, **systemd
running as PID 1**): the systemd/userland-dependent collectors that the bare container
couldn't exercise now read correctly on aarch64 — **Systemd OK, DBus OK, Sessions OK**,
journald config detection, hardening (NOPASSWD-sudo WARN). Confirms the container's DBus
CRIT was a container artifact, and that the systemd-path collectors are not x86-specific.
Method: `orb push -m dsd-arm dist/dsd-linux-arm64 /tmp/dsd && orb run -m dsd-arm sudo /tmp/dsd health`.

**Tier 3 — real ARM server (STILL OPEN):** arm64 *hardware* paths — SMART, thermal sensors,
IPMI, GPU, real CPU-feature detection — none of which any Mac-hosted VM/container exposes
(Disk shows the `/mnt/mac` passthrough, no real block devices). Needs a real aarch64 server:
**Oracle Cloud always-free Ampere ($0)** or a Raspberry Pi. Graviton not required — Ampere/Pi
exercise the same hardware paths. This is the remaining ARM gap; see candidate-features plan.

### MacBook (arm64 macOS) — active macOS testbed
**Sessions 1–6 validated:**
- `dsd disk` — disk0 500GB NVMe [APPLE SSD AP0512R] SMART: PASSED ✅
- APFS container label (no false "not mounted") ✅

### Test Coverage Matrix

| Scenario | RHEL Laptop | Proxmox Host | Debian 13 VM (101) | macOS arm64 |
|---|---|---|---|---|
| 20+ collectors | ✅ | ✅ (pve01, Jun 4) | ✅ (VM 101, Jun 4) | ✅ |
| ARM64 Linux (aarch64) | N/A | N/A | N/A | ✅ OrbStack (Jun 4): /proc collectors + systemd/journald/DBus/sessions parse (container + machine); HW paths (SMART/thermal/IPMI/GPU) need real ARM server — TODO |
| SATA SSD SMART (Linux) | ✅ | ✅ LITEONIT 128GB | N/A | N/A |
| NVMe SMART (macOS diskutil) | N/A | N/A | N/A | ✅ |
| HDD detection | N/A | ✅ WD 2TB SMART PASS | N/A | N/A |
| ZFS pool health | N/A | ✅ file-backed pool (Jun 4): ONLINE + DEGRADED both caught, health CRIT | TODO | N/A |
| Disk I/O rate (deep) | ✅ | ✅ sda/sdb idle 0.0 MB/s | ✅ 4.8ms | N/A |
| LVM thin pool + snapshots | ✅ | ✅ pve/data 23%, low-space WARN | TODO | N/A |
| Run-queue saturation (CPU/RunQueue) | ✅ AlmaLinux 9 LXC (RHEL fam) | ✅ pve01 host + openSUSE KVM | TODO | N/A |
| AMD GPU (amdgpu) | ✅ | depends | N/A | N/A |
| NVIDIA (nouveau) | ✅ | depends | depends | N/A |
| k3s / k8s | ✅ | depends | TODO | N/A |
| KVM / libvirt | ✅ | ✅ likely | TODO | N/A |
| NFS stale detection | ✅ | TODO | TODO | N/A |
| BIND/named health | ✅ | TODO | TODO | N/A |
| Package integrity (deep) | ✅ | TODO | TODO | N/A |
| dsd proc smaps_rollup | ✅ | ✅ likely | ✅ | N/A |
| Docker/Podman | ✅ | depends | TODO | TODO |
| cgroup v2 | ✅ | ✅ likely | ✅ | N/A |
| SELinux enforcing | ✅ | depends | N/A | N/A |
| Battery | ✅ | N/A | N/A | ✅ |
| Journal persistent | ✅ | ✅ likely | ✅ | N/A |
| Log severity summary | ✅ | TODO | TODO | N/A |
| Crash file detection | ✅ | TODO | TODO | N/A |
| Suspend/resume | TODO | N/A | N/A | TODO |
| Multi-socket / NUMA | N/A | depends | N/A | N/A |
| apt vs dnf | dnf only | apt likely | ✅ apt (Debian 13) | brew |
