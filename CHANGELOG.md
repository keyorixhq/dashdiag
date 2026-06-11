# Changelog

All notable changes to DashDiag are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> Note: this file was not maintained between v0.2.0 and v0.6.8 — those releases
> are documented in [GitHub Releases](https://github.com/keyorixhq/dashdiag/releases)
> (auto-generated notes). Resumed at v0.6.9.

---

## [v0.6.13] — 2026-06-11

A follow-up to v0.6.12 closing the matching display drift.

### Fixed

- **network: `dsd net --deep` now agrees with `dsd health`.** v0.6.12 rate-normalized
  the since-boot TCP counters in the health verdict, but the standalone
  `dsd net --deep` table and its issue tally still classified those same counters
  by raw absolute value — so it could show ⚠️/❌ and count an "issue" for a lone
  historical SYN-retransmission/listen-overflow that `dsd health` correctly reports
  as INFO. Both now read a single shared classifier (`analysis.DeepTCPCounterLevel`),
  so the two views can't diverge (same single-source approach as the v0.6.11 disk
  fix). The counter table is relabeled "cumulative since boot." Verified live on an
  8-day-uptime host (149 SYN retransmissions → INFO, Network OK).

## [v0.6.12] — 2026-06-11

A bug-fix and hygiene release continuing the false-verdict cleanup.

### Fixed

- **network (false CRIT on long uptime)** — the since-boot TCP counters
  (SYN retransmissions, listen-queue overflows, retransmit failures) were read
  as raw totals, so a single old spike on a long-uptime host produced a current
  WARN/CRIT. They are now rate-normalized against uptime: a sustained rate
  escalates, while a small historical total — or one that can't be rated because
  uptime is unknown — is reported as INFO with the "not necessarily ongoing"
  boundary surfaced.

### Changed

- **internal: zero golangci-lint issues.** Fixed the `.golangci.yml` v2 schema
  (test-file exemptions had been silently inactive since the v2 upgrade),
  refactored `rpmvercmp` and `checkPackages` for clarity, and replaced a
  deprecated `parser.ParseDir` call. No behavioural change; CVE version-compare
  behaviour is pinned by tests and verified identical.

## [v0.6.11] — 2026-06-10

A correctness-and-coverage batch: a few targeted features plus continued
false-OK / phantom-verdict fixes across collectors.

### Added

- **arm64 awareness** — CPU core identification on arm64 and an arch-aware GRUB
  check (no x86-only assumptions) (#158).
- **Fleet Team-mode nudge** — multi-host `dsd fleet` runs surface a tasteful
  waitlist nudge for the forthcoming Team mode (#154).
- **Package update freshness** — `dsd packages` marks an "up to date" verdict as
  *unverified* when the package manager's update metadata is stale, instead of
  asserting health it can't confirm (#163).

### Fixed

- **health (non-systemd)** — DBus and journald checks are gated on systemd, so
  Alpine/OpenRC hosts no longer raise a phantom CRIT (#162).
- **disk capacity** — `dsd disk` capacity verdicts are aligned to `dsd health`
  from a single source, eliminating divergent thresholds (#161).
- **timeline** — dmesg events are classified by kernel log level rather than
  keyword matching, reducing mis-severity (#160).
- **drives (false-OK)** — NVMe drives are no longer reported "healthy" when SMART
  was never read (#159).
- **logs** — pstore panic records are recency-gated so a single old panic no
  longer produces a perpetual CRIT (#157).
- **health (memory/crash)** — sub-GB total memory no longer renders "0 GB"; a
  stale crash-loop is no longer presented as live (#156).
- **install** — the documented `--prefix` flag is honored, with wget and
  `--prefix` now covered in CI (#155).

## [v0.6.10] — 2026-06-09

### Fixed

- **Gated-collector false-OK sweep** — three more error states that were silently
  hidden now surface:
  - **Ceph**: a node configured for a cluster (`/etc/ceph/ceph.conf` present) whose
    mons are unreachable now reports CRIT instead of staying silent (#145).
  - **cloud-init**: an errored/degraded instance is now flagged — `cloud-init
    status` exits non-zero to report state and still prints the status JSON, which
    was previously discarded (#146).
  - **IPMI**: a failed BMC/sensor read on a server with IPMI hardware now WARNs
    instead of being swallowed by the not-available early return (#146).

## [v0.6.9] — 2026-06-09

A fleet-wide review closing a recurring **false-OK** bug class — a green/OK verdict
(or silence) shown when a check had not actually verified health.

### Fixed

- **Unified verdict visibility** across live `dsd health`, `--report`, and
  `--json`/`--yaml`: not-applicable collectors no longer appear as phantom "✅ OK"
  rows. Backed by a shared `runner.IsAvailable` contract + AST meta-test (#131, #132).
- **Disk/SMART**: a FAILING drive (smartctl exits non-zero on "DISK FAILING") is no
  longer silently skipped — the "back up immediately" CRIT now fires (#138).
- **Docker**: container OOM kills are no longer missed on hosts with >10 die/kill
  events in the window (#140).
- **PVE**: a never-backed-up VM is no longer hidden by a healthy node-wide backup
  age (#143).
- **Security drift**: added/removed SSH config drop-ins are now detected, not just
  content changes (#137).
- **TLS**: a cert that expired <24h ago is classified expired, not "expires in 0
  days" (#136).
- **CVE**: "scan unavailable" surfaces as INFO instead of a green CVE OK (#135).
- **Timeline**: journal parsing hardened — no false CRITs from a missing PRIORITY,
  no dropped non-UTF-8 MESSAGE events, rune-safe truncation (#134).
- **k8s**: most-recent warning events are shown (was oldest), and a malformed line
  no longer aborts event collection (#141).
- **BIND**: no phantom "named not answering" when `dig` isn't installed (#142).
- **LVM**: classic-snapshot origin no longer misread as the volume size (#139).
- **Collectors**: message truncation is rune-safe — no split UTF-8 in verdict lines
  (#144).

### Changed

- **`dsd fleet --json`** now returns a fleet-level rollup object
  (`{verdict, exit_code, total, counts, hosts}`) mirroring `dsd health --json`,
  instead of a bare array. Consumers using `jq '.[]'` should switch to `.hosts[]`
  (#133).

## [v0.2.0] — 2026-05-10

### Added

- **`--debug` flag** — enables structured debug logging to stderr for
  troubleshooting silent failures and slow checks. Output is independent
  of the configured output mode (`--json`, `--yaml`, `--plain`) so machine-
  readable stdout stays clean. Format: `[debug] HH:MM:SS.mmm  Component
  message  key=value`. Debug logging covers:
  - Per-collector start, finish, duration, and error from `internal/runner`
  - Network probe trace from `internal/collectors/network_quick.go`:
    gateway detection, each ICMP attempt (host, mode, error), TCP fallback
    attempts, final probe results
  See `internal/debug/` package for the API. Disabled by default — zero
  overhead when off.

- **F0 — inline drill-down on WARN/CRIT.** When a check fires WARN or CRIT,
  DashDiag now automatically gathers and displays the relevant attribution
  data inline:
  - **Memory**: top processes by RSS
  - **CPU**: top processes by CPU%
  - **Swap**: top processes by VmSwap (Linux)
  - **Disk**: largest directories on the affected mount
  - **IO**: top processes by I/O bytes/sec (Linux)
  - **Network**: TCP states by process, gateway ping latency/jitter
  - **Processes**: zombies with their parent process info
  - **Systemd**: last 20 lines of journalctl for failed units
  - **FDLimits**: top processes by FD usage as % of their limit
  - **Clock**: chronyc tracking output (Linux) or sntp output (macOS)
  - **Sysctl**: current value vs recommended for failing keys
  - **KernelSecurity**: AppArmor profiles in complain mode, SELinux denials
  
  Healthy systems are unaffected — drill-down code only runs on WARN/CRIT.
  Wall time on a healthy system stays at ~1.3s. Wall time when something is
  wrong adds ~0.5-1s for attribution work.
  
  Drill-down output appears in both terminal and `--json` formats.
  Use `--terse` to skip drill-down and see only the verdict.

- **`models.NetworkInfo.ICMPBlocked`** field (JSON: `icmp_blocked`,
  omitempty). Set to `true` when DashDiag had to fall back from ICMP
  probes to TCP probes for L3 reachability — typically when running
  as a non-root user on a system with restrictive
  `net.ipv4.ping_group_range`. Surfaces this fact for future privilege-
  aware UX messaging.

### Breaking changes

- **`--json` output**: check name `"MACPolicy"` renamed to `"KernelSecurity"`.
  Scripts that filter on `checks[].name == "MACPolicy"` must be updated.
  The underlying JSON fields inside the `raw` object are unchanged
  (`se_linux_present`, `se_linux_mode`, `se_linux_denials`, `app_armor_present`, `app_armor_mode`).

### Changed

- Renamed `MACPolicy` collector, model, and all internal references to `KernelSecurity`.
  The `MAC` prefix collided with macOS naming conventions and confused users on Mac
  (macOS does not implement Mandatory Access Control via SELinux/AppArmor).
- **Systemd and KernelSecurity now report INFO instead of OK when not applicable.**
  On systems without systemd (Alpine, OpenWrt, most Docker containers, macOS) the
  Systemd check now shows `INFO  systemd not present on this system` rather than
  `OK`. Same change for KernelSecurity when no kernel security module is enforcing.
  Previous behaviour would silently report OK and mislead users into thinking these
  subsystems were healthy when they weren't even running.
- **Errored collectors now surface as INFO insights** instead of being silently
  dropped. Previously, if a collector returned a non-nil error from `Collect()`,
  the analysis layer would silently skip it (`continue`) and the user would see
  *nothing* — indistinguishable from a passing check. Now any collector error
  produces an INFO insight: `<Check> check could not run — <error>`. Covers
  permission denials (`opening diskstats: permission denied`), context timeouts,
  missing system files, and any future collector failure mode.

### Fixed

- **Network check false-positive "gateway unreachable" for non-root Linux users.**
  The `go-ping` library required either `CAP_NET_RAW` or a permissive
  `net.ipv4.ping_group_range` (Ubuntu's default `1 0` blocks unprivileged
  ICMP). Both ICMP modes failed silently for typical non-root users,
  returning 100% packet loss — which heuristics interpreted as gateway
  CRIT. Discovered on real-hardware testing (2011 MacBook running Ubuntu
  24.04). Would have triggered for ~every `curl install.sh | sh` user
  on launch.
  
  Fix: added a TCP-connect fallback in `pingRTT`. When both privileged
  and unprivileged ICMP fail, DashDiag now tries TCP dial to ports 53
  and 80 — *both successful connection AND `connection refused` count
  as L3 reachability proof*, since the host responded to the packet.
  No `CAP_NET_RAW` required; works under every Linux distribution's
  default settings.

- **Gateway probe ambiguity for routers that ignore probes (e.g. Zyxel
  Keenetic).** Previously, any condition that produced `GatewayPingMs <
  0` triggered a CRIT "gateway unreachable" alert — even when the
  internet itself was clearly reachable. Some consumer routers drop
  ICMP/TCP probes on the LAN interface while still forwarding traffic
  normally. The analysis now distinguishes:
  - Both gateway *and* internet unreachable → CRIT "host appears offline"
  - Gateway silent but internet reachable → INFO "gateway not responding
    to probes — internet traffic is flowing"
  - Both reachable → normal latency thresholds apply

- **F0 drill-down didn't render in non-TTY contexts** — `internal/render/health.go`
  gated drill-down rendering on `mode == ModeHuman`, but `output.DetectMode`
  returns `ModePlain` whenever stdout is not a TTY (Docker without `-t`, CI/CD
  pipelines, shell pipes, redirected output). Extended the condition to
  `ModeHuman || ModePlain`. Lipgloss strips ANSI codes automatically in non-TTY
  contexts, so output stayed clean.

- **`SwapInfo.ZramUsedPct` field was always zero.** The field existed in
  the model since v0.1 but was never populated — a silent zero. Now reads
  `/sys/block/zramN/disksize` and `mm_stat` field 0 (`orig_data_size`)
  across all zram devices and calculates utilisation percentage.
  Graceful: if `mm_stat` is unavailable, the field stays zero.

- **SELinux insight orphaned by check-name mismatch.** SELinux insights
  used `Check: "SELinux"` but the renderer attached drill-down via prefix
  match against `"KernelSecurity"`. The drill-down was generated correctly
  but never displayed. Renamed the insight to `"KernelSecurity"` so prefix
  matching attaches the drill-down output.

---

## [v0.1.1] — 2026-05-08

### Fixed

- **macOS false positives**: devfs virtual mounts no longer show as full disks;
  clock sync now detected via `pgrep timed` (no sudo required on Ventura+);
  `somaxconn` threshold skipped on macOS (Linux-only concept);
  zombie detection column order fixed (`ps axo pid,ppid,stat,comm`);
  Memory/Swap insights show macOS-specific commands (`vm_stat`, `sysctl vm.swapusage`).
- **Colima/Lima VMs**: `/mnt/lima-*` disk mounts excluded; cloud-init systemd units
  (`cloud-final`, `cloud-config`, `cloud-init`, `cloud-init-local`) filtered from
  failed-unit list.
- **Clock in containers**: NTP check skipped when running inside a container
  (clock is inherited from the host).
- **FDLimits**: hot-process threshold lowered from 80% to 70% to reduce false negatives.
- **JSON output**: raw collector data included under `raw` key in each check object.
- **Network**: `probeConnectivity` extracted to fix `funlen` lint; DNS lookup has a
  dedicated 5 s sub-context timeout.
- **Heuristics**: `FDLimits` check name corrected (was `FileDescriptors`).

### Added

- Stress test suite (`scripts/stress/`) with self-calibrating CPU, swap, and IO tests;
  supports physical and SSH-safe test modes.

---

## [v0.1.0] — 2026-04-28

### Added

- Initial release.
- Collectors: CPU, Memory, Swap, Disk, IO, Network, Clock, FDLimits, Processes,
  Systemd, Sysctl, KernelSecurity (SELinux / AppArmor).
- Renderers: terminal health table (`dsd health`), JSON (`--json`), TUI (`--tui`).
- Analysis: threshold-based insights with per-check remediation hints.
- Platform detection: bare-metal, VM, container context awareness.
- CI: golangci-lint, gosec, govulncheck, dependabot, branch protection.
