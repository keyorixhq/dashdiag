# Changelog

All notable changes to DashDiag are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

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
