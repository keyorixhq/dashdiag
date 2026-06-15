# Changelog

All notable changes to DashDiag are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> Note: this file was not maintained between v0.2.0 and v0.6.8 — those releases
> are documented in [GitHub Releases](https://github.com/keyorixhq/dashdiag/releases)
> (auto-generated notes). Resumed at v0.6.9.

---

## [Unreleased]

## [0.14.0] - 2026-06-15

### Added

- **Kafka health.** A gated Kafka collector folded into `dsd health` (Kafka is a
  broker, like RabbitMQ — surfaced in health, not `dsd db`). The headline signal
  is **OFFLINE partitions** (a partition with no leader can be neither produced to
  nor consumed from — its data is unavailable) → CRIT; **under-replicated
  partitions** (replicas not in the ISR, so no redundancy) → WARN. Gated on the
  broker port (9092) + a kafka CLI (`kafka-topics.sh`/`kafka-topics`); reads via
  `--describe --unavailable-partitions` / `--under-replicated-partitions`. When
  the CLI can't reach the bootstrap server (SSL/SASL auth, or a broker mid-startup)
  it reports "needs access" (INFO), never a false green. Validated against a real
  3-node KRaft cluster.

### Fixed

- `dsd db` empty-state hint now lists **Memcached and MongoDB** alongside
  PostgreSQL, MySQL, and Redis — it had gone stale when those collectors were
  added in 0.13.0.

## [0.13.0] - 2026-06-15

Service coverage expands: dsd now watches four more of the engines you actually
run — message broker, search, document store, and a second cache — each with the
specific outage signal that matters, folded into `dsd health` (and `dsd db` for
the datastores). Gated and degrade-gracefully throughout: when metrics need
credentials dsd says so (INFO), never a false green.

### Added

- **RabbitMQ health.** Surfaces an active **resource alarm** (memory or disk
  watermark) — the state where the broker is up but BLOCKING all publishers, so
  messages silently stop being accepted. CRIT. Gated on the AMQP port + the
  rabbitmq CLI; diagnostics run via the rabbitmq user (Erlang cookie).
- **Memcached health.** Detects **active eviction** (the working set exceeds the
  cache) via a short two-sample eviction delta — not a bytes/limit ratio, which
  never shows pressure because memcached evicts to stay under the limit — plus
  connection saturation. Speaks the text protocol directly (no client needed).
- **Elasticsearch / OpenSearch health.** The **cluster status**: RED (primary
  shards unassigned — data unavailable) → CRIT; YELLOW (replicas unassigned — no
  redundancy) → WARN. Probes http/https on 9200; reports "needs credentials" when
  security is on.
- **MongoDB health.** Replica-set health: **no PRIMARY** (writes failing) → CRIT;
  a down member → WARN; plus connection saturation. Via one `mongosh --eval`
  round-trip.
- `dsd db` now also shows **Memcached** and **MongoDB** alongside Postgres, MySQL,
  and Redis.

## [0.12.0] - 2026-06-15

Service health: dsd now watches the **web servers and databases running on the
box**, not just the OS — the services that actually page you. Plus the timeline
groups events into incidents.

### Added

- **`dsd db` — database health.** Detects local **PostgreSQL, MySQL/MariaDB, and
  Redis/Valkey** servers (by their unix socket / PING) and reports liveness,
  connection saturation, memory pressure, replication lag, and more — in one
  focused command, and folded into `dsd health`. The checks target the outages
  that actually happen: `too many connections` before it fires, the Redis
  `noeviction` memory cliff (writes rejected), idle-in-transaction lock pileups,
  a replica that quietly fell behind. Metric depth degrades gracefully on access:
  when it can't read the metrics it says so (INFO), never a false green.
- **Web-server config-validity health** for **nginx, Apache, and HAProxy.** These
  servers keep serving their *last-loaded* config, so a broken on-disk config is a
  latent outage — invisible until the next reload takes the site down. dsd runs
  the server's own config test (`nginx -t` / `apachectl configtest` /
  `haproxy -c`) and raises a CRIT with the exact directive and line **before** the
  reload. Gated on a running server, folded into `dsd health`.

### Changed

- **`dsd timeline` v2 — incidents.** Instead of a flat wall of deduplicated
  events, the timeline now clusters time-adjacent events into **incidents** (a
  quiet gap starts a new one), each headlined by its worst event with the event
  count, distinct units, and span — the "what happened" story. Available in the
  table and in `--json` (`incidents[]`).

## [0.11.0] - 2026-06-15

Two diagnostic depth features — the correlation engine and `dsd fleet` both gain a
"v2" that turns raw signals into answers: *what's the root cause*, and *is it
fleet-wide or one box*.

### Added

- **Correlation engine v2** — six new cross-collector causal chains that name the
  root cause instead of listing symptoms: Disk-Full Service Failure (a full disk is
  the cause, the failed unit is downstream), NFS Stall Process Hang (D-state tasks on
  a stale mount), Clock Skew Breaking TLS/Auth (fix time, not the certs), Container
  Memory-Limit OOM (the container's limit is too low — host RAM is fine), Thermal
  Throttling Under Load (capped by heat, not core count), and DNS Resolver Failure
  (a resolver problem, not connectivity). Folded into `dsd health` alongside the v1
  rules.
- **`dsd fleet` v2 — cross-host aggregation.** Beyond the per-host verdict table,
  `dsd fleet` now groups every host's WARN/CRIT issues across the fleet and labels
  each **fleet-wide** (a majority share it — systemic, fix once), **outlier** (one
  host drifting from the rest), or common. Number-masked grouping collapses the same
  issue with host-specific values into one row. Shown as a "Fleet issues" section and
  in `--json` (`issues[]` with scope/hosts/count).
- **`NeedsDaemonReload` in `dsd health`** — surfaces systemd units whose on-disk file
  changed but were never `daemon-reload`ed (running stale config), folded from
  `dsd services deep` into the unified health verdict.

### Fixed

- systemd daemon-reload detection queried the non-existent `NeedsDaemonReload`
  property (the real one is `NeedDaemonReload`), so the signal was dead in
  `dsd services deep` too — now corrected.
- `dsd replay` now routes symlink reads through the capture layer, so a captured
  host's symlink-derived insights (NIC driver, resolv.conf, etc.) reproduce on
  replay instead of reading the replaying machine's filesystem.

## [0.10.1] - 2026-06-15

Hardening and correctness follow-up to the v0.10.0 capture/replay release: every
collector's I/O is now routed through the capture layer (so `dsd replay` reproduces
the *full* health run, not a subset), plus a batch of health-verdict correctness
fixes — several "stale signal reported as live" and "couldn't read → reads healthy"
cases.

### Fixed

- Docker: a container that crash-looped earlier but has since run stably no longer
  reports a perpetual "crash looping" CRIT. The verdict is now recency-gated — a
  container running continuously past a 10-minute window is treated as recovered (#278).
- Kubernetes: a recovered (fully-ready) pod with a high lifetime restart count no
  longer raises "instability detected"; active flapping still surfaces via
  CrashLoopBackOff / not-ready (#280).
- Disk: `dsd disk` now flags NVMe wear ≥90% or media errors even when the SMART
  overall assessment still reads PASSED — a degrading drive no longer summarises as
  "healthy" (#281).
- Disk: an overdue ZFS scrub (>30 days) renders as an informational note, and a
  never-run anacron job as INFO — matching the severities `dsd health` already uses
  (#281).
- Replay: `dsd replay` now reproduces permission-denied reads faithfully
  (`os.IsPermission`), so permission-gated insights like "config present but not
  readable" are no longer silently dropped when a bundle was captured as non-root
  (#284).

### Changed

- Capture/replay: all collectors now route their file, glob, directory, and command
  I/O through the capture layer, so `dsd capture --raw` records — and `dsd replay`
  reproduces — the complete health run rather than a subset (#281, #283).
- Capture: GPU presence is autodetected and the capture manifest is routed through
  the source layer (#282).

### Breaking Changes

- None

## [0.10.0] - 2026-06-14

Raw input capture & replay — turn a scarce real-hardware window into permanent,
re-runnable test capital. Collectors read sysfs and command output; until now
those raw bytes were discarded after the run, so a hardware-specific parser bug
(AMD k10temp, EDAC, amdgpu) couldn't be reproduced off the box. Now `dsd capture
--raw` records exactly what the collectors read into one portable bundle, and
`dsd replay` re-runs the real collector code against it offline. See
`docs/adr/0003-raw-input-capture-replay.md`.

### Added

- **`dsd capture --raw`** — one command, one self-contained `.tar.gz`. Runs the
  full health check with every file/sysfs read and command output recorded (keyed
  by real path and argv), plus the rendered health JSON for cross-checking. The
  native replacement for `hack/hw-snapshot.sh`, which remains the fallback for
  hosts where you can't get a binary on.
- **`dsd replay <bundle>`** — re-runs the migrated collectors (thermal, cpufreq,
  gpu) against a captured bundle with no hardware and no live reads. Also accepts
  the file layer of an `hw-snapshot.sh` tarball. Replay must run in a binary
  matching the captured host's OS (use an OrbStack Linux container for a Linux
  bundle).
- **`internal/source`** — a recordable/replayable I/O abstraction behind the
  collectors (Live / Recorder / Replay) with a `raw-v1` bundle format. An
  unrecorded access fails loud rather than falling through to the live system, so
  a recording gap can't masquerade as a healthy result.

### Changed

- Collector command execution (`runCmd` / `runCmdOutput` / `runCmdTimeout`) and
  the thermal / cpufreq / amdgpu sysfs reads now route through the active source,
  so they are captured and replayable. Live behaviour (LC_ALL=C, timeouts,
  exit-code contract) is unchanged.

## [0.9.7] - 2026-06-14

k8s node-diagnostics overhaul, validated end-to-end against a real k3s cluster: the
checks now understand k3s's layout, the OS-layer verdict actually surfaces in
`health deep`, and the KUBE-FORWARD check no longer false-OKs when it can't be read.

### Added

- **`dsd health deep` now surfaces the k8s OS-layer node diagnostics** — CNI plugins,
  flannel, KUBE-FORWARD/kube-proxy, IP forwarding and cert expiry. These were collected
  only by `dsd k8s --deep` and judged only in the (non-deep) health path, so they
  produced no insights anywhere; deep health now runs the deep K8s collector so the
  verdict actually fires. Validated on a live k3s node (no false positives).

### Fixed

- **K8s: the KUBE-FORWARD chain check no longer defaults to "present" when it can't be
  read** — when neither `nft` nor `iptables` is available on the host (e.g. k3s keeps
  its bundled iptables off the host PATH), the old logic evaluated `!contains("", "No
  chain")` and reported the chain as present (false-OK). It now records whether a tool
  actually ran and treats "couldn't check" as unknown, not present/missing.

### Fixed

- **K8s: the OS-layer node diagnostics now understand k3s** — `dsd k8s --deep` reported
  wrong values on a healthy k3s node (the dominant homelab/edge distribution) because
  the checks assumed kubeadm paths: CNI bins reported missing (k3s bundles them under
  `/var/lib/rancher/k3s/data/current/bin`, not `/opt/cni/bin`); flannel reported not-in-use
  (k3s keeps its CNI config under `/var/lib/rancher/k3s/agent/etc/cni/net.d`); containerd
  reported inactive (k3s embeds it — socket at `/run/k3s/containerd/containerd.sock`); and
  kubelet reported inactive (`systemctl is-active kubelet k3s` is a two-unit call that
  fails because k3s has no `kubelet.service` — the unit is `k3s`/`k3s-agent`). All four now
  detect the k3s layout. Validated live against a real k3s v1.36 node.

## [0.9.6] - 2026-06-14

Tail of the collector-audit sweep: the bonding/oom JSON cleanups and the cgroup deep
recency reframe (lifetime counters no longer presented as live alarms).

### Fixed

- **Cgroup (deep): cumulative counters are no longer framed as live alarms** — the
  root-scope `memory.events` oom_kill counter fired a CRIT "processes are being killed"
  whenever it was >0, but it's a lifetime total since boot, so a single boot-time OOM
  produced a permanent CRIT (a recency-gate). It's now an INFO that says "since boot
  (lifetime total)" and points to the windowed Logs/OOM check for recency. CPU
  throttle (`throttled_usec/usage_usec`) is likewise a lifetime ratio, not the current
  rate — its wording now says "of its run time (since boot)" so a slice hammered at
  boot but idle now isn't read as currently throttled. (Throttle severity unchanged —
  a high lifetime ratio is still a real chronic-constraint signal.)

### Fixed

- **Bonding: the standalone collector's JSON now reports degraded/all_down** — only the
  NetworkCollector path set those verdict booleans, so `dsd bonding`/`--json` raw
  payloads showed `degraded:false`/`all_down:false` even for a fully-down bond (the
  human verdict was already correct). The derivation moved into the shared parser, so
  every caller gets it.
- **OOM: when neither journalctl nor dmesg can be read, the section gates off** — both
  failing (non-systemd host with `kernel.dmesg_restrict=1` and no root) left
  Available=true with 0 events, which rendered a phantom "OOM ✅ OK" row. It's now
  marked unavailable so an un-checkable OOM state isn't shown as verified-clean.

## [0.9.5] - 2026-06-14

Final wave of collector-audit fixes: three more "couldn't read → reads healthy"
false-OKs (kvm enumeration failure, cgroup-v2 PSI paths, macOS swap read error).

### Fixed

- **KVM: libvirt up but unqueryable no longer reads as "no VMs"** — `kvmCollectVMs`
  returned silently on both an empty list AND a `virsh list` error, so when libvirt was
  detected but enumeration failed, the empty VM list read as healthy and a crashed VM
  went unreported. An enumeration error is now distinguished from "no domains" and
  surfaced as a WARN.
- **Pressure (PSI): the cgroup-v2 fallback read the wrong paths** — when `/proc/pressure`
  is absent, the collector fell back to `/sys/fs/cgroup` but still read `<base>/memory`
  (the controller dir) instead of `<base>/memory.pressure`, so every PSI read failed and
  Pressure reported empty/no-pressure. The fallback now uses the `.pressure` suffix.
- **Swap (macOS): a failed swap read no longer reads as healthy** — on `SwapMemory`
  error the collector returned a fabricated `MemPressureLevel:1` with zero usage, which
  `checkSwap` passed silently. It now returns the error so the row reads as errored.

## [0.9.4] - 2026-06-14

Second wave of collector-audit fixes: parser-realism bugs (real command output the
parsers mis-read) and two k8s false-alarms on non-flannel CNIs / non-root runs.

### Fixed

- **K8s: no more false CRIT on Calico/Cilium nodes, or when CNI dir is unreadable** —
  the OS-layer deep checks (a) CRIT'd "/run/flannel/subnet.env missing" on every node
  not using flannel (Calico/Cilium/Weave never create that file), and (b) read
  /opt/cni/bin with a discarded error, so a permission-denied (non-root) read reported
  "/opt/cni/bin empty — networking will fail". Flannel's subnet check now only fires
  when flannel is the configured CNI (detected from /etc/cni/net.d), and an unreadable
  CNI dir is treated as state-unknown (the existing IPForwardChecked pattern), not
  empty.

### Fixed

- **Parser realism: four collectors mis-parsed real command output** (found by the
  audit sweep, fixed as a batch):
  - **nspawn**: `machinectl list` has no state column (MACHINE CLASS SERVICE OS VERSION
    ADDRESSES), so the OS field was read as a "state" and `FailedCount` was always 0.
    Failed containers are now counted from failed `systemd-nspawn@*` units.
  - **sessions**: a local login's "-" in the `w` FROM column was treated as "no FROM
    column", shifting LOGIN@/IDLE/command by one field. "-" is now recognized as the
    (empty) FROM column.
  - **snapper**: only the Unicode "─" separator was skipped; the ASCII "---+---"
    separator that older/non-UTF-8 snapper prints was counted as a phantom config/
    snapshot. Both forms are now skipped.
  - **drbd**: the per-resource stats line ("ns:0 nr:0 …") was misclassified as a new
    resource header (matched on a colon at offset 2), duplicating the resource and
    stealing its sync-progress line. Resource headers now require a numeric minor.

## [0.9.3] - 2026-06-14

A batched collector audit (30 collectors, each finding adversarially verified) plus
live hardware validation closed a further set of false-OK / false-alarm bugs across
the storage, fabric, and server-hardware collectors.

### Fixed

- **OOM: an old OOM kill from the dmesg ring buffer is no longer reported as "last
  24h"** — when journalctl is unavailable (non-systemd hosts), the collector fell back
  to `dmesg`, which has no `--since`, and counted EVERY OOM line in the ring buffer as
  recent. On a long-running host an OOM from days ago then fired a CRIT "OOM kills in
  the last 24h" (recency-gate). The dmesg fallback now drops dated events older than
  24h (undated/boot-relative ones are kept conservatively).

- **iSCSI: a failed/reconnecting session is no longer reported as logged-in** — the
  collector parsed the bare `iscsiadm -m session` listing (which carries no state) and
  hardcoded every session `LOGGED_IN`, so `FailedCount` could never increment and a
  dropped storage path read as healthy. It now parses `iscsiadm -m session -P 1`, which
  includes the real per-session "iSCSI Session State". Verified live (2-portal LIO rig).

- **NVMe: an unparseable `smart-log` no longer reads as a healthy drive** — `SmartRead`
  was set true whenever `nvme smart-log` exited 0, even if nothing parseable came back
  (unexpected format, a tool that printed only a banner) — leaving the all-zero health
  fields looking real. It's now true only when a recognized SMART field was parsed.
- **`dsd thermal`: no longer prints "Thermal healthy" at 0.0°C** — when a CPU thermal
  sensor was detected but its temperature couldn't be read (CPUTempC stayed 0), the
  command rendered a green "Thermal healthy. Checks passed". It now reports the sensor
  as present-but-unreadable, matching the health heuristic which already gates 0°C.

- **HBA / InfiniBand: a port whose state could not be read no longer counts as
  healthy** — both verdicts whitelisted an empty state (`&& state != ""`), so a FC/IB
  port whose sysfs state file was unreadable was silently treated as fine — while the
  inline health row already counted it as not-online (a sibling-divergence false-OK).
  An unreadable port state now surfaces (WARN "state could not be read").

- **IPMI: PSU failures named "PS1 Status" are no longer missed** — the power-supply
  check only matched sensor names containing "psu" or "power supply", but real Dell/
  Supermicro servers name them "PS1 Status" / "PS2 Status". A critical/failed PSU on
  those servers went unreported. Matching now also recognizes the `ps<digit>` form
  (without matching "ups").
- **NFS: a promptly-failing stale mount is no longer a non-event** — a mount whose
  `statfs` returned ESTALE/EIO *immediately* (rather than hanging for the 2s timeout)
  set Healthy=false but left Stale=false, so the CRIT "mount is STALE" never fired. A
  prompt ESTALE/EIO now flags the mount stale.

- **Ceph: an unreadable cluster health no longer reads as OK** — when `ceph health
  detail --format json` exits 0 but its output isn't parseable health JSON (empty, a
  leading deprecation banner, or an unexpected shape), `Health` was left empty and the
  verdict fell through to silent OK. It's now marked unknown and surfaces a WARN.
- **TLS: an unreadable/garbled certificate no longer reads as healthy** — `checkTLS`
  ignored the `Uncheckable` list (and returned early when no checkable certs existed),
  so a cert file that couldn't be read produced a clean "0 expired". Uncheckable certs
  now WARN.

- **BIND: "named service is not active" no longer false-fires on RHEL/Fedora or
  non-systemd hosts** — the check ran `systemctl is-active named bind9` (two units at
  once), which exits non-zero unless BOTH units exist and are active. RHEL/Fedora have
  no `bind9.service`, so with named fully running the command failed, stdout was
  discarded, and `ServiceActive` went false → a CRIT "DNS server not running" that also
  short-circuited the port/config/zone/query checks. It now probes each unit name
  separately and falls back to the running process (`/proc` comm) on non-systemd hosts.
- **NFS: rpcbind no longer reported down on non-systemd hosts** — `nfsRpcbindActive`
  was `systemctl is-active`-only; it now falls back to the running process on
  Alpine/OpenRC/Devuan.

## [0.9.2] - 2026-06-14

Hardware-validation release: standing up real storage and a real non-systemd host on
the test fleet (live multipath/iSCSI, btrfs/LVM/ZFS, an Alpine/busybox LXC) surfaced
three bugs that unit tests missed — including two cases where the 0.9.1 non-systemd
fixes only *appeared* to work until run on actual busybox/Alpine.

### Fixed

- **Auth: SSH brute-force on busybox/Alpine is no longer missed** — `readAuthLog`
  only consulted `/var/log/auth.log` and `/var/log/secure`, but busybox/Alpine (and
  other minimal-syslog hosts) have no separate auth log — sshd's "Failed password" /
  "Invalid user" lines go to the general `/var/log/messages`. With no journald either,
  dsd saw nothing and reported "no failed logins" (a security false-OK). `messages` is
  now a third fallback candidate (consulted only when auth.log/secure are absent, so it
  never double-counts on Debian/RHEL). Verified live on an Alpine LXC: injected failed
  logins now surface with source IPs and the root-attempt warning.
- **Cron/Auditd: daemon detection on busybox/Alpine now actually works** — the
  non-systemd fallback added in 0.9.1 used `pgrep -x <name>`, but **busybox's `pgrep
  -x` matches `argv[0]` (the full `/usr/sbin/crond` path), not the comm basename** —
  so it missed a running busybox `crond`/`auditd` on the very Alpine/OpenRC hosts the
  fallback was meant to fix, and still false-alarmed "no cron daemon" / "auditd not
  running". Detection now matches `/proc/<pid>/comm` directly, which is portable
  across `pgrep` implementations. Verified live on an Alpine LXC (busybox crond →
  correctly detected as active).

## [0.9.1] - 2026-06-13

A correctness-hardening release: a sweep of every collector that emits a health
verdict, closing a batch of "false-OK" bugs (a green/OK verdict shown when nothing
was actually verified) and two systematic root causes — subsystem-qualified check
names not matching their collector, and collectors assuming systemd/journald is
present (wrong verdict on non-systemd hosts).

### Fixed

- **btrfs: device errors on an unmappable device path no longer leave the volume
  "healthy"** — `btrfs device stats` errors were recorded only after matching the
  reported device path against a device from `btrfs filesystem show`, and the volume
  status upgrade lived inside that match. If the paths didn't line up (multi-device,
  `/dev/mapper`/LUKS names, or a show-parse that left the device list empty) a non-zero
  read/write/corruption/generation/flush counter was dropped and the volume stayed
  "healthy" — a false-OK on a storage-corruption signal. The volume is now flagged on
  any non-zero counter; per-device attribution remains best-effort.

- **Auditd: a running auditd on a non-systemd host no longer false-alarms "not
  running"** — the daemon-running check was `systemctl is-active`-only, so on a
  non-systemd host (OpenRC/SysV) where auditd is running it reported `Running=false`,
  producing a wrong compliance WARN ("auditd is installed but not running — compliance
  logging inactive"). It now also confirms via a running-process check (`pgrep`), the
  same fallback as cron daemon detection.

- **Cron: a running cron daemon on a non-systemd host is no longer reported as "no
  cron daemon"** — daemon detection only ran `systemctl is-active`, which fails on a
  non-systemd host (Alpine/OpenRC, Devuan/SysV, Gentoo, busybox `crond`) even when cron
  is running, producing a false WARN "no cron daemon and no anacron — scheduled jobs
  will not run". Detection now falls back to a running-process check (`pgrep`), so a
  cron daemon managed outside systemd is recognized. (Verified: busybox `crond` runs
  with no `systemctl` present and is `pgrep`-able.)

- **Auth: an unreadable SSH auth log no longer reads as "no failed logins"** — the
  Auth check counts failed SSH logins from the journal, falling back to
  `/var/log/{auth.log,secure}`. As a non-root user both are typically inaccessible
  (the journal sshd entries are system-scoped; the text logs are mode 640), and the
  fallback treated an unreadable file the same as an empty one — so the host reported
  0 failed logins having opened no log at all (a false-OK on a security check). The
  collector now distinguishes permission-denied (via `os.Open`/`os.IsPermission`) from
  "absent" and "no failures", sets the model's existing `Checked=false` when it truly
  couldn't read, and the verdict surfaces that as an honest INFO ("run as root to
  verify") instead of a silent pass. Quiet healthy hosts (readable log, 0 failures)
  are unaffected.

- **Logs: a syslog-only host no longer reports "0 errors" without reading its logs** —
  the severity summary runs `journalctl`, and the `/var/log` fallback that covers the
  no-error case was gated on `JournalVolatile` (a journald-only flag). On a host with
  no journald (Devuan, Alpine, Gentoo/OpenRC, …) `journalctl` reads nothing, so the
  error count stayed 0 and Logs read clean having consulted no log at all (a false-OK).
  The fallback now also fires when the detected log source is a pure syslog file, so
  `/var/log/{syslog,messages}` is actually scanned. journald and journald+syslog hosts
  are unchanged (their journal result stays authoritative — no double-reading).

- **Network: an on-link default route is no longer "verified" by pinging localhost** —
  on a host whose default route has no gateway hop (`default dev eth0`, gateway
  `0.0.0.0` — point-to-point links, tunnels, some cloud/DHCP setups), the route parser
  decoded the all-zero gateway as the literal IP `0.0.0.0`. `dsd health` then pinged
  `0.0.0.0`, which Linux routes to the **local host** (127.0.0.1) — so the gateway came
  back healthy at ~0 ms while never touching the uplink (a false-OK). The parser now
  treats an all-zero gateway as "no gateway hop": it keeps the interface but leaves the
  gateway empty, so connectivity is judged by the internet/DNS probes instead (verified
  against real `/proc/net/route` from an on-link dummy interface).
- **`health --cve`: the dnf/zypper/pacman verdict no longer claims a CVSS score it
  never measured** — the message read "critical security advisory — CVSS >= 9.0
  (dnf)", but the `<pkgmgr> updateinfo` advisory-list scan reports a vendor *severity
  rating* (Critical/Important), not a number, and a vendor's Critical/Important rating
  is not a strict CVSS band. It now reads "N critical security advisory(ies) — dnf
  rates these Critical", matching the honesty already enforced for apt (which exposes
  no severity at all). Verdict levels are unchanged — only the wording is now truthful.
- **`--report`: a subsystem-only CRIT no longer renders as "OK" in the Check Results
  table** — the table re-derived each check's status from the raw insights keyed by the
  *qualified* Check name (`Network/DNS`) but looked it up by the *base* collector name
  (`Network`), so a DNS-only CRIT showed `Network ✅ OK` while the Issues section above
  listed that very CRIT (a false-OK). The table now reads status straight from the
  baseline snapshot, which already rolls qualified findings up to their collector and
  records each check's worst finding.
- **Baseline/drift: a check's recorded status now reflects its worst finding** — the
  baseline snapshot took the *first* insight matching a check and matched check names
  *exactly*, so (a) a subsystem-qualified finding (`Network/DNS` CRIT, `Memory/Slab`,
  `CPU Load/Steal`) never attached to its collector and (b) a CRIT could be hidden
  behind an earlier INFO/WARN for the same check. Either way the check was recorded
  healthier than it was, so `dsd health` drift / `dsd baseline --drift` missed the
  degradation (false-OK). It now matches by base check name and keeps the worst level.
- **`--watch`: two devices with the same issue are tracked separately** — the change
  detector collapses fluctuating numbers in a finding's message so a value change
  (CPU 75%→82%) reads as "changed", not a resolve+new churn — but it also collapsed
  device indexes (`sda1`/`sda2`, `nvme0`/`nvme1`, `eth0`/`eth1`) into one signature, so
  two same-issue findings on different devices collided and one was dropped from the
  diff (e.g. `sda1` recovering wouldn't show as resolved while `sda2` still failed).
  Number-normalization now keeps indexes embedded in identifiers intact; free-standing
  values still collapse.
- **`--prometheus`: a subsystem-qualified finding now shows in its per-check metric** —
  insights with a qualified `Check` like `Network/DNS`, `Memory/Slab`, or `CPU Load/Steal`
  were keyed under the qualified name, but `dsd_check_status{check="…"}` is keyed by the
  base collector name. So a DNS-only CRIT left `dsd_check_status{check="network"} 0` even
  though `dsd_health_status` was `2` — a monitoring alert on the per-check series would
  silently miss it. The severity now rolls up to the base collector's metric. (Output is
  still valid Prometheus exposition format — verified with `promtool check metrics`.)

## [v0.9.0] — 2026-06-13

### Fixed

- **SELinux denial count no longer includes `avc: granted` records** — the
  audit-log and `ausearch` paths counted every `type=AVC` line, which includes
  `avc: granted` entries logged by `auditallow` policy rules, while the verdict (and
  the journald fallback) mean *denials*. On a system with `auditallow` rules this
  over-counted denials and could push the per-hour SELinux-denials verdict to WARN/CRIT.
  All paths now require `denied`. No change on the common case (no `auditallow` rules).
- **ufw SSH-reachability detection no longer mis-reads the port** — deciding whether the
  firewall lets SSH in (which drives the "firewall blocks SSH — lockout risk" warning),
  the ufw path matched `"22"` as a substring anywhere in `ufw status` and counted any
  `"allow"` regardless of which port it was on. So `2222/tcp ALLOW` made it think port 22
  was open, and a `22/tcp DENY` next to an unrelated allow rule read as reachable. Now it
  matches the SSH port against the rule's target column with proper boundaries and honors
  ufw's default-deny-incoming — consistent with the nft/iptables paths. Verified against
  real `ufw status` output.
- **An empty nftables ruleset no longer reads as an "active" firewall** — the nftables
  parser set the firewall's `Active` flag unconditionally, so a host with `nft` installed
  but **no rules** (`nft list ruleset` empty — common on minimal servers) had its firewall
  marked active, while the iptables path correctly required actual rules. Every consumer
  happened to also guard on the rule count, so this was a latent false-OK rather than a
  live one — but the field is now correct and consistent across both backends (active
  requires rules). Verified against real `nft list ruleset` output.
- **SSH duration parsing now handles the `d` (day) and `w` (week) units** — OpenSSH's
  time format (e.g. `LoginGraceTime`) accepts `s/m/h/d/w`, but the parser only knew
  `s/m/h`. It silently dropped `d`/`w`, which also concatenated the surrounding digits:
  `1d12h` parsed as "112h" (403200s) instead of 129600s, and `1w` as 1s instead of
  604800s. Now matches `sshd -T` normalization exactly (verified against real
  openssh-server). Affects the file-parse fallback path (`sshd -T` already emits
  normalized seconds); low practical impact since LoginGraceTime/ClientAliveInterval
  are rarely set in days/weeks, but it was a real correctness gap.
- **`dsd capture` redacts the hostname by default** — capture output is routinely
  committed to a repo (`fixtures/`) or pasted into a ticket, but it embedded the real
  hostname verbatim into the fixture's `host:` field and the "captured from …" comment.
  It's now replaced with `redacted-host` unless `--include-identity` is passed. Also
  scrubbed real private IPs that earlier (un-redacting) captures had already committed
  into shipped fixtures. (Same privacy posture as the planned `--share --include-identity`.)
- **`dsd health --blob` now says it's encoded, not encrypted** — the report block uses
  PGP-style `-----BEGIN DSD REPORT-----` markers and is opaque base64, but it's only
  gzip + base64 (anyone can `dsd decode` it) and carries the full unredacted report —
  hostname, IP/MAC addresses, open ports and processes, package and SMART data. A user
  could mistake it for an encrypted artifact and paste it somewhere public. The emit
  guidance now states it's "NOT encrypted or redacted — send through a trusted channel,
  don't post it publicly," and PRIVACY.md documents the shipped `--blob` flow (the
  redaction/encryption guarantees there describe the still-unbuilt `--share`, not `--blob`).
- **`dsd tips` / `dsd examples` no longer suggest commands that don't work** — the tip
  rotation told users to run `dsd health --badge` (errors with "unknown flag"),
  `dsd full` (errors with "unknown command"), and `dsd health --share` (a hidden,
  unimplemented stub that produces no share URL); `dsd examples` led its "share with
  team" entry with the same `--share` stub. These referenced backlog features that were
  never built. Replaced with working shipped features (`dsd cis --level 1`, `dsd tls
  --endpoint`, `dsd health --deep`, and a Markdown-report example) so every suggested
  command actually runs.
- **`dsd cron` OpenRC remediation is now fully runnable** — the "start crond" hint on
  Alpine/OpenRC rendered `sudo rc-update add crond && rc-service crond start`, but the
  single leading `sudo` only elevated the first command, so a non-root user copy-pasting
  it added crond to boot while `rc-service crond start` (which needs root) silently failed
  — crond not actually started. `sudo` now applies to each command:
  `sudo rc-update add crond && sudo rc-service crond start` (via `PlatformServiceCmdSudo`).
  Validated live on Alpine/OpenRC. (Completes the TRIAGE §A unrunnable-remediation class.)
- **Proxmox: an unreachable `pvesh` API no longer reads as a healthy node (false-OK)** —
  the PVE collector gated on the `pvedaemon` binary existing, then ran every check via
  `pvesh`. When the API was down (pmxcfs/pve-cluster stopped, not quorate) all queries
  failed silently, returning empty — and `collectPVECluster` treated a *failed* cluster
  query as "single-node, quorum implicitly OK". So a cluster node that had lost its API
  showed `dsd pve` → "✅ Proxmox VE healthy. Checks passed" and `dsd health` → green,
  with quorum reported OK. Confirmed on PVE 9.1 that a real standalone node returns the
  query successfully (exit 0), so the error path is purely failure. Now an `APIReachable`
  probe surfaces WARN "Proxmox VE API (pvesh) not responding — cluster/storage/backup
  health could NOT be verified" instead. Validated live (healthy + simulated-failure) on
  a real PVE host. (TRIAGE §E; false-OK class, mirrors the k8s-API-unreachable fix #210.)
- **`dsd net` now agrees with `dsd health` on packet loss, DNS latency, and TIME_WAIT** —
  three network verdicts used different thresholds in the detail command than in the
  health rollup. Gateway packet loss: `dsd net` escalated any drop to CRIT (1%/5%)
  while health used 10%/50% — since loss is sampled from only 2-3 pings (effectively
  0/33/50%), 10/50 is the meaningful granularity, so `dsd net` now matches it (a single
  dropped packet is WARN, not CRIT). DNS resolution: health was looser (WARN 200ms /
  CRIT 1000ms) than `dsd net` (100/500) — health now uses 100/500. TIME_WAIT: health
  had no CRIT tier, so 60k sockets read the same WARN as 1001 — it now escalates to
  CRIT at 5000, matching `dsd net`. All three route through shared
  `analysis.GatewayPacketLossLevel`/`DNSResolveLevel`/`TimeWaitLevel`. (TRIAGE §E; BUG-050 class.)
- **`dsd disk` / `dsd pve` now agree with `dsd health` on LVM and Proxmox storage** —
  four capacity verdicts were classified with different inline thresholds in the
  detail command than in the health rollup, so the same volume could read WARN in one
  and OK (or CRIT vs WARN) in the other: LVM thin pools (`dsd disk` warned at 70% vs
  health 80%), snapshots (70% vs 80%, and `dsd disk` showed CRIT at 90% vs health's
  95%), volume-group free space (`dsd disk` warned under 15% / CRIT under 5% free vs
  health 10% / 2%), and PVE storage (`dsd pve` 85/95% vs health 80/90%). All four now
  route through shared `analysis.LVM*Level`/`PVEStorageLevel` classifiers — one source
  of truth, same as the disk/ZFS thresholds fixed earlier. (TRIAGE §E; BUG-050 class.)
- **SteamOS: an unreadable `rauc status` no longer reads as a healthy A/B slot** —
  both RAUC slot-health checks were gated on `RAUCAvailable`, so when `rauc status`
  failed (D-Bus down, service dead, permission, parse error) the A/B update health
  — SteamOS's most important update-blocking signal — emitted nothing (silent OK).
  Now surfaces INFO "RAUC A/B slot health could not be verified".
- **Remediation hints now match the host platform** — fix/inspect commands were
  generated in their Linux/systemd form and shown verbatim everywhere, so on macOS
  `dsd` suggested `ss -tlnp` (which doesn't exist there) and on Alpine/OpenRC it
  suggested `systemctl` (no systemd). The diagnosis was always correct; only the
  remedy line was unrunnable. A platform-aware adapter now rewrites them: on macOS
  `ss -tlnp [| grep :PORT]` → `lsof -nP -iTCP[:PORT] -sTCP:LISTEN`; on OpenRC
  `systemctl restart/enable/disable X` → `rc-service`/`rc-update`. The same audit
  routed the remedy lines that `dsd docker`, `dsd cron`, `dsd kvm`, `dsd proc`, and
  the entropy/TLS correlation print directly (outside the insight pipeline) through
  one shared `analysis.PlatformServiceCmd` helper, so those were OpenRC-wrong too
  and now aren't. (TRIAGE §A; BUG-053, BUG-054.)
- **"SSH idle timeout not set" no longer fires on hosts with no sshd** — the check
  triggers on the *absence* of `ClientAliveInterval` (value 0), but 0 is also the
  zero-value when no sshd was audited at all, so a host without sshd was told to set
  a directive in a config it doesn't have. Now gated on `SSHAuditSource` (an sshd
  config was actually read). (TRIAGE §A minor.)
- **Packages: a failed security-update query no longer reads as "0 updates"** —
  when `dnf advisory`/`zypper list-patches`/`apt-get -s upgrade` errored (broken
  plugin, apt lock, permission), the collector returned 0 security updates with no
  status, and on a host with fresh package metadata the verdict stayed a silent
  clean OK. zypper was worst — its failure path literally set `Status: "OK"`. All
  three now report `query-failed` → INFO "could not verify security updates", not a
  clean bill of health.
- **Package integrity: a modified/tampered system file is no longer missed** —
  `rpm --verify` exits non-zero (and `dnf check` likewise for broken deps) while
  printing the findings to stdout, but the shared `runCmd` helper discarded stdout
  on any non-zero exit. So the integrity check only read output when the tool
  exited 0 — i.e. when there was nothing to report — and a tampered file on a
  RHEL/Fedora host produced no insight (silent OK). The integrity collector now
  captures stdout regardless of exit code (new `runCmdOutput` helper).
- **Security: an unreadable SSH config no longer reads as hardened** — when
  `sshd_config` exists but can't be read (non-root on RHEL/Rocky, where the file
  is mode 600 and `sshd -T` also needs root), the SSH directives stayed at their
  secure defaults and `dsd security`/`dsd health` reported SSH hardened having
  audited nothing. It now distinguishes "config unreadable" from "no SSH server"
  and surfaces INFO "sshd settings were NOT audited — re-run as root" instead of a
  silent OK.
- **`dsd tls`: an unreachable endpoint no longer reports "all healthy"** — a cert
  that couldn't be checked (unreachable remote endpoint, unreadable file) was
  counted in neither the CRIT/WARN/OK tally nor the exit code, so `dsd tls
  --endpoint down-host:443` printed "All 0 certificate(s) healthy" and **exited 0**
  — a cert-expiry monitor reporting success on a host it never reached (whose cert
  may be expired). `--json` was worse: the failed endpoint was dropped entirely
  (`0 expired, 0 expiring`). Now uncheckable certs are counted (`N ERR`, exit 1)
  and surfaced in `--json` as `uncheckable[]` with a `warning` status.
- **k8s: an unreachable cluster API no longer reads as a healthy cluster** — when
  `kubectl`/`k3s` is present but no cluster query succeeds (API server down, bad
  kubeconfig, or insufficient RBAC), every count stayed at zero and `dsd health`
  reported the cluster fine — a false-OK on the exact host where k8s is broken.
  It now tracks whether a query actually reached the API and surfaces
  "cluster health NOT verified" as INFO instead of a silent OK (matching how
  Docker/Ceph surface their unreachable states).
- **CVE scan: a failed apt scan no longer reads as "no CVEs"** — when both
  `apt-get --simulate upgrade`/`dist-upgrade` failed (apt lock held by
  unattended-upgrades, broken sources, or insufficient privilege), `dsd health
  --cve` parsed zero advisories and reported the system **clean** — a false sense
  of security on the most common Linux servers. apt now reports the failure (like
  the zypper/dnf paths already did), so a scan that couldn't run surfaces as INFO
  "CVE scan unavailable" instead of a green OK.

### Added

- **Release signing scaffold (minisign)** — `dsd update` can now verify that a
  release's `checksums.txt` was signed by the project key before trusting any hash
  in it, closing the self-updater single-origin gap (a compromised origin can
  serve a matching checksum but can't forge an Ed25519 signature). Verification is
  **in-binary** (stdlib + `x/crypto/blake2b`, no external tool) and **fails
  closed** once a key is embedded; `install.sh` adds a best-effort `minisign`
  check. The whole path ships **dormant** (like the Homebrew-tap job) until a
  maintainer generates a key and sets `MINISIGN_SECRET_KEY` — see
  `docs/RELEASE_SIGNING.md`. No behaviour change until then.

### Fixed

- **macOS: failing drives now surface, healthy drives stay quiet** — the `diskutil`
  SMART path had two faults: a `"Failing"` status was stuffed into an error field
  where the analysis layer *skips* it, so a dying Mac drive was silently hidden;
  and (after the SATA `SmartRead` guard) a healthy `"Verified"` drive was
  mis-labelled "SMART not read". Both darwin paths (`dsd health` + `dsd disk`) now
  share one verdict mapping: `Verified/Passed` → healthy, `Failing` → **CRIT**,
  `Not Supported`/unknown → "SMART not read" INFO.
- **SATA/SAS + `dsd hardware`: a drive whose SMART can't be read is no longer
  reported as failing** — `smartctl --json -a` emits JSON with **no `smart_status`**
  for drives behind RAID/HBA controllers, USB bridges, and virtual disks (common
  on cloud/VMware guests). The verdict then defaulted to "not passed" with no
  error, firing a false **CRIT** — `dsd health`: "drive may be failing"; `dsd
  hardware`: "may fail imminently, back up immediately" — on perfectly healthy
  drives. Both paths now track whether a verdict was actually read (`SmartRead`)
  and surface unread drives as **INFO** ("SMART health not read — behind a
  controller/bridge or virtual disk") instead of a confident CRIT. Brings SATA/SAS
  and `dsd hardware` in line with the NVMe path (BUG-048).
- **NVMe: a set `critical_warning` flag is no longer missed** — `nvme smart-log`
  prints `critical_warning` as hex (`%#x`, e.g. `0x4`), but the parser used
  `strconv.Atoi`, which can't read `0x…` and returned `0` — so a drive signalling
  spare-exhausted / reliability-degraded / read-only / backup-failed was reported
  **healthy** (`critical_warning` is *the* primary NVMe health flag). Now parsed
  base-0 (hex or decimal). Verified against the nvme-cli 2.13 format string.
- **NVMe/SMART: negative attribute values no longer read as a healthy drive** —
  the `nvme smart-log` and `smartctl -A` parsers assigned counts directly, so a
  garbled or hostile log printing e.g. `media_errors: -5` set a *negative* count
  — which slips under the `> 0` failure threshold in the analysis layer and reads
  as healthy (a false-OK). Both parsers now reject negative/garbled numbers.
  Found by the new `nvme`/`smartctl`/`rauc` fuzz harnesses (SSDLC Layer 2).
  NVMe key:value path of the `smartctl -A` parser assigned counts directly, so a
  garbled or hostile SMART log printing e.g. `Media and Data Integrity Errors: -5`
  set a *negative* `MediaErrors` count — which slips under the `> 0` failure
  threshold in the analysis layer and reads as healthy (a false-OK). The parser
  now rejects negative/garbled numbers (mirroring the SATA path's existing guard).
  Found by the new `smartctl`/`rauc` fuzz harnesses (SSDLC Layer 2).

### Security

- **Installer fails closed on unverifiable downloads** — `install.sh` previously
  *skipped* sha256 verification (silent warning, install continued) whenever
  `checksums.txt` couldn't be fetched, lacked an entry for the platform, or no
  hashing tool was present. An origin that simply withheld `checksums.txt` thus
  downgraded every install to unverified (threat model CLI **F-3**). The installer
  now **aborts** in those cases; the new `--no-verify` flag is the explicit, loud
  escape hatch for genuinely tool-less environments. A checksum *mismatch* still
  always aborts regardless of the flag. CI now guards the fail-closed path.

---

## [v0.8.7] — 2026-06-12

### Added

- **Checks reference (`docs/CHECKS.md`) + `dsd explain --markdown`** — a generated,
  browsable reference of all 36 checks (what each looks at, why it matters, how the
  verdict is decided, how to fix), so coverage is visible on GitHub without
  installing. A sync test keeps the doc from drifting from the topic registry;
  regenerate with `dsd explain --markdown > docs/CHECKS.md` (#197).

## [v0.8.6] — 2026-06-12

### Added

- **`dsd explain --search <keyword>`** — finds topics by content, not just name:
  `dsd explain --search memory` surfaces memory, swap, oom, docker, k8s, gpu, and
  sysctl. For "I'm seeing X, which check covers it?" when you don't know the topic
  name. Honors `--json` (#195).

## [v0.8.5] — 2026-06-12

### Added

- **`dsd explain` now covers 36 subsystems** — added oom, firewall, pve, bind,
  ceph, ipmi, bonding, and containerd, so the remaining commonly-flagged checks
  all have a "what it means / how it's judged / how to fix it" entry (#193).

## [v0.8.4] — 2026-06-12

### Added

- **`dsd explain --all`** — prints full detail for every topic in one pass; pipe
  it to a file for a complete checks reference (`dsd explain --all > checks.md`).
  Honors `--json`/`--plain`.
- **Tab-completion for `dsd explain`** — `dsd explain <TAB>` completes topic
  names (#191).

## [v0.8.3] — 2026-06-12

### Added

- **`dsd health --fix`** — after the verdict, prints a "Suggested fixes" block:
  the remediation commands for every flagged subsystem, grouped and deduped, as a
  copy-pasteable list. Completes the triage → understand → fix arc alongside
  `--explain`. Opt-in, so default output stays terse (#189).

## [v0.8.2] — 2026-06-12

The release that actually ships the SELinux path-guard security fix and the
prometheus output fix described in the v0.8.1 notes — both landed just after the
v0.8.1 tag, so v0.8.2 is the first built binary to contain them. Plus a CI
lint cleanup.

### Security

- **SELinux policy-type path hardening** — now shipped in a released binary. (Full
  detail under v0.8.1; in short: the filesystem path built from `SELINUXTYPE=` in
  `/etc/selinux/config` is charset-guarded before use. Root-owned config, so
  practical exploitability was low.)

### Changed

- **CI: golangci-lint gate is clean** — cleared 18 pre-existing issues so the
  stricter gate passes: removed dead, unreferenced helper funcs (and the
  single-func `fcntl_linux.go`); preallocated slices with known capacity; dropped
  ineffectual assignments; applied two staticcheck simplifications; and `nolint`'d
  two inherently-branchy parsers plus a gosec G703 on a host-local trusted crontab
  path (stat-only). Behaviour-preserving (#187).

### Docs

- `dsd examples` adds scenarios for understanding a finding (`dsd explain` /
  `--explain`), monitoring integration (`--nagios` / `--prometheus`), and watching
  an incident (`--watch`) (#184).

## [v0.8.1] — 2026-06-12

### Added

- **`dsd explain` now covers 28 subsystems** — added sysctl, entropy, fdlimits,
  thermal, kvm, lvm, raid, and nfs to the offline reference, so the common checks
  an operator gets flagged on all have a "what it means / how it's judged / how to
  fix it" entry (#182).

### Security

- **SELinux policy-type path hardening** — `dsd health`/security collection built
  a filesystem path from the `SELINUXTYPE=` value in `/etc/selinux/config` under a
  suppression that claimed allowlist validation the code did not actually enforce.
  The value is now charset-guarded before use. The config file is root-owned, so
  practical exploitability was low, but the guard is now enforced in code. As a
  side effect, distro-custom policy names (e.g. Debian's `default`) are handled
  correctly.

### Fixed

- Prometheus exposition output now uses `fmt.Fprintf` directly instead of
  `WriteString(fmt.Sprintf(...))` (no behavioural change; resolves two
  staticcheck warnings).

### Docs

- README documents the v0.7–v0.8 features: `dsd explain`, and the `dsd health`
  `--watch` / `--explain` / `--nagios` / `--prometheus` flags, with a
  monitoring-integration section (#181).

## [v0.8.0] — 2026-06-12

Monitoring integration and in-context explanations.

### Added

- **`dsd health --nagios`** — a single-line monitoring-plugin status on stdout
  (`DASHDIAG OK/WARNING/CRITICAL - …`) with the exit code already matching the
  Nagios spec (0/1/2). Drops dsd straight into Nagios/Icinga/check_mk/Sensu as a
  check command, no wrapper script. Each affected subsystem is named once at its
  worst level (#178).
- **`dsd health --prometheus`** — the verdict as Prometheus exposition metrics
  (`dsd_up`, `dsd_check_status{check="…"}`, `dsd_health_status`; severity 0/1/2)
  for node_exporter's textfile collector or scraping — chart and alert on host
  health in Grafana/Alertmanager. Output validated by `promtool check metrics`
  (#179).
- **`dsd health --explain`** — after the verdict, appends a "Why these matter"
  block explaining each flagged subsystem and how to fix it (from the `dsd explain`
  content). Opt-in, so default output stays terse (#177).

## [v0.7.0] — 2026-06-12

Two new capabilities — a live incident view and an in-tool reference.

### Added

- **`dsd explain <topic>`** — a plain-language reference for the health checks.
  `dsd explain swap` (or zfs, cve, drives, docker, k8s, …) prints what the check
  diagnoses, why it matters, how dsd decides severity (the real thresholds), and
  the commands to investigate and fix it; no argument lists the 20 topics, and
  aliases resolve (`ram`→memory, `zpool`→zfs, `kev`→cve). It is pure static
  documentation — it never touches the host — and `--json` is supported. Turns dsd
  from an alerter into a teacher: when health flags a subsystem, get the full
  picture in-tool (#174, #175).
- **`dsd health --watch` change detection** — each refresh now prints a "Changes
  since last refresh" block: 🆕 newly-broken, ✅ newly-resolved, and ↕ severity
  changes (WARN→CRIT), with "· no change" as a steady-state signal. Insights are
  matched across ticks by a value-normalized signature, so a fluctuating number
  (CPU 75%→82%) doesn't churn as resolved+new. The point of watch during an
  incident is the delta — now you see it (#173).

## [v0.6.15] — 2026-06-11

### Fixed

- **cve: apt no longer claims a CVSS verdict it can't measure.** apt publishes no
  per-package CVSS, so `dsd health --cve` inferred severity from the package name
  yet reported it as "critical advisory — CVSS >= 9.0" / "high-severity — CVSS >=
  7.0" — and a name guess (e.g. a routine `python3-*` or `libssl` update) could
  raise a hard CRIT. For apt, name-matched advisories now fold into a single
  honest WARN ("severity inferred from package name; apt exposes no CVSS", with a
  pointer to the distro security tracker) — no name-only CRIT, no fabricated CVSS
  claim. Package managers that expose real severity (dnf/zypper/…) are unchanged,
  and CISA KEV matches still escalate to CRIT (#171).

## [v0.6.14] — 2026-06-11

A batch of false-positive fixes — verdicts that fired on healthy hosts.

### Fixed

- **swap: no more false WARN on zram churn.** Swap-activity WARNed on *any*
  paging (`> 0` pages/s) and ignored zram. On zram-by-default distros
  (Fedora/Ubuntu/Pop!_OS/SteamOS) swapping is compressed-RAM churn, not disk
  thrash. The WARN floor is raised to 50 pages/s, and zram-backed paging below the
  heavy-thrash threshold is now INFO ("compressed RAM, not disk thrash"). Heavy
  paging (>100 pages/s) still CRITs; disk-backed swap keeps WARN/CRIT (#167).
- **drives: power-on-hours is age, not wear.** The NVMe (>35,000 h) and HDD
  (>43,800 h) power-on-hours checks WARNed about "consumer/HDD lifespan" — but
  hours run is not a failure signal, and the real endurance metrics
  (NVMe percentage-used/spare, SATA reallocated sectors, SMART self-assessment)
  are checked separately. A healthy long-lived enterprise drive no longer gets a
  false lifespan WARN; power-on-hours is now INFO context (#168).
- **zfs: no more perpetual CRIT on repaired vdev errors.** `zpool`'s cumulative
  read/write/checksum vdev counters include errors ZFS already repaired and
  persist until `zpool clear`, so one transient blip CRITed forever. Severity is
  now gated on actual pool health: an ONLINE pool with a clean last scrub is WARN
  ("repaired; investigate if recurring"), CRIT only when the pool is not ONLINE or
  the last scrub left unrepairable errors — real corruption is still caught (#169).

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
