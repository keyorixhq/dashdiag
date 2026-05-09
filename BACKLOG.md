# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-08
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: ✅ v0.1.1
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0)
Infrastructure: ✅ dependabot + issue templates + PR template + JSON schema
Branch protection: ✅ Active (Test ubuntu-22.04 + macos-14 required)
Linux testing: ✅ P1–P4 COMPLETE | macOS arm64: ✅ VALIDATED

---

## NOW — Launch prerequisites

- [ ] **Inline drill-down on WARN/CRIT** — when a check fires, show
      the relevant raw data (top 10 processes, largest dirs, failed
      units, etc.) inline rather than just hinting at a command.
      THE single biggest UX improvement before launch. Closes the
      "diagnose then explain" loop. Makes the demo GIF dramatically
      more compelling. ~1-2 weeks of focused work across all 12 checks.
      See "Customer journey & inline drill-down" section below.
- [ ] Decide and commit DashDiag license (Apache 2.0 recommended — see PRODUCT_IDEAS.md)
- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page + waitlist form)
- [ ] Write README.md (install command, quick start, demo output)
- [ ] Record demo GIF with vhs or asciinema (after drill-down ships)
- [ ] Add waitlist link to README, push
- [ ] Write Hacker News Show HN post draft
- [ ] Write CHANGELOG.md (v0.1.0 + v0.1.1 entries)
- [ ] Backup strategic documents off-laptop (gitignored, single-machine = risk)

---

## NEXT — After first HN post

### Features
- [ ] `dsd init` — wire into root.go so it runs on first launch
- [ ] `dsd health --share` — upload snapshot to dashdiag.sh (requires backend)
- [ ] `--report --out <file>` — save markdown report to file
- [ ] Shell completion: `dsd completion bash/zsh/fish` (cobra built-in, 5 min)

### Quality
- [ ] Golden file tests for all renderers (`go test ./internal/render/... -update`)
- [ ] Contract tests in `test/contract/` — validate JSON output against schema
- [ ] Coverage report: `make cover` — identify packages under 70%

### SDLC
- [ ] cosign key generation for release binary signing
- [ ] Homebrew formula (Formula/dsd.rb in a tap repo)
- [ ] Install script (install.dashdiag.sh — curl | sh)

### Testing (deferred)
- [ ] P2.8 Flatcar — requires registry authentication
- [ ] P5.1 Fedora 40, P5.2 Oracle Linux 9, P5.3 AlmaLinux 9
- [ ] AWS Graviton EC2 — real arm64 server hardware
- [ ] Raspberry Pi OS
- [ ] macOS Intel (x86_64) validation
- [ ] macOS stress suite — needs native macOS version (networksetup, pfctl, launchctl)
      Linux stress.sh uses tc/ip/systemctl — not portable to macOS

---

## LATER — Phase-gated (wait for the signal before building)

### Gate: dsd health is in daily use by real engineers
- [ ] `dsd health deep` — per-core CPU, temperature, throttle detection

### Gate: first GitHub issue requesting containers
- [ ] `dsd docker` — container health, restart counts, OOM kills

### Gate: dsd docker in production use
- [ ] `dsd compare` — multi-server side-by-side comparison (FEATURES.md F2)
- [ ] `dsd policy` — YAML policy file, CI gate (FEATURES.md F1, F3)

### Gate: 3+ users request configurable thresholds
- [ ] Configurable thresholds via config file (~/.dsd/config.yaml)
      Defer until 3+ users request it. Keep minimal scope:
      override specific thresholds, defaults applied otherwise.
      Connects to policy-as-code (FEATURES.md F1, F3) when built.
      See KEYORIX_FOUNDATION.md §6 — defaults, not configuration.

### Gate: AI ops integration becomes priority (~year 2)
- [ ] `dsd mcp` — MCP server subcommand for AI assistant integration
      DashDiag's --json output is already AI-ready. Wrap as MCP server
      so Claude/Cursor/etc. can call dsd_health(), dsd_diff() etc. directly.
      ~1 week of work. Don't market heavily — let it be discovered.
      See PRODUCT_IDEAS.md §0 — portfolio MCP layer.

### Gate: Phase 3 validated
- [ ] `dsd logs` — journald aggregation, recurring error detection
- [ ] `dsd security` — SSH config, sudo, listening ports

### Gate: dsd docker validated
- [ ] `dsd k8s` — 8 failure modes (OOMKilled, CrashLoop, Evicted, etc.)
- [ ] `dsd k8s deep` — BestEffort QoS, CPU throttling

### Gate: Phase 4 validated
- [ ] `dsd pve` — Proxmox VE (cluster, ZFS, guests, kernel version)

### Gate: backend live
- [ ] `--badge` — README shields.io badge
- [ ] `dsd fleet` — enterprise multi-server management
- [ ] `--share` 90-day retention

### Gate: 10+ paying teams
- [ ] UnpackOps RCA platform

### Gate: UnpackOps RCA validated
- [ ] Gauge (FinOps product)

### Strategic docs (see private gitignored files)
- KEYORIX_FOUNDATION.md — philosophy, audience, method
- POSITIONING.md — brand, voice, messaging
- STRATEGY.md — 5 monetization paths
- FEATURES.md — 11 enterprise features ranked by enterprise pull
- LAUNCH_PREP.md — README/GIF/HN post sequence
- PRODUCT_IDEAS.md — xwan, future products, acquisition lens

---

## BUGS / KNOWN ISSUES

### In progress
- [ ] macOS swap threshold producing false WARNs (sent to Claude Code 2026-05-08)
      Platform-aware thresholds: Linux 20%/50%, macOS 75%/90% gated by
      memory pressure (sysctl kern.memorystatus_vm_pressure_level)

### Known limitations (not bugs)
- CPU stress: FAIL on busy machines — mitigated by baseline skip + cores*2 spinners
- IO stress: no iostat in Colima Lima VM — graceful skip expected
- Flatcar: registry access denied — deferred
- macOS: clock OffsetMs always -1 (by design — no offset API without sudo)
- Any container: Systemd Available=false (by design)
- Memory WARN in 512MB containers — slab cache threshold fires (expected)

### Pre-existing
- [ ] `--qr` shows empty QR (shareURL stub)
- [ ] `dsd health --weekly` needs 7 days of data
- [ ] `dsd services` empty state needs real config testing

---

## BUGS FIXED

### macOS validation (2026-05-08)
- [x] Disk CRIT /dev (devfs) — macOS virtual filesystem false positive
      Fix: exclude devfs and /System/Volumes/* from disk collector
- [x] Clock CRIT on macOS — timedatectl/chronyc not available
      Fix: check timed daemon running (macOS time sync service)
- [x] Sysctl CRIT net.core.somaxconn — Linux-only sysctl on macOS
      Fix: skip somaxconn check on darwin
- [x] Processes WARN zombie false positive on macOS
      Fix: use ps axo pid,stat on darwin, check only stat column for Z
- [x] Swap/Memory hints wrong on macOS (free -h, vmstat don't exist)
      Fix: macOS-appropriate hints (vm_stat, sysctl vm.swapusage, top -l 1)
- [x] MACPolicy collector renamed to KernelSecurity
      MAC abbreviation collided with macOS naming — confused users on Mac

### P1.3 Colima + Docker distro sweep (2026-05-08)
- [x] Clock CRIT in all containers — inherit host clock fix
- [x] Disk CRIT /mnt/lima-cidata — Lima metadata disk excluded
- [x] Systemd CRIT cloud-final.service — cloud-init services excluded

### P1.2 Proxmox + raw data (2026-05-08)
- [x] raw:{} empty in JSON — all 12 collectors serialise raw data
- [x] stress.sh IO: writes to / on LVM, CPU cores*2, Swap 150% free RAM
- [x] run_stress.sh: conditional sudo for root-only environments

### P1.1 Ubuntu 24.04 — Sessions 1+2 (2026-05-08)
- [x] 25 bugs fixed — see git log for full details

---

## IDEAS

- Prometheus exporter: `dsd export metrics`
- `dsd health --since 2h` — diff against N hours ago
- Man page generation from cobra docs
- Slack webhook: `dsd health --notify-slack $WEBHOOK_URL`
- `dsd health --threshold cpu_warn=90` — per-run threshold overrides
- Structured logging in --debug mode
- `dsd how "check if a port is open"` — built-in command lookup mode
   (replaces cheat sheets — reinforces "burn the cheat sheet" positioning)
- Conntrack table saturation check — read /proc/sys/net/netfilter/nf_conntrack_count
   vs nf_conntrack_max. When the table fills, new connections silently fail.
   Common cause of "the network feels slow but I can't tell why" on systems
   with iptables/nftables. Belongs in the Network check, deferred until
   F0 attribution work is done.
- DNS resolver attribution — slow or failing DNS lookups attributed to
   specific upstream nameservers. Often the actual cause of "the app is slow"
   is one upstream resolver being slow. Read /etc/resolv.conf, time queries
   to each, attribute slowness. Belongs in the Network check.
- Per-connection TCP diagnostics — parse `ss -tno state established` for
   timer info, retransmit counts, send/recv queue depths. Detects:
   high retransmit count = packet loss to specific peer (network problem,
   not app); send queue persistently > 0 = receiver overwhelmed (downstream
   congested); recv queue persistently > 0 = local app reading too slowly
   (consumer bug). Per-connection attribution, very actionable.
- Upstream connectivity check (opt-in via `--check-upstream` flag) — TCP
   connect to 8.8.8.8:53 and 1.1.1.1:53, measure handshake time. Both slow
   = real internet problem; one slow other fast = specific path issue.
   Opt-in because external probing changes DashDiag's character (it's no
   longer purely local diagnostic). Sysadmins should consciously decide.
- Pre/post-deploy diff (FEATURES.md F1) — capture baseline, diff after deploy
- Multi-env compare (FEATURES.md F2) — diff prod vs staging system state
- GitHub Action for PR checks (FEATURES.md F3) — block merges on CRIT
- Drift detection (FEATURES.md F4) — daily snapshots, trend analysis
- Approval workflow (FEATURES.md F5) — Slack-mediated risky-change approval

---

## DECISIONS LOG

2026-05  Rejected: AI flag in collectors — deterministic by design
2026-05  Rejected: Persistent TUI dashboard — btop/lazydocker/k9s exist
2026-05  Rejected: RPG achievements — too gamey for DevOps/SRE audience
2026-05  Rejected: Speed tier differentiation — runs locally, no server queues
2026-05  Deferred: Watermarks on --share — engineers would remove them
2026-05  Renamed: MACPolicy → KernelSecurity (macOS naming collision)
2026-05  Decided: Defaults over configuration — see KEYORIX_FOUNDATION.md §6

---

## HOW TO USE THIS FILE

When you complete a NOW item: mark [x], pull from NEXT if NOW empties, commit.
When you find a bug: add to BUGS, escalate to top of NOW if blocking.
When someone requests a feature: add to IDEAS first, promote only after planning.
When a phase gate opens: move from LATER to NEXT (never directly to NOW).
Weekly review: 5 minutes — NOW accurate? anything stuck? Ideas to promote?

---

## Customer journey & inline drill-down (reference for NOW item #1)

### The problem

DashDiag currently tells the user **what's wrong** and gives a hint
about **what command to run next**. The user must:

1. Read the hint
2. Copy the command
3. Run it manually
4. Interpret the output themselves
5. Repeat for each issue

That's better than nothing but still passes cognitive load to the user.
The Keyorix philosophy says: if DashDiag knows the command to run,
DashDiag should run it and show the result.

### The four-step customer journey

The strongest version of DashDiag closes the loop:

1. **Detect** — what's wrong (current capability)
2. **Explain** — show the data that proves it (Feature 1, this item)
3. **Contextualize** — show how it changed over time (Feature 2 = F4 drift, deferred)
4. **Hypothesize** — suggest root causes (separate product, UnpackOps RCA)

Right now we're at step 1.5. Step 2 is the highest-value next move
because it absorbs the most cognitive load for the lowest engineering
cost.

### What inline drill-down looks like

```
Memory       ❌  RAM at 94% (1.2 GB free of 16 GB)
   Top processes by memory:
   PID    MEM%  RSS    COMMAND
   12345  31.4  5.0GB  /opt/postgres/bin/postgres
   23456  18.2  2.9GB  /opt/elasticsearch/bin/java
   ... (5 more)

CPU          ⚠️  CPU usage at 87% sustained for 3 minutes
   Top processes by CPU:
   PID    CPU%  COMMAND
   12345  45.2  /opt/postgres/bin/postgres -D /var/lib/postgres
   23456  18.7  python3 /opt/etl/process_orders.py
   ... (5 more)
```

User sees the cause inline. No copy-paste cycle. No "let me Google
this command" detour. Information arrives where attention already is.

### Per-check drill-down spec

Each check that fires WARN or CRIT auto-collects relevant context.
The principle is **attribution relative to the limit being hit**, not
just absolute values. Showing "process X is at 980/1000 FDs" is more
useful than "process X has 8000 FDs."

| Check          | Auto-collect on WARN/CRIT |
|----------------|---------------------------|
| CPU            | Top 10 processes by CPU%, plus user vs kernel CPU breakdown |
| Memory         | Top 10 processes by RSS |
| Swap           | Top 10 processes by VmSwap (from /proc/PID/status on Linux) |
| Disk           | Top 5 largest directories on the affected mount, plus recently-grown files (mtime within 24h) |
| IO             | Top 5 processes by combined read+write bytes/sec (from /proc/PID/io on Linux) |
| Network        | TCP states by process: TIME_WAIT pileup (port exhaustion risk), CLOSE_WAIT leak (app bug), stuck SYN_SENT/SYN_RECV. Plus failed DNS lookups. Plus gateway ping latency/jitter (20 samples, ~4s, avg/stddev/loss). |
| Processes      | Zombie processes with their PARENT process info (parent is the actual offender) |
| Systemd        | Last 20 lines of journalctl for failed units |
| FDLimits       | Top 10 processes by FD usage as % of their individual limit |
| Clock          | Output of chronyc tracking or platform equivalent |
| Sysctl         | Current value vs recommended for failing settings |
| KernelSecurity | Which AppArmor profiles in complain mode, which SELinux booleans off |

**Platform notes:**
- Linux: full attribution available via /proc filesystem
- macOS: per-process swap attribution not available (no public API), fall back to top-by-RSS
- macOS: FD attribution via lsof, slower than Linux's /proc but works
- macOS: I/O attribution via fs_usage or limited; show platform note if not available
- Non-root users: show what's accessible, note that some processes may be hidden

**What attribution does NOT solve:**
Attribution shows WHICH process. It doesn't explain WHY the process is
doing what it's doing. That's UnpackOps RCA territory (separate product).
Stay in attribution lane for DashDiag.

Example: "postgres is using 5GB of swap" is attribution (good for DashDiag).
"Postgres is using 5GB of swap because shared_buffers is misconfigured" is
causation (UnpackOps RCA territory, not DashDiag).

### Suggested data structure

Each check exposes a `Details` field in its JSON output. CLI renderer
shows it inline. JSON consumers get structured data. Hints stay as
fallback for users who want to dig deeper.

```json
{
  "name": "Memory",
  "status": "CRIT",
  "message": "RAM at 94% (1.2 GB free of 16 GB)",
  "details": {
    "type": "process_table",
    "title": "Top processes by memory",
    "columns": ["PID", "MEM%", "RSS", "COMMAND"],
    "rows": [
      ["12345", "31.4", "5.0GB", "postgres"],
      ["23456", "18.2", "2.9GB", "java"]
    ]
  },
  "hints": [
    "ps aux --sort=-%mem | head -10",
    "vmstat 1 5"
  ]
}
```

### Implementation notes

- Drill-down only runs when status is WARN or CRIT (don't slow down OK case)
- `--terse` flag for users who want only the verdict (preserves current behavior)
- JSON output always includes details (machine consumers can choose to ignore)
- Each collector implements its own drill-down — no central drill-down engine
- Keep drill-down output capped (top 10, not top 100) to avoid wall of text
- macOS and Linux use platform-appropriate commands internally

### Why this matters for launch

The current launch GIF would show: check fires → hint command → end.
With drill-down: check fires → cause appears inline → user understands.

That's a dramatically stronger first impression for HN. The "wow" moment
moves from "neat, it tells me what to run next" to "wait, it just told
me which process is the problem."

This is the feature that distinguishes "another diagnostic tool" from
"the tool engineers actually use."

### Why we're NOT building features 3 and 4 right now

**Feature 2 (drift detection)** is already in FEATURES.md as F4. Defer
until post-launch — requires persistent storage, comparison logic, and
benefits from real user feedback first.

**Feature 3 (causal explanation)** is UnpackOps RCA territory. Building
it into DashDiag would betray the Keyorix philosophy — DashDiag's
essential thing is "diagnose what's wrong with this server right now."
Cross-signal inference is a different essential thing and deserves its
own product.

---

## Network connection state diagnostics (reference for F0 Network check)

The Network check in F0 covers more than just "is the network up." It
diagnoses the four most common pathological TCP connection patterns,
each of which has a distinct cause and resolution.

### TIME_WAIT pileup

**What it means:** TCP closes a connection by holding the originating
socket in TIME_WAIT for ~60 seconds (2MSL timeout). This prevents stray
packets from a previous connection being misinterpreted by a new
connection on the same port pair.

**The failure mode:** Heavy short-lived connection load (web servers
without keep-alive, aggressive HTTP clients) accumulates TIME_WAIT
sockets by the thousands. The system runs out of source ports
(default range ~28K). New outbound connections start failing with
EADDRINUSE.

**Detection:** Count sockets in TIME_WAIT state, attribute to local
process/port via `ss -tnp state time-wait`.

**Thresholds:**
- WARN at 10,000 total TIME_WAIT
- CRIT at 30,000 (port exhaustion likely imminent)

**Common causes:**
- HTTP client without connection pooling
- Reverse proxy without upstream keep-alive
- Database client without persistent connections

### CLOSE_WAIT leak

**What it means:** Remote end closed the connection (sent FIN). Local
socket sits in CLOSE_WAIT waiting for the local application to call
`close()`. If the application has a bug and never closes the socket,
it stays in CLOSE_WAIT forever.

**The failure mode:** Application bug — missing `defer conn.Close()`,
missing `try/finally`, connection pool not releasing. Eventually
exhausts file descriptors.

**Detection:** Count sockets in CLOSE_WAIT state per-process via
`ss -tnp state close-wait`.

**Thresholds:**
- WARN at 200 CLOSE_WAIT for any single process
- CRIT at 1000 (almost certainly a bug, FD exhaustion approaching)

**Diagnostic value:** This is one of the most useful detections because
CLOSE_WAIT pileup is almost always a real bug, not a config issue. The
process attribution tells the user exactly which application to fix.

### Stuck SYN_SENT / SYN_RECV

**What they mean:**
- SYN_SENT: We sent SYN, never got SYN+ACK back. Typically a firewall
  silently dropping packets, or destination is down.
- SYN_RECV: We received SYN, sent SYN+ACK, never got the final ACK.
  Typically a SYN flood attack or misconfigured client.

**The failure mode:**
- High SYN_SENT to specific destinations = network connectivity problem
  (firewall, routing, destination down)
- High SYN_RECV without corresponding ESTABLISHED = either DDoS or
  client-side problem

**Detection:** Count sockets by state via
`ss -tnp state syn-sent` and `ss -tnp state syn-recv`.

**Thresholds:**
- WARN on SYN_SENT > 100 sustained
- WARN on SYN_RECV > 1000 (possible attack or load issue)

### What we're NOT trying to detect (yet)

- **Stale ESTABLISHED connections** (zero bytes for hours) — harder to
  detect cheaply, less actionable. Defer to v2.
- **Per-destination breakdown** — useful for security audits but
  belongs in `dsd security`, not health check.
- **Bandwidth per process** — requires nethogs or similar, often not
  installed, expensive to compute.
- **UDP error rates** — possible but less critical than TCP issues.
  Defer.

### What this gives users

```
Network      ⚠️  unusual connection patterns
   TIME_WAIT:    14,832 (high — port exhaustion possible)
   CLOSE_WAIT:   847 (likely application bug)

   Top processes with CLOSE_WAIT (likely socket leak):
   PROC                     CLOSE_WAIT  CMD
   python3[8423]            612         /opt/etl/scrape_orders.py
   nginx[7891]              198         /usr/sbin/nginx (worker)

   Top processes with TIME_WAIT:
   PROC                     TIME_WAIT   CMD
   nginx[7891]              12,400      /usr/sbin/nginx
   redis-cli[multiple]      1,800       short-lived connections

   → ss -tnp state close-wait
   → ss -s
```

That answers four questions in one screen:
1. Is something weird happening? Yes.
2. Which patterns? CLOSE_WAIT and TIME_WAIT both elevated.
3. Which process? python3 ETL job leaking sockets, nginx with TIME_WAIT pile-up.
4. What do I look at? Either fix the ETL bug, or tune nginx keep-alive.

That's actionable diagnosis. That's what distinguishes "another diagnostic
tool" from "the tool engineers actually use."

### Architectural note: active probing vs passive reading

DashDiag is starting to do **active probing** (sending packets, measuring
responses) in addition to **passive reading** (parsing kernel state).
These have different tradeoffs and should be visually distinguished in
output.

**Passive reading** (current approach for most checks):
- Cheap, fast, no external impact
- No permission issues, deterministic
- Just reads what the kernel already knows

**Active probing** (gateway ping, TCP-connect, DNS query):
- Costs wall time (4s for 20 ping samples)
- May require capabilities (cap_net_raw for ICMP)
- Changes external state slightly (creates packets)
- Results vary with external conditions

**Keyorix design rule for probing:**

Be opinionated about what to probe but make it visible. Don't probe
silently. Show the user what was measured and why.

For F0:
- Gateway ping latency/jitter: always run on Network WARN/CRIT
   (cheap, local, high value, no external dependency)
- Upstream connectivity probe: opt-in only via `--check-upstream`
   (deferred to post-launch idea)

If a user wants the fastest possible health check during an active
incident, future `--quick` flag could skip all active probing. But
default behavior includes the gateway ping because it's the difference
between "Network OK" and "Network OK with confirmed local connectivity."
