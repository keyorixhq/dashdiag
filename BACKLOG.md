# DashDiag — Backlog
# ─────────────────────────────────────────────────────────────────────────────
# Three sections: NOW (do this week) · NEXT (after NOW is done) · LATER (gated)
# Rule: NOW never has more than 10 items. When it empties, pull from NEXT.
# Update this file every time you complete something or discover something new.
# ─────────────────────────────────────────────────────────────────────────────

## STATUS
Last updated: 2026-05-10
GitHub: ✅ PUBLIC — github.com/keyorixhq/dashdiag
Tag: ✅ v0.1.1 (v0.2.0 ready to tag — F0 verified end-to-end)
Code quality: ✅ CLEAN (golangci-lint + gosec + govulncheck all 0)
Infrastructure: ✅ dependabot + issue templates + PR template + JSON schema
Branch protection: ✅ Active (Test ubuntu-22.04 + macos-14 required)
Linux testing: ✅ P1–P4 + Fedora 40 arm64 | macOS arm64: ✅ VALIDATED
F0 inline drill-down: ✅ SHIPPED + FULLY VERIFIED 2026-05-10
   - 9/12 checks drilldown verified in Docker (CPU, Memory, Processes, IO, Disk,
     FDLimits, Network, Sysctl — all pass; 3 bugs fixed this session)
   - 4 checks deferred to VM: Swap, Systemd, Clock, KernelSecurity (env limits)
   - Drilldown bug fixed: renderer now respects ModePlain (Docker, CI, pipes)

---

## NOW — Launch prerequisites

- [x] **Inline drill-down on WARN/CRIT** ✅ SHIPPED 2026-05-09
      See "F0 shipped" section in BUGS FIXED for full implementation details.
- [x] ✅ **F0 drilldown not firing end-to-end** — RESOLVED 2026-05-10.
      Root cause was NOT a stale binary (as initially suspected). The
      drilldown data was populated correctly by drilldown.PopulateAll all
      along. The bug was in the renderer:
      
        internal/render/health.go gated drilldown table rendering on
        `r.mode == output.ModeHuman`, but output.DetectMode returns
        ModePlain whenever stdout is not a TTY — which is always the case
        in Docker without -t, CI/CD pipelines, shell pipes, and any
        redirected output.
      
      Fix: extended the render condition to `ModeHuman || ModePlain`.
      Lipgloss strips ANSI codes automatically in non-TTY contexts, so
      renderDetails already produced clean plain text — just needed to
      be allowed to run in ModePlain.
      
      Verified in Fedora 40 ARM64 docker:
      - Terminal mode: Memory CRIT shows "Top processes by memory (RSS)"
        table inline with PID/MEM%/RSS/COMMAND columns
      - --json mode: details field present with type "process_table",
        full columns and rows (was unaffected — JSON skips PrintAll entirely)
      
      Lesson: integration testing in production-like environments (Docker
      without -t, CI runners, redirected output) catches bugs that unit
      tests and interactive Mac terminal testing both miss.
- [ ] ~~JSON output contaminated with progress logs~~ — FALSE ALARM. The test
      command used `2>&1` which merged stderr into stdout. Code in
      internal/output/progress.go correctly uses fmt.Fprintf(os.Stderr, ...)
      for all progress messages. Without `2>&1`, JSON output is clean.
- [ ] Decide and commit DashDiag license (Apache 2.0 recommended — see PRODUCT_IDEAS.md)
- [ ] Register dashdiag.sh domain
- [ ] Build dashdiag.sh landing page (single page + waitlist form)
- [ ] Write README.md (install command, quick start, demo output)
- [ ] Record demo GIF with vhs or asciinema (after drill-down ships)
- [ ] Add waitlist link to README, push
- [ ] Write Hacker News Show HN post draft
- [ ] Write CHANGELOG.md (v0.1.0 + v0.1.1 entries)
- [ ] Backup strategic documents to private GitHub repo
      (keyorixhq/strategy, private). Today.
      See "Strategy backup setup" section at bottom of this file
      for the 5-minute setup commands and ongoing sync workflow.
      Risk: 8 documents (~3000 lines) currently exist only on one laptop.

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

### F0 drilldown — full check coverage verified (2026-05-10)

Verified all testable checks fire their drilldown in Docker (Fedora 40 ARM64).
Three bugs found and fixed in this session.

**Verification results:**

| Check          | Triggered | Drilldown fired | Content valid | Notes |
|----------------|-----------|-----------------|---------------|-------|
| CPU            | YES CRIT  | YES             | YES           | bash busyloops, 2 pinned CPUs, 122% load |
| Memory         | YES CRIT  | YES             | YES           | verified 2026-05-10 (overcommit threshold) |
| Processes (zombie) | YES WARN | YES           | YES           | verified 2026-05-10 |
| Processes (hung) | YES WARN | YES (FIXED)    | YES (FIXED)   | was routing to ZombiesWithParent — now HungProcesses() |
| IO             | YES WARN  | YES (FIXED)     | YES           | empty table bug fixed; verified with active DNF I/O |
| Disk           | YES CRIT  | YES (FIXED)     | YES (FIXED)   | root files now visible — fixed per-child du -sh |
| FDLimits       | YES WARN  | YES             | YES           | Python opens 1024/1024 FDs |
| Network        | YES WARN  | YES             | YES           | 160 CLOSE_WAIT via Python socket pairs |
| Sysctl         | YES CRIT  | YES             | YES           | sysctl -w net.core.somaxconn=128 |
| Swap           | NO        | N/A             | N/A           | deferred — no swap in Docker, needs VM |
| Systemd        | NO        | N/A             | N/A           | deferred — no real systemd in container |
| Clock          | NO        | N/A             | N/A           | deferred — needs NTP manipulation or broken sync |
| KernelSecurity | NO        | N/A             | N/A           | deferred — needs SELinux enforcing with denials |

**Bugs fixed:**

1. **Processes hung drilldown mismatch** (`drilldown/processes.go` + `drilldown/drilldown.go`):
   When Processes fired for "hung (uninterruptible)" the dispatch called
   `ZombiesWithParent`, returning a zombie table (empty, wrong title).
   Fix: added `HungProcesses()` that scans for state=="D"; dispatch routes
   messages containing "hung" or "uninterruptible" to it.

2. **IO drilldown empty table** (`drilldown/io.go`):
   When IO fired from a transient latency spike but the 500ms per-process
   sample captured no active I/O, the drilldown returned empty rows.
   Renderer printed only the title ("Top processes by I/O:") with no content.
   Fix: set `d.Note = "no active I/O detected in sampling window"` when rows==0,
   so the note renders instead of a dangling title.

3. **Disk drilldown misses large files at mount root** (`drilldown/disk.go`):
   `du --max-depth=1 /mount` lists subdirectories only; a large file at the
   root (e.g. 87MB fill file) was invisible — only `lost+found` at 12K showed.
   Fix: switched to `os.ReadDir(mount)` + per-child `du -sh <full-path>` which
   includes both files and directories in the listing.

**Deferred (not bugs, need VM-based testing):**
- Swap drilldown: no swap available in Docker containers typically.
  To test: bare metal / VM with swap configured, run stress-ng --vm.
- Systemd drilldown: requires real systemd; Docker containers use init.
  To test: Fedora/Ubuntu VM, systemctl stop <service>, run dsd.
- Clock drilldown: requires actual NTP drift.
  To test: VM with chrony/ntpd installed, disconnect from NTP source.
- KernelSecurity drilldown: requires SELinux in enforcing mode with denials.
  To test: Fedora/RHEL VM with selinux=enforcing and a policy violation.

**v0.2.0 proposal:** All testable drilldowns verified + 3 bugs fixed.
Deferred items are environment constraints (no systemd, no swap, no SELinux
in containers), not code bugs. Safe to tag v0.2.0 once release artifacts
(CHANGELOG, README) are ready.

---

### Fedora 40 ARM64 — basic compatibility confirmed (2026-05-10)

Tested in docker container `fedora:40` with `--privileged -v PWD:/dashdiag`.
Installed `procps-ng iproute systemd jq stress-ng` via dnf. All 12
collectors ran without crashes. Wall time ~1.3s. Output format clean.

This means RHEL 9 family (Rocky, Alma, RHEL itself) and Fedora 40+
should all work — same kernel family, same systemd version range,
same /proc layout. P5.1 Fedora can be marked validated.

Two issues surfaced during this test (now in NOW section):
- F0 drilldown not firing end-to-end (regression from today's ship)
- JSON output contaminated with progress logs

Neither is Fedora-specific — they appear on every Linux distro.
Fedora just happened to be the test bed where they were caught.

### F0 — Inline drill-down shipped (2026-05-09)

All 12 checks now produce inline attribution on WARN/CRIT. Healthy
systems unchanged — drilldown code never runs on OK checks.

**New files:**
- `internal/models/insight.go` — Details struct added to Insight
  (Type, Title, Columns, Rows, KV, Note)
- `internal/drilldown/drilldown.go` — PopulateAll dispatcher +
  shared helpers (walkProcs, runCmd, formatBytes, mount/unit parsers)
- `internal/drilldown/memory.go` — /proc/PID/status VmRSS on Linux,
  ps on macOS
- `internal/drilldown/cpu.go` — double-sample for accurate CPU%
- `internal/drilldown/swap.go` — /proc/PID/status VmSwap on Linux;
  nil+note on macOS (no public API)
- `internal/drilldown/disk.go` — du --max-depth=1 (macOS: -hd 1)
  with os.ReadDir fallback
- `internal/drilldown/io.go` — double-sample /proc/PID/io with 500ms
  gap on Linux; nil+note on macOS
- `internal/drilldown/network.go` — ss -tnp with /proc/net/tcp
  fallback on Linux, netstat on macOS
- `internal/drilldown/processes.go` — /proc/PID/stat zombie+parent
  lookup on Linux, ps on macOS
- `internal/drilldown/systemd.go` — journalctl -u <unit> tail
- `internal/drilldown/fdlimits.go` — /proc/PID/fd + /proc/PID/limits
  on Linux, lsof on macOS
- `internal/drilldown/clock.go` — chronyc tracking / timedatectl on
  Linux, sntp on macOS
- `internal/drilldown/sysctl.go` — /proc/sys/ reads with
  recommended-value table
- `internal/drilldown/kernelsec.go` — aa-status + getsebool on Linux

**Modified files:**
- `cmd/health.go` — wires drilldown.PopulateAll(ctx, insights,
  results) after ApplyThresholds; adds --terse flag (skips drilldown)
- `render/health.go` — renderDetails() prints tabular rows or KV
  pairs indented under the check line (ModeHuman only)
- `render/json.go` — JSONInsight.Details *models.Details propagated
  from insight (backward-compatible: field is omitempty)

**Behaviour summary:**
- Healthy: no drilldown, wall time unchanged (~1.3s)
- WARN/CRIT: attribution inline, <2s typical
- `--terse`: skips drilldown even on WARN/CRIT (minimal output)
- `--json`: always includes Details when present

**Next step:** Test on a real system with actual WARN/CRIT firing to
verify output format, indentation, and table rendering look right
before tagging v0.2.0.

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
- `dsd how "check if a port is open"` — built-in command lookup mode.
   The strategic insight: generic cheat sheets (like the giant Linux
   command mouse pads engineers buy) are useless during incidents. They
   contain commands you'd already know if you used them daily, and lack
   commands you'd need precisely when something unfamiliar is broken.
   They serve as PLACEBO COMPETENCE — make engineers feel less anxious
   without solving the underlying problem.
   
   DashDiag is uniquely positioned to do better because it knows what's
   wrong AND knows what commands are available on this specific system.
   No cheat sheet can do this. No Stack Overflow answer can. Even AI
   assistants don't know your specific system without DashDiag's data.
   
   Example interactions:
     dsd how "check firewall rules"
     → Detects nftables vs iptables vs ufw via systemctl + which
     → Suggests the right command for THIS system
     → Cross-references to dsd net for automatic diagnosis
   
     dsd how "find process holding a port"
     → Suggests ss -tnlp on Linux with iproute2
     → Falls back to lsof -i if iproute2 not present
     → Falls back to netstat -tnlp on RHEL 6 / minimal containers
   
   Replaces cheat sheets entirely. Reinforces "burn the cheat sheet"
   positioning. High strategic value, medium build cost (~2-3 weeks
   for v1 with ~50 common queries).
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
- Wall time per check: 10-200ms

**Active probing** (gateway ping, TCP-connect, DNS query):
- Costs wall time (4s for 20 ping samples)
- May require capabilities (cap_net_raw for ICMP)
- Changes external state slightly (creates packets)
- Results vary with external conditions
- Wall time per probe: 1-10 seconds

**Wall time matters for UX:**

Current `dsd health` runs in ~1.3s — fast enough that engineers don't
break flow when running it during incidents. Adding a 4s gateway ping
to every run would triple wall time. That's a meaningful UX cost.

**Keyorix design rule for probing — tiered execution:**

> Match wall time to user intent. Healthy = fast. Broken = thorough.

```
Default `dsd health` — passive checks only, ~1.3s
├── If everything OK → done (no wall time penalty for healthy systems)
├── If WARN/CRIT detected → run inline drill-down
│   ├── Process attribution (cheap, <100ms)
│   ├── Connection state analysis (cheap, <200ms)
│   └── Active probes only for the failing check
│       └── Network failed → gateway ping (4s)
│       └── Disk failed → recently-grown files scan
│       └── (Each check decides its own probing budget)
```

User mental model this matches: "if it's healthy I want to know fast;
if it's broken I want to understand why."

**Future flags (not v0):**
- `--quick` — force passive-only mode even on WARN/CRIT
   (incident response: skip probes when you already know the problem)
- `--deep` — run ALL probing including upstream connectivity, bandwidth
   (periodic baseline runs, not incident response)

For F0:
- Gateway ping latency/jitter: only runs on Network WARN/CRIT,
   not on every health check (preserves the ~1.3s healthy-case wall time)
- Upstream connectivity probe: opt-in only via future `--check-upstream`
- Be opinionated about what to probe but make it visible — show user
   what was measured and why

### Parallel execution architecture (for F0 implementation)

Wall time matters for UX. Goroutines shrink wall time when you have
independent operations that block on I/O. Both apply to DashDiag.

**Three-phase execution model for F0:**

```
Phase 1: Parallel passive collection (verify already working)
   ├── 12 goroutines, one per check
   ├── errgroup with context timeout (5s max per check)
   └── Wait for all to complete or timeout
   Wall time: ~200-300ms

Phase 2: Conditional drill-down (new for F0)
   ├── For each check that returned WARN/CRIT:
   │   ├── Spawn drill-down goroutine for that check
   │   └── Drill-down internally parallelizes its work
   │       (e.g., Memory drill-down: worker pool of 8 reads 500 /proc/PID/status)
   └── Drill-downs run in parallel with each other
   Wall time when triggered: ~500ms-1s

Phase 3: Conditional probing (new for F0)
   ├── If Network drill-down needs gateway ping → ping (~1s)
   ├── Other probes parallel to ping if any
   └── Use errgroup.SetLimit() to cap concurrent probes
   Wall time when triggered: ~1s
```

**Resulting wall times:**
- Healthy system: ~300ms (Phase 1 only)
- WARN/CRIT system: ~1.5-2s (Phase 1 + 2 + 3)

Healthy systems actually get faster than the current 1.3s. Broken
systems take ~2s but provide actionable diagnosis instead of just
verdict.

**Key Go patterns to use:**

```go
import "golang.org/x/sync/errgroup"

// Worker pool with concurrency limit
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(8) // 8 concurrent workers

for _, pid := range pids {
    pid := pid // capture loop variable
    g.Go(func() error {
        return readProcStatus(ctx, pid)
    })
}
if err := g.Wait(); err != nil { /* handle */ }

// Context with timeout per check
ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
defer cancel()
```

**Implementation rules:**

1. **Verify Phase 1 is already parallel.** Quick check:
   `grep -r "go func\|sync.WaitGroup\|errgroup" internal/`
   If sequential, this is a quick win — move to parallel goroutines first.

2. **Use worker pool for /proc iteration.** Don't spawn 500 goroutines
   reading /proc/PID/*. Use errgroup.SetLimit(8) or runtime.NumCPU().
   Prevents pathological behavior on systems with thousands of processes.

3. **Always use context.WithTimeout.** 5 seconds max per check. If
   something hangs (D-Bus to systemd can stall, ping can take longer
   than expected), it gets killed and reported as "Check X timed out"
   instead of blocking the whole run.

4. **Always use recover() in each goroutine.** A panic in one check
   should not crash DashDiag. Report "Check X errored: <reason>" instead.

5. **Test output stability.** Parallel execution must not produce
   non-deterministic output ordering. Collect results into a map keyed
   by check name, render in stable sorted order.

6. **Don't over-parallelize ping.** ping -c 20 -i 0.2 takes 4s by design
   (measuring jitter). Running parallel pings would skew the measurement.
   If 4s is too long, reduce sample count (-c 10 -i 0.1 = 1s, less data
   but still useful).

7. **Context-aware hints (small F0 enhancement).** Currently hints are
   static suggestions like "ss -tnp state close-wait". But ss may not
   be installed on RHEL 6, Alpine, or stripped containers.
   
   Each hint generator should check what's actually available on this
   system via exec.LookPath() and suggest the command that exists:
   
     if hasSS := exec.LookPath("ss"); hasSS == nil {
         hints = append(hints, "ss -tnp state close-wait")
     } else if hasNetstat := exec.LookPath("netstat"); hasNetstat == nil {
         hints = append(hints, "netstat -tnp | grep CLOSE_WAIT")
     } else {
         hints = append(hints, "(install net-tools or iproute2 to investigate)")
     }
   
   Small but meaningful: difference between "here's a command" and
   "here's a command that will actually work on YOUR system."
   ~1 day of work added to F0. The deeper version (`dsd how`) is in IDEAS.

---

## Strategy backup setup (NOW item — ~5 minutes)

8 strategic documents currently exist only on one laptop:
- KEYORIX_FOUNDATION.md (philosophy, ~970 lines)
- POSITIONING.md (brand, voice, category)
- STRATEGY.md (5 monetization paths)
- FEATURES.md (12 features incl. F0)
- LAUNCH_PREP.md (launch sequence)
- PRODUCT_IDEAS.md (xwan + portfolio)
- CONTENT_LINKEDIN_CHEATSHEET.md (launch content)
- CONTENT_HN_REDDIT_CHEATSHEET.md (launch content)

Plus BACKLOG.md (this file) which IS in the public repo.

Total ~3000 lines of strategic work. A laptop loss = catastrophic.

### 5-minute setup commands

```bash
# Create a fresh local directory for the strategy repo
cd ~
mkdir -p dev/keyorix-strategy
cd dev/keyorix-strategy
git init

# Copy current strategy docs from dashdiag/
cp /Users/andreibeshkov/dev/dashdiag/KEYORIX_FOUNDATION.md .
cp /Users/andreibeshkov/dev/dashdiag/POSITIONING.md .
cp /Users/andreibeshkov/dev/dashdiag/STRATEGY.md .
cp /Users/andreibeshkov/dev/dashdiag/FEATURES.md .
cp /Users/andreibeshkov/dev/dashdiag/LAUNCH_PREP.md .
cp /Users/andreibeshkov/dev/dashdiag/PRODUCT_IDEAS.md .
cp /Users/andreibeshkov/dev/dashdiag/CONTENT_*.md .

# Add a README explaining what this repo is
cat > README.md <<'EOF'
# Keyorix Strategy

Private strategy and positioning documents for Keyorix S.L.

This repo is the canonical source of truth for company-level strategic
thinking. The public dashdiag/keyorixhq repos contain operational
documentation only.

## Documents

- KEYORIX_FOUNDATION.md — philosophy and conviction (the why)
- POSITIONING.md — brand, voice, audience, category framing
- STRATEGY.md — monetization paths
- FEATURES.md — feature roadmap with priority
- LAUNCH_PREP.md — launch sequence
- PRODUCT_IDEAS.md — future products beyond DashDiag and Keyorix Vault
- CONTENT_*.md — drafts for launch coordination

## Access

Restricted to founders and approved cofounders post-ENISA verification.
EOF

git add -A
git commit -m "Initial strategy snapshot - 2026-05-09"

# Create the private repo on GitHub and push
gh repo create keyorixhq/strategy --private --source=. --push

# Verify it pushed
gh repo view keyorixhq/strategy --web
```

### Sync script for ongoing updates

After initial setup, save this as `~/bin/sync-keyorix-strategy.sh`:

```bash
#!/bin/bash
set -e

DASHDIAG=/Users/andreibeshkov/dev/dashdiag
STRATEGY=$HOME/dev/keyorix-strategy

# Copy current versions
cp "$DASHDIAG"/KEYORIX_FOUNDATION.md "$STRATEGY"/
cp "$DASHDIAG"/POSITIONING.md "$STRATEGY"/
cp "$DASHDIAG"/STRATEGY.md "$STRATEGY"/
cp "$DASHDIAG"/FEATURES.md "$STRATEGY"/
cp "$DASHDIAG"/LAUNCH_PREP.md "$STRATEGY"/
cp "$DASHDIAG"/PRODUCT_IDEAS.md "$STRATEGY"/
cp "$DASHDIAG"/CONTENT_*.md "$STRATEGY"/ 2>/dev/null || true

cd "$STRATEGY"
git add -A

# Only commit if there are changes
if ! git diff --cached --quiet; then
    git commit -m "snapshot $(date +%Y-%m-%d-%H%M)"
    git push
    echo "Strategy backed up to private repo"
else
    echo "No changes to back up"
fi
```

Make it executable: `chmod +x ~/bin/sync-keyorix-strategy.sh`

Run after every strategy session.

### When ENISA cofounder checks clear

Grant cofounders access to the strategy repo:
```bash
gh api repos/keyorixhq/strategy/collaborators/USERNAME -X PUT \
  -f permission=push
```

Or via web UI: github.com/keyorixhq/strategy/settings/access

### Defense in depth (after launch)

Once the immediate backup is in place, consider additional layers:
- Local encrypted backup to external drive (monthly)
- iCloud Drive copy of the strategy repo (auto-syncs continuously)
- Optional: GitLab.com mirror for EU sovereignty story consistency
   (GitHub is owned by Microsoft, US jurisdiction)

Don't let perfect-backup planning prevent imperfect-backup execution.
GitHub private repo tonight is enough.
