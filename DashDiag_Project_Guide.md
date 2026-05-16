# DashDiag (dsd) — Project Bible & AI-Assisted Build Guide

> **One command → instant system health overview, visually clear, actionable, and shareable.**

---

## 1. Project Summary

### What It Is
DashDiag (`dsd`) is a lightweight, modular CLI tool for DevOps engineers, SREs, cloud engineers, and system administrators. It consolidates fragmented Linux/macOS diagnostic utilities into a single, readable, shareable interface with emoji-enhanced output, color highlights, and concise summaries.

### The Problem It Solves
| Problem | DashDiag Solution |
|---|---|
| Fragmented CLI workflow (htop, df, free, ping, docker ps…) | One command replaces them all |
| Onboarding friction for junior engineers | Friendly UX with emoji, colors, clear summaries |
| Slow multi-command manual checks | Snapshot in seconds |
| Non-shareable output | Clean output for Slack, GitHub, incident war rooms |
| No unified container/k8s pre-flight check | Modular architecture designed for it |

### Target Audience
- DevOps Engineers & SREs needing quick health snapshots
- Cloud Engineers managing multi-node / multi-container environments
- System Administrators wanting one-command overviews
- Junior / Mid-level engineers who benefit from guided UX

---

## 2. Core Features

### Commands
```
dsd              # runs dsd health (zero-config default)
dsd health       # Core health check: CPU, memory, disk, swap, IO, network, clock,
                 #   FD limits, systemd units, processes, sysctl, SELinux (~5s)
dsd health deep  # Everything in dsd health + extended checks: per-core CPU, jitter,
                 #   slab/overcommit memory, journal size, bond health (~8s)
dsd net          # Network snapshot: interfaces, gateway, DNS, TCP states (~3s)
dsd net deep     # Full network analysis: jitter, bonds, ethtool, wireless,
                 #   conditional traceroute (~30s)
dsd docker       # Container runtime status (Docker / Podman / CRI-O)
dsd services     # Service port health: SSH, HTTP, DB, custom endpoints
dsd k8s          # Kubernetes cluster health snapshot
dsd k8s deep     # Full K8s audit: all failure modes + resource hygiene
dsd pve          # Proxmox VE: cluster, ZFS, VMs, LXC (roadmap)
dsd compare <h1> <h2> ...  # Side-by-side health comparison across servers via SSH
                           #   outlier detection: flags the server that differs from peers
dsd compare <h1> <h2>  # Side-by-side health comparison across servers via SSH,
                       #   outlier detection flags the server differing from peers
dsd logs         # Log error aggregation + journal size
dsd security     # Security posture: SSH config, ports, sudo, SELinux
dsd full         # All modules combined
dsd examples     # Show real-world usage workflows (incident triage, pre-deploy, CI gate)
dsd trial start  # Start free 14-day Team plan trial (no card needed)
dsd --changelog  # Show what changed in the current version (shown on re-engagement)
```

**Output format flags (apply to any command):**
```
--plain          # ASCII only, no emoji/color (auto on non-TTY/pipe/CI)
--report         # Markdown tables for Slack/GitHub/Jira
--report --out health-$(date +%Y%m%d).md   # Save to file
--json           # Structured JSON for scripting/CI gates
--debug          # Timing + raw values to stderr
--compact        # Horizontal one-line-per-row (wide terminals)
```

### Product Design Principles

These three principles govern every UX decision in DashDiag. When in doubt about what to build or how to present data, return to them.

**Principle 1 — Signal over noise.**
Do not dump raw data. Interpret it. An engineer running `dsd health` wants to know if anything needs their attention, not read a table of numbers. Every check must produce a verdict (`✅ OK`, `⚠️ WARN`, `❌ CRIT`), not just a value.

```
❌ Raw data (noise):    CPU: 85%   RAM: 92%   Disk: 70%
✅ Signal:              ⚠️ Memory high (92%)   ⚠️ CPU elevated   ✅ Disk OK
                        Summary: 2 issues detected
```

**Principle 2 — Assistant, not viewer.**
The tool must tell the engineer what to do next, not just what the state is. Every WARN and CRIT result includes a `Next:` hint with the exact command to run. This is what separates DashDiag from an alias.

```
⚠️ Memory high (92% used)
→ ps aux --sort=-%mem | head -10
→ dsd health deep
```

**Principle 3 — Decision acceleration.**
DashDiag is not a monitoring tool. It is a **decision acceleration layer** — it reduces the time from "something might be wrong" to "I know what to do about it" from 5 minutes to 10 seconds. This framing matters for positioning to SREs and enterprises.

**Principle 4 — Visual hierarchy.**
Summary first, details optional. `dsd health` output must be skimmable top-to-bottom in under 3 seconds. The summary line (pass/fail count + next steps) is the most important part — it appears at the bottom so the engineer sees it last after scanning the sections, and it is always present. Details are in sections above it. Longer commands like `dsd full` follow the same pattern: each section has a one-line verdict, not just a table.

**Principle 5 — Consistency across all commands.**
`dsd docker`, `dsd net`, `dsd pve`, `dsd k8s` must all produce output with the same conventions:
- Same section header format: `[Section Name]`
- Same status icons: `✅` / `⚠️` / `❌` / `ℹ️`
- Same summary footer: `Checks: N | Passed: N | Failed: N`
- Same `Next steps:` block format at the bottom
A user who has seen `dsd health` output should immediately understand `dsd pve` output without reading documentation.

**Principle 6 — Progressive disclosure.**
Two levels of detail, never mixed:

- **Level 1** (`dsd health`): concise, summary, key signals only. If everything is OK, collapse the detail and show one line. Beginners are not overwhelmed.
- **Level 2** (`dsd full`, `dsd net`, `dsd pve`): full tables, all checks, raw values, debug context. Experts get depth.

The critical renderer rule: **when all checks pass, collapse to a single summary line.** Do not show a table of green checkmarks — that is noise.

**Max 2 issues per section in quick mode.** If a section has 5 failing checks, show the 2 most severe and add: `and 3 more issues — run dsd full for details`. This prevents the "wall of red" that causes engineers to stop reading.

```
# All checks OK — collapsed (correct):
⚡ System snapshot ready
✅ All systems normal  (8 checks passed in 0.8s)
Next: → dsd docker   → dsd net

# All checks OK — expanded (wrong — do not ship this):
✅ CPU: 8 cores, load 1.2 (15%)
✅ RAM: 6.3G free / 16G  (61% used)
✅ Swap: 512MB used / 4GB  (13%)
✅ Root FS: 120G free / 250G  (52% used)
✅ Gateway reachable  (2ms)
✅ Internet reachable  (18ms)
✅ Clock: synchronized  (+2ms)
✅ FDs: 4821 / 524288  (1%)
```

Only expand sections that contain WARN or CRIT results. This is the single most important renderer decision — it is what makes the tool feel fast and focused rather than verbose.

**Principle 7 — Trust through transparency.**
DevOps engineers do not install unfamiliar tools on production servers unless they trust them. Trust is communicated at the UX level, not just in documentation. Three rules:

1. Every check shows what it read, not just what it concluded: `RAM: 13.8G / 16G  (86% used) ← from /proc/meminfo`
2. The `--debug` flag shows exactly which files were read, which commands were run, and what raw values were returned — no hidden behaviour.
3. The startup line must communicate the tool's nature: `⚡ System snapshot (read-only)` — two words that remove the "will this change something?" anxiety.

```
# Good startup line:
⚡ System snapshot (read-only) …

# With --debug:
[debug] MemoryCollector      21.3ms  ok   (read /proc/meminfo)
[debug] DiskCollector        78.1ms  ok   (read /proc/mounts + statvfs)
[debug] SwapCollector      1102.4ms  ok   (read /proc/vmstat x2, 1s sample)
[debug] NetworkQuick        487.2ms  ok   (ICMP ping x3 concurrent)
```

**Principle 8 — Expectation transparency.**
Tell the engineer how long a check will take before it starts. First-run abandonment
is the single biggest adoption killer for CLI tools that take more than a few seconds.
A user who sees nothing for 10 seconds thinks the tool is frozen. A user who sees
"~30s" waits patiently. Two rules:

1. **Every command prints its time estimate before the first async work starts** —
   not after. The estimate must appear within 50ms of invocation.
2. **Live progress shows what is currently running** — not just a spinner.
   "Running: traceroute…" is infinitely more reassuring than a rotating bar.

```
# dsd net deep startup (correct — estimate first, then live progress):
⚡ Deep network analysis (read-only) — ~30s
   Running: gateway ping (20 samples) …        [▓▓▓░░░░░░░░░░░░░] 20%

# When a slow conditional step triggers, explain it:
   Running: traceroute (triggered: 18% packet loss) …  [▓▓▓▓▓▓▓▓▓░░░░░░░] 58%
   ℹ️  This may take up to 15s — tracing path to 8.8.8.8

# In --plain / non-TTY (CI, pipes, logs):
[INFO] Starting deep network analysis (~30s)
[INFO] Running: gateway ping (20 samples)
[INFO] Running: DNS timing
[INFO] Running: traceroute (triggered: high latency)
[INFO] Completed in 28s
```

Per-command estimates (printed at startup, before any collector runs):

| Command | Estimate | Note |
|---|---|---|
| `dsd health` | `~5s` | IO 1s sample is the floor |
| `dsd health deep` | `~8s` | + CPUDetail 100ms per-core sample |
| `dsd net` | `~3s` | 3 concurrent pings |
| `dsd net deep` | `~30s` | Traceroute can add up to 15s |
| `dsd k8s` | `~10s` | API server latency variable |
| `dsd k8s deep` | `~15s` | More list calls |
| `dsd docker` | `~5s` | Docker socket response |
| `dsd security` | `~10s` | `find /etc` is the slow step |
| `dsd logs` | `~8s` | journalctl window |
| `dsd full` | `~45s` | All modules |

---

### Output Philosophy
- Emoji + color = instant readability for humans in a terminal
- Tables for structured data (network interfaces)
- Progress bar + pass/fail summary
- **Collapse when all-OK** — show one summary line, not a table of green checkmarks
- **Expand only what needs attention** — WARN/CRIT sections expand, OK sections collapse to one token
- **Max 2 issues shown per section in quick mode** — `and N more — run dsd full` for the rest
- `--plain` flag: ASCII only, no emoji/color — auto-activates on non-TTY (pipes, CI, redirects)
- `--report` flag: markdown tables for Slack/GitHub/Jira (not a command — a format switch)
- `--report --out <file>`: save report to file (works on any command)
- `--json` flag: structured JSON for scripting, CI gates
- `--yaml` flag: YAML output — same data as `--json`, formatted as YAML for K8s/Ansible engineers
  who live in YAML and find JSON-to-YAML conversion friction annoying
- `--debug` flag: timing + raw values to stderr (never corrupts --json)
- `--compact` flag: horizontal one-line overview for wide terminals
- Auto-TTY detection: `--plain` activates automatically when stdout is not a terminal
- Output pastes cleanly into Slack, Teams, GitHub issues
- **Zero-config value** — bare `dsd` runs `dsd health` — value from first keystroke
- **Read-only transparency** — startup line: `⚡ System health (read-only)` — no side-effect anxiety
- **Pro feature labels in `--help`** — paid/account-gated commands marked inline
  so engineers discover upgrade paths naturally without ad interruption:

```
$ dsd --help

Available commands:
  dsd health       Core health check (~5s)
  dsd health deep  Thorough pre-deploy check (~8s)
  dsd net          Network snapshot (~3s)
  dsd net deep     Full network analysis (~30s)
  dsd compare      Side-by-side server comparison     ◆ Team
  dsd fleet        Multi-server fleet checks           ◆ Team
  dsd policy       CI/CD policy gates                  ◆ Team

Output flags:
  --share          Share snapshot URL (24h)            ◆ Free account
  --badge          README health badge                  ◆ Free account
  --diff           Delta since last run                Free
  --json           Structured JSON                     Free

◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup
```

The ◆ marker is a lipgloss-styled suffix: dim in plain mode, coloured in human
mode, omitted entirely in --json output.

- **Pro feature labels in `--help`** — paid/account-gated commands marked inline so engineers
  discover upgrade paths naturally without ad interruption:

```
$ dsd --help

Available commands:
  dsd health       Core health check (~5s)
  dsd health deep  Thorough pre-deploy check (~8s)
  dsd net          Network snapshot (~3s)
  dsd net deep     Full network analysis (~30s)
  dsd compare      Side-by-side server comparison     ◆ Team
  dsd fleet        Multi-server fleet checks           ◆ Team
  dsd policy       CI/CD policy gates                  ◆ Team

Output flags:
  --share          Share snapshot URL (24h)            ◆ Free account
  --badge          README health badge                  ◆ Free account
  --diff           Delta since last run                Free
  --report         Markdown for Slack/Jira             Free
  --json           Structured JSON                     Free

◆ Team: dashdiag.sh/teams  |  ◆ Free account: dashdiag.sh/signup
```

The `◆` marker is implemented as a lipgloss-styled suffix — dim in plain mode,
coloured in human mode, omitted entirely in `--json` output.

**Principle 9 — Typo correction and fuzzy matching.**
Never show "unknown command" and nothing else. Two layers of correction:

**Layer 1 — Command typos (Cobra built-in):**
Measure Levenshtein distance between the typed command and all valid commands.
If distance ≤ 2, suggest the closest match. One line of Cobra config.

**Layer 2 — Config value fuzzy matching:**
When a command accepts a name that appears in `~/.dsd.yaml` (server names in
`dsd compare`, service names in `dsd services`, policy names in `dsd policy`),
fuzzy-match the typed value against known config entries. If the engineer types
`dsd compare web-pord-01` and `web-prod-01` is in their config, suggest it.

```bash
# Layer 1 — command typo:
$ dsd healt
dsd: unknown command "healt"
Did you mean: dsd health?

# Layer 2 — config value typo:
$ dsd compare web-pord-01 web-prod-02
dsd compare: unknown host "web-pord-01"
Did you mean: web-prod-01? (from ~/.dsd.yaml)
Run: dsd compare web-prod-01 web-prod-02
```

```
# BAD:
$ dsd healt
Error: unknown command "healt"

# GOOD:
$ dsd healt
dsd: unknown command "healt"
Did you mean: dsd health?
Run 'dsd --help' for usage.
```

```go
// cmd/root.go — enable in Cobra:
rootCmd.SuggestionsMinimumDistance = 2
rootCmd.SuggestFor = []string{} // auto-detected via edit distance
```

**Principle 10 — First-run onboarding.**
The first time `dsd` runs on a new server, offer a 30-second guided setup.
Detect server type from running processes and suggest a matching profile.
Save to `~/.dsd.yaml`. Then run the first health check immediately — value
from the first keystroke, not after configuration.

```
$ dsd
👋 First run detected. Let's set up DashDiag. (~30 seconds)

What type of server is this?
  1) Web server (nginx / apache)
  2) Database server (postgres / mysql / redis)
  3) Kubernetes node
  4) General purpose / skip

> 1

✅ Web server profile applied
   IO thresholds: SSD (await warn > 1ms)
   Services check: nginx:80, nginx:443
   Config saved: ~/.dsd.yaml

⚡ Running first health check…
[health output]
```

Detection: scan running processes with `ps aux` — if nginx/apache detected,
suggest web profile. If postgres/mysql, suggest database profile. If kubelet,
suggest K8s profile. If nothing recognised, suggest general. Engineer can
override. The wizard only runs once — never on subsequent runs.

**Principle 11 — Empty state guidance.**
When a command runs but finds nothing to act on, never show a blank output or
a bare INFO line. Turn the empty state into a guided starting point — show the
exact commands or config the engineer needs to get value immediately.

```
# BAD — cryptic, no direction:
$ dsd services
ℹ️  No services configured.

# GOOD — empty state as onboarding:
$ dsd services
ℹ️  No services configured yet.
    Add services to ~/.dsd.yaml to check port health:

    services:
      - name: nginx
        host: localhost
        port: 80
        protocol: http
      - name: postgres
        host: localhost
        port: 5432
        protocol: tcp

    Or run: dsd init  to set up a server profile automatically.

$ dsd k8s
ℹ️  No kubeconfig found (~/.kube/config or $KUBECONFIG).
    → Set KUBECONFIG=/path/to/config  or  copy your kubeconfig to ~/.kube/config
    → kubectl config view  to check your current context

$ dsd policy check
ℹ️  No policy file specified.
    Create .dsd-policy.yaml in your project root:

    require:
      cpu_load_max: 0.7
      disk_free_min_pct: 20
    → dsd policy check --policy .dsd-policy.yaml
```

Empty state guidance applies to: `dsd services`, `dsd k8s`, `dsd policy check`,
`dsd compare` (no hosts given), `dsd logs` (journald not available).
Rule: every empty state output must contain at least one concrete next command.

---

### Tone of Voice

All output strings — status messages, hints, summaries — must follow this voice. Inconsistent tone breaks the "product not script" feeling.

```
Style:   concise · neutral · slightly human · never robotic · never verbose

✅ Good: "⚠️ High memory usage (92%)"
✅ Good: "Gateway unreachable — check cable or router"
✅ Good: "All systems normal"

❌ Bad:  "Memory usage is critically elevated and may cause performance degradation"
❌ Bad:  "ERROR: The memory subsystem has reported abnormal utilization metrics"
❌ Bad:  "Unable to ascertain the current operational status of the network interface"
```

**Rules:**
- Max one sentence per issue line
- State the fact + the implication, not just the number
- Next-step hints are commands, not explanations
- Never use "error" as a standalone word — say what happened instead

---

### Output Modes — Three-Way Format Decision

| Mode | Flag | Auto-activates when | Best for |
|---|---|---|---|
| Human | (default) | stdout is a real terminal | Daily use in terminal |
| Plain | `--plain` | stdout is piped/redirected/CI | Log files, scripts, CI output |
| Report | `--report` | explicit only | Slack, GitHub issues, Jira tickets |
| Report to file | `--report --out <file>` | explicit only | Incident reports, runbook attachments |
| JSON | `--json` | explicit only | Scripting, CI gates |
| YAML | `--yaml` | explicit only | Kubernetes/Ansible workflows |
| Share | `--share` | explicit only | Paste URL into Slack/incident channel |

**Note:** `--report` is a format flag, not a command. It applies to any command:
`dsd health --report`, `dsd net deep --report`, `dsd k8s --report --out k8s.md`

**`--report` output wraps in a triple-backtick block** so it pastes cleanly into Slack or GitHub without losing structure:

````
⚡ DashDiag Report — 2026-03-20 14:32
```
**Network**
| Interface | Status   | IPv4          | Ping |
|-----------|----------|---------------|------|
| en0       | ✅ OK    | 192.168.1.131 | ✅   |
| eth1      | ❌ FAIL  | —             | ❌   |

**CPU & Memory**
| Metric | Value          | Status   |
|--------|----------------|----------|
| CPU    | load 1.2/8 cores | ✅ OK  |
| RAM    | 14.7G / 16G    | ⚠️ WARN  |

**Summary**
Total: 8 | ✅ 6 | ⚠️ 1 | ❌ 1 | Status: ⚠️ WARN

**Next Steps**
1. `dsd net` — investigate eth1 interface
2. `ps aux --sort=-%mem | head -10` — find memory consumers
```
````

---

### Quick Glance Format — Horizontal Compact View

For `dsd health --compact` or as the default when terminal is wide enough (≥ 120 cols). Shows all modules in one horizontal table — maximum information density for experienced engineers.

```
=== DashDiag Quick Glance ===

NETWORK         CPU         MEM          SWAP       DISK           IO
en0  ✅ OK      1.2 ✅       7G ✅        2G ✅      / 52% ✅        0.2ms ✅
eth1 ❌ FAIL    3.8 ⚠️       14.7G ⚠️     3G ✅      /home 40% ✅   5.2ms ⚠️

SUMMARY:  Total: 8 | ✅ 5 | ⚠️ 2 | ❌ 1 | Status: ⚠️ WARN
Next: dsd net   dsd full   ps aux --sort=-%mem | head -10
```

**When to use which format:**

| Format | Command | Best for |
|---|---|---|
| Vertical sections | `dsd health` (default) | Issues present — engineer needs to read each section |
| Collapsed one-liner | auto when all-OK | All green — confirm and move on |
| Horizontal compact | `dsd health --compact` or wide terminal | Experienced engineer, dense overview |
| Report markdown | `dsd health --report` | Paste into Slack/GitHub/Jira |

---

### Example Output — Quick Check (all healthy — collapsed)
```
⚡ System snapshot (read-only) …

✅ All systems normal  (8 checks passed in 0.9s)

Next: → dsd docker   → dsd net   → dsd pve
```

### Example Output — Quick Check (with issues — expanded only for affected sections)
```
⚡ System snapshot (read-only) …

[CPU & Memory]           ← expanded because WARN/CRIT present
⚠️  CPU: 4 cores, load 3.8 (95%)  ← elevated
❌  RAM: 312MB free / 16G  (98% used)
❌  Swap: 3.9GB used / 4GB  (97%)  si=142 so=89 pages/sec  ← thrashing

[Disk & IO]              ← expanded because CRIT present
✅ Root FS: 45G free / 250G  (82% used)
❌ sda: util 97%  await 180ms  ← saturated

Network ✅  Clock ✅  FDs ✅   ← collapsed — all OK, one line

— Summary —
Checks: 8 | Passed: 4 | Failed: 4
Issues:
  ❌ Memory: 98% used + active swap thrashing — OOM risk
  ❌ Disk IO: sda saturated (97% util)
  ⚠️  CPU: load 3.8 on 4 cores

Next steps:
  → ps aux --sort=-%mem | head -10
  → iostat -x 1 5
  → dsd full  for complete diagnostics
```

### Example Output — Quick Check (issues detected)
```
⚡ System snapshot ready

[CPU & Memory]
⚠️  CPU: 4 cores, load 3.8 (95%)  ← elevated
❌  RAM: 312MB free / 16G  (98% used)
❌  Swap: 3.9GB used / 4GB  (97%)  si=142 so=89 pages/sec  ← thrashing

[Disk & IO]
✅ Root FS: 45G free / 250G  (82% used)
❌ sda: util 97%  await 180ms  ← saturated

[Network]
✅ Gateway 192.168.1.1 reachable  (2ms)
✅ Internet reachable  (18ms)

[Clock]
✅ Synchronized  (offset +2ms)

— Summary —
Checks: 8 | Passed: 4 | Failed: 4
Issues:
  ❌ Memory: 98% used + active swap thrashing — OOM risk
  ❌ Disk IO: sda saturated (97% util) — processes may be blocked
  ⚠️  CPU: load 3.8 on 4 cores — check for runaway processes

Next steps:
  → ps aux --sort=-%mem | head -10
  → iostat -x 1 5
  → dsd health deep  for complete diagnostics
```

---

## 3. Architecture Decisions

### Language Decision: Rust vs Go vs Python

All three are viable. Here is the honest trade-off table for this specific project:

| Criterion | Rust | Go | Python |
|---|---|---|---|
| Execution speed | Excellent (no GC, zero-cost abstractions) | Very good (minor GC overhead) | 10–60× slower |
| Binary size | ~0.5–5 MB stripped | ~10–25 MB static | 50–200 MB (pyinstaller) |
| Cross-compile | Excellent (cargo + targets) | Best-in-class (GOOS/GOARCH) | Poor (pyinstaller pain) |
| Static binary | Yes (musl for fully static) | Yes (default) | No |
| Startup time | Blazing fast | Fast | Slow (import overhead) |
| Terminal UX libs | `colored`, `ratatui`, `comfy-table`, `indicatif` | `lipgloss`, `bubbletea`, `tablewriter` (Charm ecosystem) | `rich`, `typer` — easiest |
| System metrics libs | `sysinfo`, `psutil-rs`, `nix` | `gopsutil` (battle-tested) | `psutil` (easiest) |
| Compile time | Slow (fast with caching) | Very fast | Instant |
| Learning curve | Steep (borrow checker) | Gentle | Lowest |
| Popular CLI examples (2026) | `bat`, `ripgrep`, `fd`, `eza`, `zoxide`, `starship`, `dust` | `docker`, `kubectl`, `gh`, `helm`, `terraform` | `glances`, `httpie` |
| DevOps/SRE adoption | High and rising | Extremely high (K8s-native ecosystem) | High for scripts, lower for binaries |
| Future external tool integration | Good FFI | Decent | Best ecosystem |
| Distribution | `cargo install` + Homebrew | `curl \| sh` + Homebrew + apt/yum | Requires `pipx` or bundler |

### The Verdict

**Go is the recommended choice for DashDiag.** Here is why, specifically for this project:

- The Kubernetes and Docker ecosystems are Go-native. `client-go`, Docker SDK, and `gopsutil` are all first-party Go libraries — using Rust means working against the grain for the container/k8s modules that are your moat.
- Go's cross-compilation (`GOOS=linux GOARCH=arm64 go build`) is genuinely trivial. GoReleaser handles all four platforms in one config file.
- Iteration speed matters when you are building a startup in parallel. Go builds in seconds; Rust fights the borrow checker for hours early on.
- The Charm ecosystem (`lipgloss`, `bubbletea`) produces output quality that rivals anything in Rust for terminal UX.

**Rust is the right choice if:** your top priority is the "wow factor" of a 2 MB binary and you have 2–3 months to climb the learning curve. Rust CLI tools (`bat`, `ripgrep`, `eza`) dominate the "mind-blown" posts on Reddit/HN in 2026. If you are comfortable with Rust already, use it — the ecosystem momentum is real.

**Python is only for:** validating your UX/output format before committing to Go or Rust. Use `typer` + `rich` + `psutil` to prototype `dsd health` in an afternoon, confirm the output design feels right, then port.

**Decision: Go 1.22+.** Single static binary, dead-simple cross-compile, K8s-native libraries, fast iteration, and the entire DevOps toolchain community knows how to contribute to it.

### Rust Library Reference (if you choose Rust)

```toml
# Cargo.toml
[dependencies]
clap = { version = "4", features = ["derive"] }   # CLI args/subcommands
colored = "2"                                       # Terminal colors
owo-colors = "3"                                    # Alternative coloring
comfy-table = "7"                                   # Pretty tables
indicatif = "0.17"                                  # Progress bars
serde = { version = "1", features = ["derive"] }
serde_json = "1"                                    # --json output
sysinfo = "0.30"                                    # CPU/mem/disk/net metrics
nix = "0.27"                                        # Unix system calls
tokio = { version = "1", features = ["full"] }     # Async runtime
```

### Project Structure
```
dashdiag/
├── cmd/
│   ├── root.go           # root: runs dsd health by default + global flags
│   ├── health.go         # dsd health (8 core collectors, ~5s)
│   ├── health_deep.go    # dsd health deep (12+CPUDetail collectors, ~8s)
│   ├── net.go            # dsd net (network snapshot, ~3s)
│   ├── net_deep.go       # dsd net deep (jitter + bonds + traceroute, ~30s)
│   ├── docker.go         # dsd docker
│   ├── services.go       # dsd services
│   ├── logs.go           # dsd logs
│   ├── security.go       # dsd security
│   ├── k8s.go            # dsd k8s (cluster snapshot)
│   ├── k8s_deep.go       # dsd k8s deep (full audit)
│   ├── pve.go            # dsd pve
│   ├── full.go           # dsd full (all modules)
│   ├── hook.go           # dsd hook install (CI, SSH, git, systemd)
│   ├── examples.go       # dsd examples (workflow discovery, ~50 lines)
│   ├── trial.go          # dsd trial start (14-day team plan trial)
│   └── tips_cmd.go       # dsd tips (show all tips at once)
├── internal/
│   ├── collectors/
│   │   ├── collector.go  # Collector interface + DebugCollector wrapper
│   │   ├── cpu.go               # aggregate: load avg, usage %, load pct
│   │   ├── cpu_detail.go        # per-core: usage, temp, frequency, throttle
│   │   ├── memory.go
│   │   ├── swap.go              # swap + /proc/vmstat activity + zram + zswap
│   │   ├── disk.go              # filesystem usage + inode + SMART status
│   │   ├── io.go                # dual-sample IO: util, await, queue depth
│   │   ├── network_quick.go     # fast ping + gateway + DNS (dsd quick)
│   │   ├── network_deep.go      # ping + jitter + DNS + bonds + ethtool + wireless
│   │   ├── services.go          # TCP/HTTP port health: connect + response time
│   │   ├── processes.go         # zombie (Z) and hung (D-state) process detection
│   │   ├── systemd.go           # failed/stuck systemd units
│   │   ├── sysctl.go            # key kernel parameters: somaxconn, pid_max, swappiness
│   │   ├── kernel_security.go        # SELinux / AppArmor status and recent denials
│   │   ├── logs.go              # journald + syslog error aggregation + journal size
│   │   ├── security.go          # read-only security posture: SSH config, ports, sudo
│   │   ├── clock.go             # NTP sync check
│   │   ├── fdlimits.go          # FD: system-wide + per-process limits + deleted-but-open files
│   │   ├── runtime.go           # DetectRuntime() — Docker/Podman socket detection
│   │   └── docker.go            # ContainerCollector
│   ├── runner/
│   │   └── runner.go     # concurrent RunAll() + streaming channel
│   ├── analysis/
│   │   ├── heuristics.go # deterministic pre-AI insights
│   │   └── jitter.go     # RTT standard deviation
│   ├── render/
│   │   ├── table.go
│   │   ├── summary.go
│   │   ├── network.go
│   │   ├── json.go
│   │   ├── story.go      # --story: deterministic narrative renderer
│   │   ├── postmortem.go # --post-mortem: incident template renderer
│   │   └── weekly.go     # --report --weekly / --monthly: usage summary from state.json
│   ├── output/
│   │   ├── tty.go        # IsPlain(), StatusIcon(), DetectMode()
│   │   ├── formatter.go
│   │   └── progress.go   # CommandProgress: startup line + live progress bar
│   ├── models/           # shared data types — no import cycles
│   │   ├── cpu.go
│   │   ├── memory.go
│   │   ├── swap.go
│   │   ├── disk.go
│   │   ├── io.go
│   │   ├── network.go
│   │   ├── process.go           # ProcessState, ProcessInfo
│   │   ├── systemd.go           # SystemdInfo (failed/stuck units)
│   │   ├── sysctl.go            # SysctlInfo (kernel parameters)
│   │   ├── kernel_security.go        # KernelSecurityInfo (SELinux/AppArmor)
│   │   ├── logs.go              # LogError, LogsInfo (+ journal size)
│   │   ├── security.go          # PortEntry, SecurityInfo
│   │   └── progress.go          # ProgressBar() locked spec
│   ├── platform/
│   │   ├── linux.go
│   │   ├── macos.go
│   │   ├── container.go  # DetectContainerContext(), cgroup v1/v2
│   │   └── cloud.go      # DetectCloudEnvironment() → AWS/GCP/Azure/bare-metal
│   │   └── proxmox.go    # DetectProxmoxContext() — host/VM/LXC detection
│   ├── baseline/
│   │   ├── baseline.go     # --diff: save/load/compare snapshots (~/.dsd/baselines/)
│   │   └── since_deploy.go # --since-deploy: DetectLastDeployTime() + FindBaselineBeforeTime()
│   ├── tips/
│   │   ├── tips.go       # tip of the day rotation + state tracking
│   │   └── milestones.go # usage milestone messages
│   ├── tui/
│   │   ├── select.go     # reusable SingleSelect + MultiSelect bubbletea components
│   │   └── tui.go        # IsTTY() helper, fallback to plain prompts when non-TTY
│   ├── tui/
│   │   ├── select.go     # reusable SingleSelect + MultiSelect bubbletea components
│   │   └── tui.go        # IsTTY() helper, fallback to plain prompts when non-TTY
│   ├── init/
│   │   ├── detector.go   # detect server type from running processes
│   │   └── firstrun.go   # first-run wizard + IsFirstRun() gate
│   ├── render/
│   │   ├── story.go      # --story: deterministic narrative renderer
│   │   ├── postmortem.go # --post-mortem: incident template renderer
│   │   └── weekly.go     # --report --weekly / --monthly: usage summary from state.json
│   └── version/
│   ├── baseline/
│   │   ├── baseline.go     # --diff: save/load/compare snapshots (~/.dsd/baselines/)
│   │   └── since_deploy.go # --since-deploy: DetectLastDeployTime() + FindBaselineBeforeTime()
│   ├── tips/
│   │   ├── tips.go       # tip of the day rotation + state tracking
│   │   └── milestones.go # usage milestone messages
│   ├── tui/
│   │   ├── select.go     # reusable SingleSelect + MultiSelect bubbletea components
│   │   └── tui.go        # IsTTY() helper, fallback to plain prompts when non-TTY
│   ├── init/
│   │   ├── detector.go   # detect server type from running processes
│   │   └── firstrun.go   # first-run wizard + IsFirstRun() gate
│       └── version.go    # build-time Version/Commit/Built via ldflags
├── test/
│   ├── e2e/              # testcontainers-go E2E tests (build tag: e2e)
│   │   └── quick_test.go
│   ├── contract/         # JSON schema contract tests
│   │   └── json_schema_test.go
│   └── testdata/
│       └── golden/       # golden files for renderer output
├── schema/
│   └── dsd-output.json   # published JSON output schema (versioned)
├── scripts/
│   ├── install.sh        # curl-pipe installer
│   └── smoke-test.sh     # post-install smoke tests
├── .github/
│   └── workflows/
│       ├── ci.yml        # lint + test matrix (every PR)
│       ├── security.yml  # govulncheck + gosec + semgrep + SBOM (every PR + weekly)
│       └── release.yml   # build + sign + publish (on v* tags)
├── SECURITY.md           # vulnerability policy + threat model
├── go.mod
├── Makefile
└── README.md
```

### Key Libraries (Go)

```
github.com/spf13/cobra                # CLI framework (kubectl uses this)
github.com/spf13/viper                # Config file support (~/.dsd.yaml)
github.com/charmbracelet/lipgloss     # Terminal styling / colors
github.com/charmbracelet/bubbletea    # Interactive TUI (optional, for dsd full)
github.com/shirou/gopsutil/v3         # Cross-platform CPU/mem/disk/net
github.com/go-ping/ping               # ICMP ping (privileged + unprivileged)
gitee.com/liumou_site/gns             # Gateway, DNS, public IP, network suite
github.com/nxtrace/NTrace-core        # Traceroute (ICMP/TCP/UDP + ASN whois)
github.com/docker/docker/client       # Official Docker SDK for container checks
github.com/fatih/color                # Color output (simpler alternative to lipgloss)
github.com/olekukonko/tablewriter     # Pretty terminal tables
```

### Network Libraries — Detailed Breakdown

This is the full picture for replacing `ping`, `ip a`, `traceroute` etc. with native Go:

| Purpose | Library | Key Features |
|---|---|---|
| ICMP Ping | `go-ping` | Privileged/unprivileged modes, packet loss, RTT stats |
| Interfaces & Routes | `gopsutil/v3/net` | Interface list, I/O counters, connections |
| Gateway + DNS | `gns` | Gateway detection, DNS servers, public IP, CIDR utils |
| Traceroute | `nexttrace` | Multi-protocol (ICMP/TCP/UDP), ASN whois, visual maps |
| All-in-One | `gns` | Ping quality rating, interfaces, IP, CIDR in one lib |

**Recommended `go.mod` for network module:**
```
require (
    github.com/shirou/gopsutil/v3 v3.23.12
    github.com/go-ping/ping v1.1.0
    gitee.com/liumou_site/gns v1.7.2
)
```

**Key `gns` capabilities for `dsd net`:**
```go
d := gns.NewGNSManager(false)

// Ping with quality rating
result, _ := d.Ping.ICMPWithStats("8.8.8.8", 4, false)
// result.LossRate, result.AvgRTT, result.Quality ("Excellent"/"Good"/"Poor")

// Interface list with gateway and DNS per interface
interfaces := d.Eth.GetEthList()
// iface.Name, iface.IP, iface.Gateway, iface.DNS

// Public IP
publicIP, _ := d.IP.GetPublicIPv4()
```

---

---

## 4. Software Architecture — Pipeline with Layered Dependencies

### Why Other Patterns Don't Apply

Before choosing an architecture, it helps to understand why the common ones are wrong for this project.

**Vertical Slice** — designed for web APIs where each feature (create user, list orders) is independent top-to-bottom. DashDiag is the opposite: `dsd health` and `dsd full` share the same `MemoryCollector`, `DiskCollector`, `SwapCollector`. Vertical slices would force you to duplicate collectors per command. Wrong shape.

**Event-Driven** — for distributed systems communicating asynchronously over a bus. You have goroutines sending to a channel. That is already the right amount of event-driven for a CLI. Adding a full event bus is ceremony without benefit.

**Hexagonal (Ports & Adapters)** — the key idea is valuable: insulate business logic from I/O using interfaces. You already have this with `MemoryReader`, `DiskReader`, etc. You do not need the full ceremony of named ports and adapters on top.

**AI-First** — not a software architecture. It is a product philosophy meaning "structure data so AI can consume it." You already do this with `--json` and typed `CheckResult` structs. It is a concern, not a structural pattern.

**TUI scope** — DashDiag uses `bubbletea` for exactly two interactive selection
prompts: the `dsd init` profile wizard and the `dsd hook install` multi-select.
Nowhere else. DashDiag is a snapshot tool that exits after each run. A persistent TUI
dashboard would make it a different product (`btop`, `lazydocker`, `k9s` already exist).
All other output is one-directional: DashDiag prints, the engineer reads.


**TUI (Text User Interface)** — DashDiag uses `bubbletea` for exactly two interactive
selection prompts: the `dsd init` profile wizard and the `dsd hook install` multi-select.
Nowhere else. The boundary is deliberate: DashDiag is a snapshot tool that exits after
each run. A persistent TUI dashboard would make it a different product — one that already
exists (`btop`, `lazydocker`, `k9s`). The two wizard prompts use bubbletea because
arrow-key selection is standard terminal UX that engineers already know. All other output
is one-directional: DashDiag prints, the engineer reads.

**Clean Architecture** — valuable for complex domain logic that needs insulation from frameworks. Your domain is simple: collect data, apply thresholds, render output. Take its one useful rule (dependency inversion) and leave the rest.

---

### The Right Architecture: Data Pipeline

DashDiag is a **data pipeline**. Every invocation follows the same shape:

```
INPUT           COLLECT              ANALYSE           RENDER          OUTPUT
─────────────   ──────────────────   ───────────────   ─────────────   ────────
CLI flags    →  Goroutines (runner)  Thresholds     →  Formatter    →  stdout
~/.dsd.yaml     gopsutil             Heuristics        lipgloss        stderr
                /proc /sys           Insights          JSON            file
                Docker API
                k8s API
```

This maps directly to the package structure. The structure is not arbitrary — it is the pipeline made explicit:

```
cmd/             ← INPUT layer      — parses flags, builds collector list, calls runner
internal/
  collectors/    ← COLLECT layer    — pure system reads, zero business logic
  runner/        ← ORCHESTRATION    — concurrent execution, streaming results
  analysis/      ← ANALYSE layer    — thresholds, heuristics, insights
  render/        ← RENDER layer     — tables, colours, progress bars
  output/        ← OUTPUT layer     — TTY detection, JSON marshalling, plain mode
  models/        ← SHARED TYPES     — no dependencies on anything else
  platform/      ← INFRASTRUCTURE   — OS abstraction, container detection
```

---

### The One Inviolable Rule: Dependency Direction

Dependencies flow **inward only**. Inner layers never import outer layers.

```
cmd
 └─→ runner
      └─→ collectors ─→ models ←─ analysis ←─ render ←─ output
                ↑                              ↑
           platform                        platform
```

Concretely:

```
✅ collectors  imports  models
✅ analysis    imports  models
✅ render      imports  models, output
✅ cmd         imports  runner, render, output
✅ platform    imports  nothing internal

❌ collectors  imports  analysis   (collector must not apply thresholds)
❌ models      imports  collectors (models are dumb data)
❌ analysis    imports  render     (analysis must not know about colours)
❌ render      imports  collectors (renderer must not collect data)
```

If you find yourself wanting to violate this — a collector that checks a threshold, a model with a `String()` method that formats output — that is the signal to stop and move the logic to the right layer.

---

### The Five Architectural Rules

These are the concrete decisions that follow from the pipeline shape. Apply them to every new piece of code.

**Rule 1: Collectors are pure functions.**

A collector takes a context and a reader interface. It reads raw system data. It returns a model. It has zero knowledge of thresholds, flags, or rendering. No side effects beyond the read.

```go
// ✅ RIGHT — collector only collects raw data
func (c *DiskCollector) Collect(ctx context.Context) (interface{}, error) {
    partitions, err := c.Reader.Partitions(true)
    if err != nil {
        return nil, fmt.Errorf("disk partitions: %w", err)
    }
    var filesystems []models.FilesystemInfo
    for _, p := range partitions {
        usage, _ := c.Reader.Usage(p.Mountpoint)
        filesystems = append(filesystems, models.FilesystemInfo{
            MountPoint: p.Mountpoint,
            Device:     p.Device,
            FSType:     p.Fstype,
            TotalGB:    float64(usage.Total) / 1e9,
            FreeGB:     float64(usage.Free) / 1e9,
            UsedPct:    usage.UsedPercent,
            InodesUsedPct: usage.InodesUsedPercent,
            // NO status field — that belongs in analysis layer
        })
    }
    // SMART check runs separately for physical devices (best-effort, needs smartctl)
    smartResults := collectSMART(ctx)
    return models.DiskInfo{Filesystems: filesystems, SMART: smartResults}, nil
}

// ❌ WRONG — collector applying thresholds (belongs in analysis/)
func (c *DiskCollector) Collect(ctx context.Context) (interface{}, error) {
    // ...
    if usage.UsedPercent > 80 {
        return nil, fmt.Errorf("disk critical: %.0f%% used", usage.UsedPercent)
    }
}
```

**Rule 2: Analysis owns all WARN/CRIT decisions.**

Every Status field, every threshold comparison, every heuristic lives in `internal/analysis/`. This means thresholds are configurable from a single place. It means you can change the WARN threshold for disk from 80% to 70% without touching the disk collector. It means you can write threshold tests completely independently of system calls.

```go
// internal/analysis/thresholds.go

type Thresholds struct {
    DiskWarnPct  float64 // default 80
    DiskCritPct  float64 // default 90
    RAMWarnPct   float64 // default 80
    RAMCritPct   float64 // default 95
    // ... loaded from ~/.dsd.yaml via viper
}

func ApplyDiskThresholds(info models.DiskInfo, t Thresholds) models.DiskInfo {
    for i, fs := range info.Filesystems {
        switch {
        case fs.UsedPct > t.DiskCritPct:
            info.Filesystems[i].Status = "CRIT"
        case fs.UsedPct > t.DiskWarnPct:
            info.Filesystems[i].Status = "WARN"
        default:
            info.Filesystems[i].Status = "OK"
        }
    }
    return info
}
```

**Rule 3: Models are dumb structs.**

No methods on model types. No `IsHealthy()`, no `String()`, no `Render()`. A model is data. Behaviour lives in analysis and render.

```go
// ✅ RIGHT — model is pure data
type MemoryInfo struct {
    TotalGB       float64 `json:"total_gb"`
    FreeGB        float64 `json:"free_gb"`
    UsedPct       float64 `json:"used_pct"`
    // Extended /proc/meminfo fields
    SlabMB        float64 `json:"slab_mb"`          // kernel slab cache (can grow unbounded)
    CommitLimitMB float64 `json:"commit_limit_mb"`  // max memory the kernel will commit
    CommittedAsMB float64 `json:"committed_as_mb"`  // currently committed virtual memory
    OverCommitted bool    `json:"over_committed"`   // Committed_AS > CommitLimit → OOM risk
    Status        string  `json:"status"`
    StatusReason  string  `json:"status_reason"`
}

// ❌ WRONG — model has behaviour
func (m MemoryInfo) IsHealthy() bool { return m.UsedPct < 80 }
func (m MemoryInfo) String() string  { return fmt.Sprintf("RAM %.0f%%", m.UsedPct) }
```

**Rule 4: The runner owns all concurrency.**

No collector spawns goroutines. A collector is a single-threaded unit of work that accepts a context for cancellation and timeout. Concurrency decisions (how many goroutines, what timeout, whether to run in parallel or sequence) belong exclusively to the runner.

```go
// ✅ RIGHT — collector is single-threaded, runner orchestrates
func (c *NetworkDeepCollector) Collect(ctx context.Context) (interface{}, error) {
    // Run pings concurrently WITHIN this collector is acceptable
    // because it is the collector's internal implementation detail
    // — the runner still sees this collector as one unit of work
    var wg sync.WaitGroup
    for _, target := range targets {
        wg.Add(1)
        go func(t string) { defer wg.Done(); ping(ctx, t) }(target)
    }
    wg.Wait()
    // ...
}

// ❌ WRONG — collector launching work that the runner doesn't know about
func (c *DiskCollector) Collect(ctx context.Context) (interface{}, error) {
    go c.backgroundCheck() // runner cannot cancel or time this out
}
```

**Rule 5: Commands are wiring only.**

`cmd/health.go` does exactly four things: parse flags, build collector list, call runner, call renderer. No logic. Fifty lines maximum. If you find yourself writing an `if` statement in a command file that is not about flags, move it.

```go
// cmd/health.go — 40 lines, no logic
func runHealth(cmd *cobra.Command, args []string) {
    ctx     := context.Background()
    plain   := output.IsPlain(plainMode)
    ctrCtx  := platform.DetectContainerContext()
    thresh  := analysis.LoadThresholds() // from ~/.dsd.yaml

    // dsd health: 12 core collectors — runs concurrently, floor ~5s (IO sample)
    cols := []collectors.Collector{
        collectors.NewCPUCollector(ctrCtx),      // load avg, usage %, load pct
        collectors.NewMemoryCollector(ctrCtx),   // RAM, slab, overcommit
        collectors.NewDiskCollector(),            // capacity, inodes, SMART
        collectors.NewSwapCollector(),            // swap + zram + paging rate
        collectors.NewIOCollector(),              // util %, await, queue depth
        collectors.NewNetworkQuickCollector(),    // interfaces, gateway, DNS, TCP states
        collectors.NewClockCollector(),           // NTP sync + offset
        collectors.NewFDLimitsCollector(),        // system + per-process + deleted files
        collectors.NewSystemdCollector(),         // failed/stuck units
        collectors.NewSysctlCollector(),          // somaxconn, pid_max
        collectors.NewKernelSecurityCollector(),       // SELinux/AppArmor
        collectors.NewProcessCollector(),         // zombie + D-state
    }

    renderer := render.NewRenderer(plain, outputFmt)
    if ctrCtx.InContainer {
        renderer.PrintContainerBanner(ctrCtx)
    }
    // Note: command-to-collector routing:
    //   dsd health      → CPUCollector, MemoryCollector, DiskCollector, SwapCollector,
    //                  IOCollector, NetworkQuickCollector, ClockCollector, FDLimitsCollector,
    //                  SystemdCollector, SysctlCollector, KernelSecurityCollector, ProcessCollector
    //   dsd net      → NetworkDeepCollector
    //   dsd docker   → ContainerCollector
    //   dsd services → ServicesCollector
    //   dsd logs     → LogsCollector
    //   dsd security → SecurityCollector
    //   dsd pve      → PVEHostCollector, PVEVMCollector
    //   dsd k8s      → K8sCollector
    //   dsd full     → all of the above

    results := runner.RunAll(ctx, cols)
    for result := range results {
        result = analysis.ApplyThresholds(result, thresh)
        renderer.PrintSection(result)
    }
    renderer.PrintSummary()
}
```

---

### Dependency Inversion — Applied Consistently

Every external dependency gets an interface. The real implementation wraps the external call. The mock lives in `_test.go`. This is the single most important practice for testability.

```go
// Pattern: define interface + real impl in same file, mock in _test.go

// internal/collectors/disk.go
type DiskReader interface {
    Partitions(all bool) ([]disk.PartitionStat, error)
    Usage(path string)   (*disk.UsageStat, error)
    IOCounters()         (map[string]disk.IOCountersStat, error)
}

type gopsutilDiskReader struct{}  // real impl — just calls gopsutil
func (r *gopsutilDiskReader) Partitions(all bool) ([]disk.PartitionStat, error) {
    return disk.Partitions(all)
}
// ... etc

// internal/collectors/disk_test.go
type mockDiskReader struct {
    partitions []disk.PartitionStat
    usage      map[string]*disk.UsageStat
    ioCounters map[string]disk.IOCountersStat
}
func (m *mockDiskReader) Partitions(all bool) ([]disk.PartitionStat, error) {
    return m.partitions, nil
}
// ... etc
```

**Interface checklist — every collector must inject these:**

| Collector | Interface | External dep wrapped |
|---|---|---|
| `CPUCollector` | `CPUReader` | `gopsutil/cpu`, `gopsutil/load` |
| `MemoryCollector` | `MemoryReader` | `gopsutil/mem` |
| `DiskCollector` | `DiskReader` | `gopsutil/disk` |
| `SwapCollector` | `SwapReader` + `VMStatReader` | `gopsutil/mem`, `/proc/vmstat` |
| `IOCollector` | `IOReader` + `SysReader` | `gopsutil/disk`, `/sys/block/*/` |
| `NetworkCollector` | `NetReader` + `Pinger` | `gopsutil/net`, `go-ping` |
| `ContainerCollector` | `ContainerRuntime` | Docker SDK |
| `K8sCollector` | `K8sClient` | `client-go` |
| `ClockCollector` | `NTPChecker` | `timedatectl`, `chronyc` |

---

### Plugin Architecture Boundary

The plugin system uses a **process boundary** — stronger than any software pattern. A crashing plugin cannot corrupt the core process.

```
Core process (trusted)          OS process boundary        Plugin binary (untrusted)
──────────────────────          ─────────────────────      ─────────────────────────
runner.RunAll()            →    exec.Command()         →   dsd-postgres
PluginCollector.Collect()       stdin/stdout pipe           runs independently
                                context timeout             exits 0 / 1 / 2
                                JSON schema validation  ←   []CheckResult JSON
                                ↓
                          analysis.ApplyThresholds()
                          renderer.PrintSection()
```

The plugin protocol is the interface. Nothing else needs to be specified. This is why plugins can be written in any language — they just need to speak the JSON contract.

---

### Architecture Decision Record — Quick Reference

| Decision | Choice | Reason |
|---|---|---|
| Overall pattern | Data pipeline | Matches the actual data flow exactly |
| Layer isolation | Dependency inversion | Inner layers tested without any system calls |
| Concurrency | Runner-owned goroutines | Collectors stay simple; timeouts centralised |
| Threshold logic | Analysis layer only | Configurable, testable, separate from I/O |
| Model behaviour | None — dumb structs | No coupling between data and presentation |
| Plugin isolation | Process boundary | Crash safety; language-agnostic; JSON contract |
| External deps | Interface + real impl | Every dep mockable; fuzz-testable parsers |
| Commands | Wiring only, no logic | Thin; readable; logic stays testable in inner layers |

## 5. Concurrency Architecture — How Checks Run Fast

All collectors run as goroutines simultaneously. The total time for `dsd health` is the time of the **slowest single check**, not the sum of all checks.

**Sequential vs concurrent timing:**

```
Sequential (naive):
  CPU check      →   50ms
  Memory check   →   20ms
  Disk check     →   80ms
  Network ping   → 2000ms  (3 × ~600ms timeout per target)
  DNS check      →  100ms
  ─────────────────────────
  Total:           2250ms  ← user waits 2.25 seconds

Concurrent (with per-check timeouts):
  All goroutines start simultaneously
  Network ping reduced to 500ms timeout
  ─────────────────────────
  Total:            500ms  ← limited by slowest check only
```

With both concurrency **and** tight per-check timeouts, `dsd health` runs in under 500ms on any healthy machine. `dsd net` runs in 3–5 seconds. A hung DNS server never delays the disk check.

---

### The Runner — `internal/runner/runner.go`

The central runner launches every collector as a goroutine and collects results through a channel. Results stream to the renderer as they arrive — the user sees CPU and memory output in ~50ms while the network check is still running.

```go
package runner

import (
    "context"
    "sync"
    "time"

    "github.com/yourusername/dashdiag/internal/collectors"
    "github.com/yourusername/dashdiag/internal/models"
)

type Result struct {
    Name  string
    Data  interface{}
    Error error
    Took  time.Duration
}

// RunAll launches all collectors concurrently and streams results
// as each one completes. Never blocks on a slow check.
func RunAll(ctx context.Context, cols []collectors.Collector) <-chan Result {
    resultsCh := make(chan Result, len(cols))

    var wg sync.WaitGroup
    for _, col := range cols {
        col := col  // capture loop variable (required in Go < 1.22)
        wg.Add(1)
        go func() {
            defer wg.Done()

            // Each collector enforces its own deadline
            checkCtx, cancel := context.WithTimeout(ctx, col.Timeout())
            defer cancel()

            start := time.Now()
            data, err := col.Collect(checkCtx)
            resultsCh <- Result{
                Name:  col.Name(),
                Data:  data,
                Error: err,
                Took:  time.Since(start),
            }
        }()
    }

    // Close channel when all goroutines finish
    go func() {
        wg.Wait()
        close(resultsCh)
    }()

    return resultsCh
}
```

**Critical design rule:** Never return the collector error to `errgroup` or cancel the context on failure. Each check runs to completion regardless of what others do. Errors are stored in `Result` and handled by the renderer, not the runner.

---

### The Collector Interface — with Timeout

Every collector declares its own time budget. The runner wraps it automatically:

```go
// internal/collectors/collector.go

package collectors

import (
    "context"
    "time"
)

type Collector interface {
    Name()    string
    Timeout() time.Duration   // collector declares its own budget
    Collect(ctx context.Context) (interface{}, error)
}
```

**Timeout budgets per collector:**

```go
// Quick collectors — fast system reads
func (c *CPUCollector) Timeout()          time.Duration { return 500 * time.Millisecond }
func (c *MemoryCollector) Timeout()       time.Duration { return 200 * time.Millisecond }
func (c *DiskCollector) Timeout()         time.Duration { return 1 * time.Second }

// Network — limited by ICMP round trips
func (c *NetworkQuickCollector) Timeout() time.Duration { return 3 * time.Second }
func (c *DeepNetworkCollector) Timeout()  time.Duration { return 25 * time.Second }

// Container — limited by Docker socket response
func (c *ContainerCollector) Timeout()    time.Duration { return 5 * time.Second }

// Kubernetes — API server latency
func (c *K8sCollector) Timeout()          time.Duration { return 10 * time.Second }
```

---

### Concurrency Inside the Network Collector

Pings to multiple targets must also run concurrently *within* the network collector. Sequential pings to 3 targets at 3s each = 9 seconds. Concurrent = 3 seconds.

```go
func (c *DeepNetworkCollector) Collect(ctx context.Context) (interface{}, error) {
    targets := []string{c.gateway, "1.1.1.1", "8.8.8.8"}
    results := make([]*models.PingStats, len(targets))

    var wg sync.WaitGroup
    for i, target := range targets {
        i, target := i, target
        wg.Add(1)
        go func() {
            defer wg.Done()
            results[i], _ = pingWithSamples(ctx, target, 20, 3*time.Second)
        }()
    }
    wg.Wait()

    // Decide traceroute trigger AFTER all pings complete
    internetReachable := results[1] != nil && results[1].Reachable
    highLatency       := results[1] != nil && results[1].AvgRTT > 200*time.Millisecond
    highLoss          := results[1] != nil && results[1].PacketLoss > 5.0

    var hops []models.TracerouteHop
    if !internetReachable || highLatency || highLoss {
        hops, _ = runTraceroute(ctx, "8.8.8.8", 15)
    }

    return models.DeepNetworkInfo{
        PingResults: results,
        Traceroute:  hops,
    }, nil
}
```

---

### Streaming Output — Results Print as They Arrive

The renderer reads from the results channel as goroutines finish, printing each section immediately rather than waiting for all checks to complete. This makes `dsd health` feel instantaneous — CPU and memory appear in ~50ms while network is still running.

```go
// cmd/quick.go

// NOTE: This is an illustrative excerpt showing the collector list only.
// The complete implementation is in cmd/health.go (see Rule 5 above).
func runHealthCollectors() []collectors.Collector {
    cols := []collectors.Collector{
        &collectors.CPUCollector{},
        &collectors.MemoryCollector{},
        &collectors.DiskCollector{},
        &collectors.NetworkQuickCollector{},
    }

    ctx := context.Background()
    resultsCh := runner.RunAll(ctx, cols)

    plain := output.IsPlain(plainMode) // auto-TTY + --plain flag

    if plain {
        fmt.Println("System health check (read-only)...")
    } else {
        fmt.Println("⚡ System health (read-only) …")
    }
    fmt.Println()

    renderer := render.NewRenderer(plain)
    var allResults []runner.Result
    for result := range resultsCh {
        allResults = append(allResults, result)
        // Stream WARN/CRIT sections immediately as they arrive
        // OK sections are buffered — printed collapsed in summary
        if result.Error != nil || hasIssues(result) {
            renderer.PrintSection(result)
        }
    }

    // After all checks: if no issues, print collapsed all-OK line
    // If issues exist, print collapsed OK sections + already-printed WARN/CRIT sections
    renderer.PrintSummary(allResults)
}
```

**What the user experiences:**
```
⚡ Quick system check…

[CPU & Memory]                    ← appears at ~50ms
✅ CPU: 8 cores, load avg 0.9
✅ RAM: 6.3G free / 16G

[Disk]                            ← appears at ~80ms
✅ Root FS: 120G free / 250G

[Network]                         ← appears at ~500ms
✅ Gateway 192.168.1.1 reachable
✅ Internet reachable

— Summary —                       ← appears after all checks
Checks: 4 | Passed: 4 | Failed: 0
```

---

### AI Prompt for the Runner

```
Prompt:
"Write internal/runner/runner.go for DashDiag.
Requirements:
1. RunAll(ctx, []Collector) returns a <-chan Result (buffered, len == num collectors)
2. Each collector runs in its own goroutine with context.WithTimeout using col.Timeout()
3. Results are sent to channel as each goroutine completes (streaming, not batched)
4. Channel closes automatically when all goroutines finish (use sync.WaitGroup + goroutine)
5. Collector errors are stored in Result.Error, never cancel other collectors
6. Each Result includes: Name, Data, Error, Took (time.Duration)
7. Write a RunAllAndWait() variant that blocks and returns []Result sorted by Name
   (for --json output which needs all results before printing)

Write table-driven tests covering:
- All collectors succeed: all results received, channel closes
- One collector times out: others still complete, timed-out result has non-nil Error
- Context cancelled externally: all goroutines respect cancellation"
```

---

## 5b. macOS Platform Support — Capability Matrix

DashDiag targets Linux as the primary platform and macOS as a supported secondary target. Both receive binary releases. This table documents what works fully, partially, or not at all on macOS, so engineers know exactly what they get.

| Collector / Check | Linux | macOS | macOS notes |
|---|---|---|---|
| CPU load average | ✅ Full | ✅ Full | `gopsutil` reads `sysctl kern.loadavg` |
| Per-core CPU usage | ✅ Full | ✅ Full | `gopsutil cpu.Percent(perCPU=true)` |
| CPU temperature | ✅ Full | ❌ N/A | Requires `sudo powermetrics` — out of scope |
| CPU throttle detection | ✅ Full | ❌ N/A | `/sys/cpufreq/` Linux-only; returns `Throttled=false` on macOS (in `dsd health deep`) |
| RAM usage | ✅ Full | ✅ Full | `gopsutil` reads `vm_stat` internally |
| Slab / CommitLimit | ✅ Full | ❌ N/A | `/proc/meminfo` Linux-only; fields return 0 on macOS |
| Swap usage % | ✅ Full | ✅ Full | `gopsutil/mem.SwapMemory()` |
| Swap activity (paging rate) | ✅ Full | ✅ Partial | macOS: `vm_stat` "swapped in/out" counters; no per-second delta — single snapshot only |
| zram / zswap | ✅ Full | ❌ N/A | Linux kernel feature — not present on macOS |
| Disk capacity + inodes | ✅ Full | ✅ Full | `gopsutil/disk` is cross-platform |
| SMART disk health | ✅ Full | ⚠️ Partial | `smartctl` available on macOS via Homebrew; NVMe support varies |
| Filesystem health (tune2fs) | ✅ Full | ❌ N/A | ext4-specific; use `diskutil verifyVolume` instead (not implemented) |
| IO utilization + await | ✅ Full | ⚠️ Partial | `gopsutil` IOCounters work; `/sys/block/*/queue/rotational` absent — no HDD/SSD threshold differentiation |
| IO queue depth | ✅ Full | ❌ N/A | `/sys/block/<dev>/stat` Linux-only; field returns 0 |
| Network interfaces + IPs | ✅ Full | ✅ Full | `gopsutil/net.Interfaces()` cross-platform |
| Gateway ping (ICMP) | ✅ Full | ✅ Full | `go-ping` with `CAP_NET_RAW` or UDP fallback |
| DNS check | ✅ Full | ✅ Full | `gns` library works on macOS |
| Traceroute | ✅ Full | ✅ Full | `nexttrace` has macOS binary |
| Bond / ethtool / wireless | ✅ Full | ❌ N/A | `/proc/net/bonding/` and `ethtool` Linux-only; macOS uses `ifconfig` |
| TCP connection states | ✅ Full | ⚠️ Partial | `gopsutil net.Connections()` works; `ss` not available — uses `netstat` fallback |
| NTP clock sync | ✅ Full | ✅ Full | Linux: `timedatectl`/`chronyc`; macOS: `systemsetup -getusingnetworktime` |
| NTP offset (ms) | ✅ Full | ⚠️ Partial | macOS: offset not available without `sntp` — reports sync state only |
| FD limits (system-wide) | ✅ Full | ✅ Full | `/proc/sys/fs/file-nr` Linux; `sysctl kern.maxfiles` macOS (not yet implemented) |
| FD per-process | ✅ Full | ⚠️ Partial | `/proc/<PID>/limits` Linux; macOS path via `launchctl limit` not yet implemented |
| Deleted-but-open files | ✅ Full | ✅ Full | `/proc/<PID>/fd` symlink scanning works on macOS |
| Zombie / D-state processes | ✅ Full | ⚠️ Partial | `/proc/<PID>/stat` Linux; macOS uses `ps` state — Z state detectable, D state not |
| wchan (kernel wait func) | ✅ Full | ❌ N/A | `/proc/<PID>/wchan` Linux-only |
| Systemd units | ✅ Full | ❌ N/A | `systemctl` not present on macOS; returns `Available=false` |
| Sysctl parameters | ✅ Full | ⚠️ Partial | `/proc/sys/` Linux; macOS uses `sysctl -n`; `somaxconn` → `kern.ipc.somaxconn` |
| SELinux / AppArmor | ✅ Full | ❌ N/A | `getenforce` / `/sys/module/apparmor` Linux-only; macOS has TCC not SELinux |
| Journal / log errors | ✅ Full | ❌ N/A | `journalctl` Linux-only; macOS: `log show` not yet implemented |
| Journal size | ✅ Full | ❌ N/A | `journalctl --disk-usage` Linux-only |
| Docker / container | ✅ Full | ✅ Full | Docker SDK works; Docker Desktop on macOS |
| Proxmox checks | ✅ Full | ❌ N/A | Proxmox is Linux-only |
| K8s checks | ✅ Full | ✅ Full | `client-go` cross-platform |
| TUI wizards | ✅ Full | ✅ Full | `bubbletea` is cross-platform; falls back to plain prompts on non-TTY |
| Service health ports | ✅ Full | ✅ Full | `net.Dialer` pure Go |
| Security posture (SSH config) | ✅ Full | ✅ Full | `/etc/ssh/sshd_config` same path on macOS |
| Security posture (ports `ss`) | ✅ Full | ⚠️ Partial | macOS lacks `ss`; `lsof -iTCP -sTCP:LISTEN` used instead |
| Security posture (sudo) | ✅ Full | ✅ Full | `/etc/sudoers` same path |
| World-writable /etc | ✅ Full | ✅ Full | `find /etc -perm -o+w` works on macOS |

**Legend:** ✅ Full = complete parity | ⚠️ Partial = works with reduced data | ❌ N/A = not applicable or not implemented

### macOS-specific implementation notes

**`sysctl` parameters on macOS:**
```go
// Key macOS equivalents for SysctlCollector
// kern.ipc.somaxconn  →  net.core.somaxconn
// kern.maxfiles       →  fs.file-max
// kern.maxproc        →  kernel.pid_max

// Read on macOS: exec.Command("sysctl", "-n", "kern.ipc.somaxconn")
// Read on Linux: os.ReadFile("/proc/sys/net/core/somaxconn")
// SysctlCollector uses build tags to pick the right path.
```

**Port listing on macOS (SecurityCollector fallback):**
```go
// On macOS, ss is not available. Use lsof instead:
// exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
// Output format differs from ss — parser handles both.
// The SecurityCollector detects which is available at runtime.
```

**CI matrix — macOS coverage:**
```yaml
# .github/workflows/ci.yml
strategy:
  matrix:
    os: [ubuntu-22.04, ubuntu-20.04, macos-13, macos-14]
# macos-13 = Intel, macos-14 = Apple Silicon (M1)
# Both run the full test suite — macOS-specific collectors
# return graceful INFO results for Linux-only checks.
```

---

---

## 6. Kubernetes Competitive Landscape

Before building `dsd k8s`, know what you are positioning against. These are the tools your users already have installed.

| Tool | Type | One-shot snapshot? | Emoji/shareable? | Read-only/safe? | Best for |
|---|---|---|---|---|---|
| `k9s` | Interactive TUI | No — requires navigation | Colors only | Yes | Daily management and deep debug |
| `popeye` | Scanner/report | Yes | Yes (colored score report) | Yes | Cluster sanitation and misconfig detection |
| `kube-score` | Static analyzer | Yes | Yes | Yes | YAML manifest best practices |
| `K8sGPT` | AI explainer | Yes (`k8sgpt analyze`) | Plain text + explanations | Yes | Root-cause in plain English |
| `ktop` | Metrics viewer | Partial | Basic | Yes | Quick resource glance |
| `kubectl` plugins (Krew) | Various | Varies | Rarely | Yes | Specific diagnostics |
| **DashDiag `dsd k8s`** | **Modular snapshot CLI** | **Yes** | **✅/❌ emoji + JSON** | **Yes** | **Fast shareable health overview** |

### The Gap DashDiag Fills

- `k9s` is the `htop` equivalent — interactive, powerful, not shareable as a one-liner
- `popeye` is the closest to your vision for K8s but produces a full audit report, not a quick pulse
- Nothing produces a **"neofetch for Kubernetes"** — one fast command, emoji summary, Slack-ready output

### `dsd k8s quick` — Target Output

```
⚡ Kubernetes cluster check…

[Control Plane]
✅ API server reachable (latency: 12ms)
✅ etcd healthy
✅ Scheduler active

[Nodes]
✅ 8/8 Ready
⚠️  node-3: MemoryPressure=True ← kubelet evicting pods

[OOM Events]
❌ OOMKilled: api-worker-7f9b/worker (512MB limit, 14 restarts)
   → kubectl logs api-worker-7f9b -n default --previous
⚠️  Evicted: cache-6d4c (node-3, memory-driven)

[Workloads]
✅ Pods: 120 Running / 3 Pending / 1 Failed
⚠️  deployment/api-service: 2/3 available  ← OOMKill restarts
✅ DaemonSets: 4/4 healthy

[Events]
⚠️  5 Warning events in last 15 minutes
   "Evicting pod default/cache-6d4c due to node memory pressure"

— Cluster Summary —
Status: ❌ CRIT | Nodes: 8/8 | OOMKilled: 1 | Evictions: 1
Next: kubectl describe pod api-worker-7f9b -n default
      kubectl describe node node-3
```

### Data Models — `internal/models/k8s.go`

```go
package models

type K8sNodeInfo struct {
    Name             string `json:"name"`
    Ready            bool   `json:"ready"`
    MemoryPressure   bool   `json:"memory_pressure"`  // condition MemoryPressure=True
    DiskPressure     bool   `json:"disk_pressure"`
    PIDPressure      bool   `json:"pid_pressure"`
    MemoryUsedPct    float64 `json:"memory_used_pct"` // from metrics-server if available
    Status           string `json:"status"`
    StatusReason     string `json:"status_reason"`
}

type K8sPodOOM struct {
    Namespace     string `json:"namespace"`
    PodName       string `json:"pod_name"`
    ContainerName string `json:"container_name"`
    Reason        string `json:"reason"`    // "OOMKilled" or "Evicted"
    ExitCode      int    `json:"exit_code"` // 137 = OOMKilled (128+9)
    MemLimitMB    float64 `json:"mem_limit_mb"` // container memory limit
    RestartCount  int    `json:"restart_count"`
}

type K8sEviction struct {
    Namespace string `json:"namespace"`
    PodName   string `json:"pod_name"`
    Reason    string `json:"reason"`    // "Evicted"
    Message   string `json:"message"`   // "The node was low on resource: memory"
    NodeName  string `json:"node_name"`
    Age       string `json:"age"`
}

// K8sCrashLoop records a pod stuck in CrashLoopBackOff — distinct from
// high restart count because CrashLoopBackOff means the pod will NEVER
// recover without manual intervention (fix config, image, or entrypoint).
type K8sCrashLoop struct {
    Namespace     string `json:"namespace"`
    PodName       string `json:"pod_name"`
    ContainerName string `json:"container_name"`
    RestartCount  int    `json:"restart_count"`
    LastExitCode  int    `json:"last_exit_code"`
    Message       string `json:"message"` // reason from waiting state
}

// K8sImagePullError records a pod that cannot pull its container image.
// Reason is "ImagePullBackOff" (retrying with backoff) or "ErrImagePull"
// (initial failure). Registry auth errors appear in Message.
type K8sImagePullError struct {
    Namespace     string `json:"namespace"`
    PodName       string `json:"pod_name"`
    ContainerName string `json:"container_name"`
    Image         string `json:"image"`
    Reason        string `json:"reason"`  // "ImagePullBackOff" or "ErrImagePull"
    Message       string `json:"message"` // registry error detail
}

// K8sPendingPod records a pod stuck in Pending with a scheduling reason.
// PodScheduled=False condition message is the key diagnostic field.
type K8sPendingPod struct {
    Namespace string `json:"namespace"`
    PodName   string `json:"pod_name"`
    Reason    string `json:"reason"` // e.g. "Insufficient memory", "no matching node affinity"
    Age       string `json:"age"`
}

// K8sCoreDNS records CoreDNS / kube-dns pod health.
// If CoreDNS is down, all in-cluster service-name DNS resolution fails.
type K8sCoreDNS struct {
    TotalPods   int    `json:"total_pods"`
    ReadyPods   int    `json:"ready_pods"`
    Status      string `json:"status"`
    StatusReason string `json:"status_reason"`
}

// K8sPVC records an unbound PersistentVolumeClaim.
// An unbound PVC causes pods to stay in ContainerCreating indefinitely.
type K8sPVC struct {
    Namespace    string `json:"namespace"`
    Name         string `json:"name"`
    Phase        string `json:"phase"`         // "Pending" = unbound
    StorageClass string `json:"storage_class"`
    Capacity     string `json:"capacity"`
    Message      string `json:"message"`       // provisioner error if available
}

// K8sBestEffortPod records a pod with QoS class BestEffort (no resource limits set).
// BestEffort pods are the first evicted when the node is under memory pressure.
type K8sBestEffortPod struct {
    Namespace string `json:"namespace"`
    PodName   string `json:"pod_name"`
    NodeName  string `json:"node_name"`
}

// K8sThrottledPod records a pod with high CPU throttling rate.
// Only populated when metrics-server is available in the cluster.
// Throttling happens when a pod hits its CPU limit but the node has spare capacity —
// the pod is artificially slowed even though resources are available.
type K8sThrottledPod struct {
    Namespace      string  `json:"namespace"`
    PodName        string  `json:"pod_name"`
    ContainerName  string  `json:"container_name"`
    CPULimitMillis int     `json:"cpu_limit_millis"`  // configured limit
    CPUUsageMillis int     `json:"cpu_usage_millis"`  // current usage from metrics-server
    UsagePct       float64 `json:"usage_pct"`         // usage / limit * 100
}

// K8sNamespacePolicy records a namespace that lacks resource enforcement.
// A namespace without LimitRange can have BestEffort pods by default.
// A namespace without ResourceQuota allows unlimited resource consumption.
type K8sNamespacePolicy struct {
    Namespace        string `json:"namespace"`
    HasLimitRange    bool   `json:"has_limit_range"`
    HasResourceQuota bool   `json:"has_resource_quota"`
    RunningPods      int    `json:"running_pods"` // number of running pods in namespace
}

type K8sInfo struct {
    APIServerLatencyMs   int64                `json:"api_server_latency_ms"`
    Nodes                []K8sNodeInfo        `json:"nodes"`
    PodPhases            map[string]int       `json:"pod_phases"` // Running/Pending/Failed/Succeeded
    OOMKilledPods        []K8sPodOOM          `json:"oom_killed_pods"`
    EvictedPods          []K8sEviction        `json:"evicted_pods"`
    CrashLoopPods        []K8sCrashLoop       `json:"crash_loop_pods"`
    ImagePullErrors      []K8sImagePullError  `json:"image_pull_errors"`
    PendingPods          []K8sPendingPod      `json:"pending_pods"`
    UnboundPVCs          []K8sPVC             `json:"unbound_pvcs"`
    CoreDNS              K8sCoreDNS           `json:"coredns"`
    BestEffortPods       []K8sBestEffortPod   `json:"best_effort_pods"`
    ThrottledPods        []K8sThrottledPod    `json:"throttled_pods"`
    UnenforcedNamespaces []K8sNamespacePolicy `json:"unenforced_namespaces"` // no LimitRange + no ResourceQuota
    MetricsServerAvail   bool                 `json:"metrics_server_avail"`  // false = ThrottledPods empty
    FailedDeployments    []string             `json:"failed_deployments"`
    WarningEvents        int                  `json:"warning_events"`
    TopWarning           string               `json:"top_warning"`
    Status               string               `json:"status"`
    StatusReason         string               `json:"status_reason"`
}
```

### OOM Signals — Three Distinct Failure Modes

K8s OOM presents three distinct ways, each requiring different remediation:

| Signal | Source | API field | Fix |
|---|---|---|---|
| **Container OOMKilled** | Pod container status | `state.terminated.reason = "OOMKilled"` | Increase memory limit or fix leak |
| **Pod eviction** | Event / Pod status | `status.reason = "Evicted"`, `status.message` contains "memory" | Node memory pressure — scale nodes or reduce requests |
| **Node MemoryPressure** | Node condition | `conditions[].type = "MemoryPressure"` | Node-level — add memory, drain node, or tune eviction thresholds |

The eviction path is especially important: kubelet evicts pods **before** OOMKill as a preventive measure. If you only check `OOMKilled` you miss the earlier warning.

### K8s Pod Failure Modes — Complete Signal Table

All eight pod failure modes DashDiag detects, with the exact API field and remediation:

| Failure | State/Reason | API field | DashDiag check | Fix |
|---|---|---|---|---|
| **OOMKilled** | Terminated | `lastTerminationState.terminated.reason = "OOMKilled"` | `OOMKilledPods` | Raise memory limit or fix leak |
| **Evicted** | Failed | `status.reason = "Evicted"`, message contains "memory" | `EvictedPods` | Node memory pressure — scale or reduce requests |
| **CrashLoopBackOff** | Waiting | `state.waiting.reason = "CrashLoopBackOff"` | `CrashLoopPods` | Fix app crash — check `logs --previous` |
| **ImagePullBackOff** | Waiting | `state.waiting.reason = "ImagePullBackOff"` | `ImagePullErrors` | Fix registry auth or image name/tag |
| **ErrImagePull** | Waiting | `state.waiting.reason = "ErrImagePull"` | `ImagePullErrors` | Same as above — first attempt before backoff |
| **Pending (unschedulable)** | Pending | `PodScheduled=False` condition message | `PendingPods` | Insufficient resources or node affinity mismatch |
| **ContainerCreating (PVC)** | Waiting | `state.waiting.reason = "ContainerCreating"` + unbound PVC | `UnboundPVCs` | Fix storage provisioner or PVC binding |
| **CoreDNS down** | Pod not Running | `kube-system/k8s-app=kube-dns` pods not Ready | `CoreDNS` | Restart CoreDNS pods — all in-cluster DNS fails |
| **BestEffort QoS** | Running | `pod.status.qosClass = "BestEffort"` | `BestEffortPods` | Add `resources:` limits to pod spec |
| **CPU throttled** | Running | metrics-server usage near CPU limit | `ThrottledPods` | Raise CPU limit or remove it for bursty workloads |
| **No LimitRange/Quota** | Namespace | No LimitRange + no ResourceQuota | `UnenforcedNamespaces` | Deploy LimitRange defaults to namespace |

### Implementation Approach

Use `client-go` (Go) or `kube-rs` (Rust) — never parse `kubectl` output. The API client gives you structured data with proper error handling.

```
Prompt for dsd k8s:
"Write internal/collectors/k8s.go using k8s.io/client-go.
Connect via ~/.kube/config or KUBECONFIG env var.
If kubeconfig missing → return single INFO 'K8s not configured', don't error.

Collect:
  1. API server latency: time a GET /healthz, store in ms

  2. Nodes: list all nodes, for each check conditions:
     - Ready=False → CRIT
     - MemoryPressure=True → WARN (evictions may be occurring)
     - DiskPressure=True → WARN
     - PIDPressure=True → WARN

  3. Pod OOM detection — TWO checks:
     a. OOMKilled containers: list all pods, for each container check:
        pod.Status.ContainerStatuses[].LastTerminationState.Terminated.Reason == 'OOMKilled'
        Also capture: exit code (should be 137), memory limit, restart count.
        CRIT if any container OOMKilled in last restart cycle.

     b. Evicted pods: list pods with Status.Phase == 'Failed' AND Status.Reason == 'Evicted'
        Parse Status.Message for 'memory' to confirm memory-driven eviction.
        WARN for evicted pods — they indicate node memory pressure before OOMKill.

  4. CrashLoopBackOff detection:
     Check pod.Status.ContainerStatuses[].State.Waiting.Reason == "CrashLoopBackOff"
     Capture: container name, restart count, last exit code.
     CRIT — pod will never self-recover without intervention.

  5. Image pull failure detection:
     Check State.Waiting.Reason for "ImagePullBackOff" or "ErrImagePull"
     Capture: container name, image name, message (registry error detail).
     CRIT — pod cannot start until image or credentials are fixed.
     Hint: "kubectl describe pod" shows the exact registry error message.

  6. Pending pods with scheduling reason:
     List pods with Status.Phase == "Pending"
     Read pod.Status.Conditions where Type == "PodScheduled" and Status == "False"
     Capture Reason + Message (e.g. "0/3 nodes: Insufficient memory").
     WARN — may resolve when resources free up; CRIT if reason is permanent (bad affinity).

  7. Unbound PVCs:
     List all PVCs across all namespaces.
     Flag any with Status.Phase != "Bound" (Pending = waiting for provisioner).
     Capture: namespace, name, storage class, capacity, phase.
     WARN — pods mounting this PVC will stay in ContainerCreating.

  8. CoreDNS health:
     List pods in kube-system with label k8s-app=kube-dns.
     Count total vs Ready (ContainersReady condition).
     CRIT if 0 Ready — all in-cluster service DNS fails immediately.
     WARN if < total Ready.

  9. Pod phases: count Running/Pending/Failed/Succeeded across all namespaces

  10. Deployments with availableReplicas == 0 → CRIT; < desiredReplicas → WARN

  11. Warning events from last 15 minutes: count + first message

12. BestEffort QoS pods:
     Filter pods where Status.QOSClass == "BestEffort" (no resource limits set).
     Store namespace, pod name, node name.
     WARN if BestEffort pods exist in namespaces that also have Guaranteed/Burstable pods.
     Hint: these are evicted first under node memory pressure.

13. CPU throttling (metrics-server gate):
     First attempt: GET /apis/metrics.k8s.io/v1beta1/pods (check metrics-server available).
     Set MetricsServerAvail = true if call succeeds, false if 404/unavailable.
     If available: for each pod, compare CPU usage vs CPU limit.
     Flag pods where usage > 80% of limit as ThrottledPods.
     WARN — pod is CPU-limited even when node has spare capacity.
     If metrics-server absent: set ThrottledPods = nil, add INFO note.

14. Namespace enforcement check:
     List all namespaces. For each: get LimitRange list and ResourceQuota list.
     Flag namespaces that have running pods but NEITHER LimitRange NOR ResourceQuota.
     WARN — pods deployed to these namespaces get BestEffort QoS by default.
     Skip kube-system, kube-public, kube-node-lease.

RBAC minimum required: get/list nodes, pods, deployments, events, persistentvolumeclaims,
  limitranges, resourcequotas, namespaces (read-only).
  metrics.k8s.io: get/list pods (optional — skip gracefully if unavailable).
Return models.K8sInfo. All list calls use context with 10s timeout."
```

### K8s Tools Worth Integrating (Not Competing With)

- **popeye**: Consider a `dsd k8s audit` that calls popeye as a backend or replicates its top-10 checks
- **K8sGPT**: The `--json` output from `dsd k8s` can be piped into K8sGPT externally — see §25 Possible Future Development
- **Krew plugins**: `dsd k8s` could auto-detect and surface available Krew plugins as "next steps"

---

## 7. General Competitive Landscape

| Tool | Focus | Strengths | Weaknesses |
|---|---|---|---|
| `htop` / `btop` | Process/resource monitoring | Beautiful, interactive, widely adopted | No network or container integration |
| `glances` | Cross-platform system monitoring | Comprehensive, web interface, API | Can feel bloated; Python dependency |
| `neofetch` / `fastfetch` | System info display | Great for sharing, visually appealing | Diagnostic depth is minimal |
| `k9s` | Kubernetes only | Excellent for K8s | Not for general system diagnostics |
| `ctop` | Container only | Great for container metrics | Single-purpose |
| `duf` | Disk usage | Modern `df` replacement | Disk only |
| `netdata` | Full monitoring platform | Dashboards, alerting | Heavy, agent-based, not CLI-first |
| **DashDiag** | **Composable snapshot CLI** | **Shareable + pre-flight + k8s-ready** | You're building it |

**Your real moat:** No tool combines composable subcommands + shareable formatted output + container/k8s pre-flight workflow in a single static binary.

### Fleet Management Tools — Complementary, Not Competitive

A separate category that looks competitive but isn't:

| Tool | What it does | Why DashDiag still fits |
|---|---|---|
| SUSE Multi-Linux Manager (SUMA) | Patch/compliance/config management for 10–100,000 servers | Requires central server + agent registration. DashDiag works before onboarding, during incidents, when agent is broken |
| Red Hat Satellite | Same as SUMA for RHEL estate | Same story — DashDiag is the escape hatch |
| Ansible / SaltStack | Configuration management + orchestration | Push-based, requires connectivity to controller. DashDiag is local-only |
| Datadog / Grafana | Monitoring and alerting platform | DashDiag is the tool for the 30 seconds before you open Datadog |

**The SUSE insight:** SUSE claims 60% of Fortune 500 runs SLES. SUMA manages those fleets. DashDiag is what sysadmins run on individual SLES servers — before SUMA, during incidents, outside SUMA's coverage. These are the same customers, not competing tools.

**Integration angle:** DashDiag's `--json` output is the platform API surface. Fleet tools like SUMA could consume dsd JSON output as a health signal without DashDiag ever needing to know about them. That's the moat — structured output that plugs into any pipeline.

### Objection Handling

**"I just use aliases"** — Aliases don't provide structured output, cross-machine consistency, color-coded status indicators, or summary views with pass/fail logic. DashDiag isn't just running commands; it's interpreting results and presenting actionable conclusions.

**"Just use btop"** — btop is a TUI monitor, not a composable pre-flight check. You can't pipe `btop` into Slack or use it as a CI gate.

**"We already have Datadog/Grafana"** — Those are monitoring platforms. DashDiag is a terminal-first human tool for the 30 seconds before you open Datadog.

---

---

## 8. Permission Model

Most `dsd` checks run without root. Two require elevated privileges and need explicit fallback handling.

### ICMP Ping — the most common first-run failure

Raw ICMP ping requires `CAP_NET_RAW` or root on Linux. A non-root user gets `permission denied` from `go-ping` before any check runs. This will be the most common support issue on day one.

**Detection and fallback strategy:**

```go
// internal/collectors/network_quick.go

func pingWithFallback(host string, count int, timeout time.Duration) (*models.PingStats, error) {
    // Attempt 1: privileged raw ICMP
    pinger, err := ping.NewPinger(host)
    if err != nil {
        return nil, err
    }
    pinger.SetPrivileged(true)
    pinger.Count   = count
    pinger.Timeout = timeout

    if err := pinger.Run(); err != nil {
        // Permission denied → fall back to unprivileged UDP ICMP
        if isPermissionError(err) {
            return pingUnprivileged(host, count, timeout)
        }
        return nil, err
    }
    return statsFromPinger(pinger), nil
}

func pingUnprivileged(host string, count int, timeout time.Duration) (*models.PingStats, error) {
    pinger, err := ping.NewPinger(host)
    if err != nil {
        return nil, err
    }
    pinger.SetPrivileged(false) // UDP ICMP — works without CAP_NET_RAW on most kernels
    pinger.Count   = count
    pinger.Timeout = timeout

    if err := pinger.Run(); err != nil {
        // Both modes failed — return INFO, don't crash
        return &models.PingStats{
            Host:      host,
            Reachable: false,
            SkipReason: "ping requires CAP_NET_RAW or root — install with: sudo setcap cap_net_raw+ep /usr/local/bin/dsd",
        }, nil
    }
    return statsFromPinger(pinger), nil
}

func isPermissionError(err error) bool {
    return strings.Contains(err.Error(), "permission denied") ||
           strings.Contains(err.Error(), "operation not permitted")
}
```

**Grant ping privileges without running as root:**
```bash
# Add to install.sh and document in README
sudo setcap cap_net_raw+ep /usr/local/bin/dsd
```

**Output when ping is unavailable:**
```
[Network]
ℹ️  Gateway ping skipped — requires CAP_NET_RAW
   → sudo setcap cap_net_raw+ep $(which dsd)
ℹ️  Internet skipped (same reason)
```

### Docker Socket — permission without root

```go
// internal/collectors/runtime.go

func newDockerClient(socketPath string) (*RuntimeClient, error) {
    cli, err := client.NewClientWithOpts(
        client.WithHost("unix://" + socketPath),
        client.WithAPIVersionNegotiation(),
    )
    if err != nil {
        return nil, err
    }

    // Ping the daemon to verify access — catches permission errors early
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    if _, err := cli.Ping(ctx); err != nil {
        if isPermissionError(err) {
            return nil, fmt.Errorf(
                "Docker socket at %s: permission denied — add user to docker group: sudo usermod -aG docker $USER",
                socketPath)
        }
        return nil, fmt.Errorf("Docker daemon not responding: %w", err)
    }
    return &RuntimeClient{Client: cli, Socket: socketPath}, nil
}
```

### Privilege summary table

| Check | Requires | Fallback if missing |
|---|---|---|
| ICMP ping (raw) | `CAP_NET_RAW` or root | UDP ICMP mode |
| UDP ICMP ping | No special perms on Linux ≥ 4.1 | Skip with INFO |
| Docker socket | `docker` group membership | Skip with INFO + instructions |
| `/proc/vmstat` | None (world-readable) | — |
| `/sys/block/*/` | None (world-readable) | — |
| zswap debugfs | Root | Skip, set `StatsAvail=false` |
| NTP sync status | None (timedatectl, chronyc) | — |

---

## 9. Container Awareness

Running `dsd health` inside a Docker container returns host metrics by default — host RAM, host swap, host disk. This silently gives wrong answers for container resource checks. Explicit detection and cgroup-aware metric reading is required.

### Container detection

```go
// internal/platform/container.go

package platform

import (
    "os"
    "strings"
)

type ContainerRuntime string
const (
    RuntimeNone       ContainerRuntime = ""
    RuntimeDocker     ContainerRuntime = "docker"
    RuntimeKubernetes ContainerRuntime = "kubernetes"
    RuntimePodman     ContainerRuntime = "podman"
    RuntimeContainerd ContainerRuntime = "containerd"
)

type ContainerContext struct {
    InContainer bool
    Runtime     ContainerRuntime
    // Limits from cgroup (0 = unlimited / not in container)
    MemoryLimitBytes uint64
    CPUQuotaCores    float64 // e.g. 0.5 = half a core
}

func DetectContainerContext() ContainerContext {
    ctx := ContainerContext{}

    // /.dockerenv — present in all Docker containers
    if _, err := os.Stat("/.dockerenv"); err == nil {
        ctx.InContainer = true
        ctx.Runtime     = RuntimeDocker
    }

    // /run/.containerenv — Podman
    if _, err := os.Stat("/run/.containerenv"); err == nil {
        ctx.InContainer = true
        ctx.Runtime     = RuntimePodman
    }

    // cgroup check — also catches containerd/kubernetes
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        s := string(data)
        if strings.Contains(s, "kubepods") {
            ctx.InContainer = true
            ctx.Runtime     = RuntimeKubernetes
        } else if strings.Contains(s, "docker") || strings.Contains(s, "containerd") {
            ctx.InContainer = true
            if ctx.Runtime == "" {
                ctx.Runtime = RuntimeContainerd
            }
        }
    }

    if ctx.InContainer {
        ctx.MemoryLimitBytes = readMemoryLimit()
        ctx.CPUQuotaCores    = readCPUQuota()
    }
    return ctx
}

// readMemoryLimit reads container memory limit from cgroup v2 then v1.
func readMemoryLimit() uint64 {
    // cgroup v2 (Ubuntu 22.04+, Fedora 33+)
    if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
        s := strings.TrimSpace(string(data))
        if s != "max" {
            if v, err := strconv.ParseUint(s, 10, 64); err == nil {
                return v
            }
        }
    }
    // cgroup v1
    if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
        if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
            // 9223372036854771712 = cgroup v1 "no limit" sentinel
            if v < 9223372036854771712 {
                return v
            }
        }
    }
    return 0
}

// readCPUQuota reads container CPU quota as a fraction of cores.
func readCPUQuota() float64 {
    // cgroup v2: cpu.max = "quota period"
    if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
        fields := strings.Fields(strings.TrimSpace(string(data)))
        if len(fields) == 2 && fields[0] != "max" {
            quota, e1  := strconv.ParseFloat(fields[0], 64)
            period, e2 := strconv.ParseFloat(fields[1], 64)
            if e1 == nil && e2 == nil && period > 0 {
                return quota / period
            }
        }
    }
    // cgroup v1
    if quota, e1 := readSysInt("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"); e1 == nil {
        if period, e2 := readSysInt("/sys/fs/cgroup/cpu/cpu.cfs_period_us"); e2 == nil {
            if quota > 0 && period > 0 {
                return float64(quota) / float64(period)
            }
        }
    }
    return 0
}
```

### How collectors use container context

The container context is detected **once** at startup and passed to the runner. Collectors use it to choose the right data source:

```go
// Memory collector — prefers cgroup limit over /proc/meminfo when in container
func (c *MemoryCollector) Collect(ctx context.Context) (interface{}, error) {
    vmem, _ := mem.VirtualMemory()

    total := vmem.Total
    if c.ContainerCtx.InContainer && c.ContainerCtx.MemoryLimitBytes > 0 {
        // Use cgroup limit as "total" — /proc/meminfo shows host RAM
        total = c.ContainerCtx.MemoryLimitBytes
    }
    // ... rest of collection using container-aware total
}
```

### Container banner in output

When running inside a container, every command shows a banner:

```
⚠️  Running inside container (docker) — memory/disk metrics reflect container limits
    Host metrics: use dsd on the host directly for full system view
```

In `--plain` mode: `[WARN] Running inside container (docker) — metrics reflect container limits`

### AI prompt for container awareness

```
Prompt:
"Write internal/platform/container.go with DetectContainerContext().
Detect: /.dockerenv, /run/.containerenv, /proc/1/cgroup keywords (kubepods/docker/containerd)
Read memory limit: try cgroup v2 /sys/fs/cgroup/memory.max first,
  fall back to cgroup v1 /sys/fs/cgroup/memory/memory.limit_in_bytes
  (ignore sentinel value 9223372036854771712)
Read CPU quota: try cgroup v2 /sys/fs/cgroup/cpu.max (format: 'quota period'),
  fall back to v1 cpu.cfs_quota_us / cpu.cfs_period_us

ContainerContext struct: InContainer bool, Runtime string, MemoryLimitBytes uint64, CPUQuotaCores float64

The runner calls DetectContainerContext() once at startup.
Pass it to MemoryCollector and CPUCollector via struct field.
Memory collector: if InContainer && MemoryLimitBytes > 0, use limit as Total.
CPU collector: if CPUQuotaCores > 0, use as effective core count for load avg context."
```

---

---

## 10. Proxmox VE Support

### Three Distinct Contexts

Proxmox creates three fundamentally different environments. DashDiag must detect which one it is in before deciding which checks to run.

```
Context A: ON the Proxmox host (bare-metal hypervisor)
           → Full access to /etc/pve/, pvesh, ZFS pools, corosync
           → Proxmox-specific checks are meaningful and critical

Context B: INSIDE a Proxmox KVM virtual machine
           → Looks like a normal Linux VM — standard checks apply
           → Add: QEMU guest agent running, virtio driver detection

Context C: INSIDE a Proxmox LXC container
           → Unprivileged container, reduced /proc visibility
           → Already handled by container detection
           → Add: explicit LXC detection, hypervisor-level limit note
```

**Detection — `internal/platform/proxmox.go`:**

```go
package platform

import (
    "os"
    "os/exec"
    "strings"
)

type ProxmoxContext struct {
    IsProxmoxHost bool
    IsProxmoxVM   bool
    IsProxmoxLXC  bool
    PVEVersion    string
    NodeName      string
}

func DetectProxmoxContext() ProxmoxContext {
    ctx := ProxmoxContext{}

    // Host: pveversion binary present and executable
    if _, err := os.Stat("/usr/bin/pveversion"); err == nil {
        ctx.IsProxmoxHost = true
        if out, err := exec.Command("pveversion").Output(); err == nil {
            ctx.PVEVersion = strings.TrimSpace(string(out))
        }
        ctx.NodeName, _ = os.Hostname()
        return ctx
    }

    // LXC: container=lxc in /proc/1/environ or /.lxc exists
    if data, err := os.ReadFile("/proc/1/environ"); err == nil {
        if strings.Contains(string(data), "container=lxc") {
            ctx.IsProxmoxLXC = true
            return ctx
        }
    }
    if _, err := os.Stat("/.lxc"); err == nil {
        ctx.IsProxmoxLXC = true
        return ctx
    }

    // KVM VM: QEMU vendor + Proxmox-style SMBIOS product name
    vendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
    if strings.Contains(string(vendor), "QEMU") {
        product, _ := os.ReadFile("/sys/class/dmi/id/product_name")
        if strings.Contains(string(product), "Standard PC") {
            ctx.IsProxmoxVM = true
        }
    }

    return ctx
}
```

---

### Proxmox Host Checks (`dsd pve`)

#### 1. Cluster Quorum — most critical check

A node without quorum refuses to start VMs and may fence itself. High WARN value — one more failure causes total loss. This is the #1 silent failure in multi-node Proxmox clusters.

```go
// internal/collectors/pve_cluster.go

type PVEClusterCollector struct{}

func (c *PVEClusterCollector) Name()    string        { return "PVE Cluster" }
func (c *PVEClusterCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *PVEClusterCollector) Collect(ctx context.Context) (interface{}, error) {
    // Try pvesh first (requires root or PVEAuditor role)
    out, err := exec.CommandContext(ctx,
        "pvesh", "get", "/cluster/status", "--output-format", "json").Output()
    if err == nil {
        return parsePVEClusterStatus(out), nil
    }

    // Fallback: corosync-quorumtool (no special permissions needed)
    out, err = exec.CommandContext(ctx, "corosync-quorumtool", "-s").Output()
    if err != nil {
        // Single node (no cluster configured) — not an error
        return models.PVEClusterInfo{
            InCluster: false,
            Status:    "OK",
            StatusReason: "single-node (no cluster configured)",
        }, nil
    }
    return parseCorosyncTool(string(out)), nil
}
```

**Data model — `internal/models/pve.go`:**

```go
package models

type PVEClusterInfo struct {
    InCluster    bool
    ClusterName  string
    QuorumOK     bool
    NodesTotal   int
    NodesOnline  int
    NodeName     string
    Status       string
    StatusReason string
}

type ZFSPoolInfo struct {
    Name         string
    Health       string   // ONLINE / DEGRADED / FAULTED / OFFLINE / REMOVED / UNAVAIL
    SizeGB       float64
    UsedPct      float64
    Fragmentation int     // % fragmentation (> 50% degrades performance)
    ScrubAge     int      // days since last scrub (> 30 = WARN)
    Status       string
    StatusReason string
}

type PVEGuestSummary struct {
    VMsRunning   int
    VMsStopped   int
    VMsError     int
    LXCRunning   int
    LXCStopped   int
    LXCError     int
    ErrorGuests  []string // IDs/names of error-state guests
    Status       string
    StatusReason string
}

type PVEKernelInfo struct {
    IsPVEKernel  bool
    Version      string
    Status       string
    StatusReason string
}

type PVEHostInfo struct {
    Cluster      PVEClusterInfo
    ZFSPools     []ZFSPoolInfo
    Guests       PVEGuestSummary
    Kernel       PVEKernelInfo
    PVEVersion   string
    NodeName     string
    RepoConfig   string   // "enterprise" / "no-subscription" / "community" / "unknown"
}
```

#### 2. ZFS Pool Health

ZFS pools need 25% free space for copy-on-write operations. Standard 80% disk threshold is wrong here — use 75%. Degraded pools serve I/O silently until the next drive fails.

```go
// internal/collectors/pve_zfs.go

func collectZFSPools(ctx context.Context) ([]models.ZFSPoolInfo, error) {
    // zpool list -H -p -o name,health,size,alloc,free,cap,frag
    // -H: no header, -p: parseable numbers
    out, err := exec.CommandContext(ctx,
        "zpool", "list", "-H", "-p",
        "-o", "name,health,size,alloc,free,cap,frag").Output()
    if err != nil {
        // ZFS not installed — not an error on non-ZFS systems
        if strings.Contains(err.Error(), "not found") ||
           strings.Contains(err.Error(), "no such file") {
            return nil, nil
        }
        return nil, fmt.Errorf("zpool list: %w", err)
    }

    var pools []models.ZFSPoolInfo
    for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
        fields := strings.Fields(line)
        if len(fields) < 7 {
            continue
        }
        sizeBytes, _ := strconv.ParseUint(fields[2], 10, 64)
        capPct, _    := strconv.ParseFloat(strings.TrimSuffix(fields[5], "%"), 64)
        frag, _      := strconv.Atoi(strings.TrimSuffix(fields[6], "%"))

        health := fields[1]
        status, reason := zfsPoolStatus(health, capPct, frag)

        pools = append(pools, models.ZFSPoolInfo{
            Name:          fields[0],
            Health:        health,
            SizeGB:        float64(sizeBytes) / 1e9,
            UsedPct:       capPct,
            Fragmentation: frag,
            Status:        status,
            StatusReason:  reason,
        })
    }
    return pools, nil
}

func zfsPoolStatus(health string, usedPct float64, frag int) (string, string) {
    switch health {
    case "FAULTED":
        return "CRIT", "pool FAULTED — data loss risk, act immediately"
    case "DEGRADED":
        return "CRIT", "pool DEGRADED — redundancy lost, scrub and replace failed device"
    case "OFFLINE", "REMOVED", "UNAVAIL":
        return "CRIT", fmt.Sprintf("pool %s — not accessible", health)
    }
    // ONLINE — check usage (ZFS needs headroom for CoW)
    switch {
    case usedPct > 85:
        return "CRIT", fmt.Sprintf("ZFS pool %.0f%% full — CoW operations at risk, snapshots may fail", usedPct)
    case usedPct > 75:
        return "WARN", fmt.Sprintf("ZFS pool %.0f%% full — approaching CoW headroom limit (75%%)", usedPct)
    case frag > 50:
        return "WARN", fmt.Sprintf("pool fragmentation %d%% — consider zpool scrub and defrag", frag)
    default:
        return "OK", ""
    }
}
```

#### 3. VM and LXC Guest Inventory

```go
// internal/collectors/pve_guests.go

func collectPVEGuests(ctx context.Context, node string) (models.PVEGuestSummary, error) {
    // Try qm list (no JSON but widely available without pvesh)
    vmOut, vmErr := exec.CommandContext(ctx, "qm", "list").Output()
    lxcOut, lxcErr := exec.CommandContext(ctx, "pct", "list").Output()

    var summary models.PVEGuestSummary

    if vmErr == nil {
        for _, line := range strings.Split(string(vmOut), "\n")[1:] { // skip header
            fields := strings.Fields(line)
            if len(fields) < 3 { continue }
            switch fields[2] {
            case "running":  summary.VMsRunning++
            case "stopped":  summary.VMsStopped++
            default:
                summary.VMsError++
                summary.ErrorGuests = append(summary.ErrorGuests,
                    fmt.Sprintf("VM %s (%s)", fields[0], fields[2]))
            }
        }
    }

    if lxcErr == nil {
        for _, line := range strings.Split(string(lxcOut), "\n")[1:] {
            fields := strings.Fields(line)
            if len(fields) < 3 { continue }
            switch fields[1] {
            case "running":  summary.LXCRunning++
            case "stopped":  summary.LXCStopped++
            default:
                summary.LXCError++
                summary.ErrorGuests = append(summary.ErrorGuests,
                    fmt.Sprintf("LXC %s (%s)", fields[0], fields[1]))
            }
        }
    }

    if len(summary.ErrorGuests) > 0 {
        summary.Status = "WARN"
        summary.StatusReason = fmt.Sprintf(
            "%d guest(s) in error state: %s",
            len(summary.ErrorGuests),
            strings.Join(summary.ErrorGuests, ", "))
    } else {
        summary.Status = "OK"
    }
    return summary, nil
}
```

#### 4. PVE Kernel Check

Proxmox ships a patched kernel. If the system boots the upstream Debian kernel, live migration, ZFS performance, and hardware passthrough break silently.

```go
// internal/collectors/pve_kernel.go

func checkPVEKernel() models.PVEKernelInfo {
    data, err := os.ReadFile("/proc/version")
    if err != nil {
        return models.PVEKernelInfo{Status: "INFO", StatusReason: "cannot read /proc/version"}
    }
    version := strings.TrimSpace(string(data))
    isPVE   := strings.Contains(version, "pve") ||
               strings.Contains(version, "-proxmox")

    if isPVE {
        return models.PVEKernelInfo{
            IsPVEKernel:  true,
            Version:      version,
            Status:       "OK",
        }
    }
    return models.PVEKernelInfo{
        IsPVEKernel:  false,
        Version:      version,
        Status:       "WARN",
        StatusReason: "not running PVE kernel — check grub boot entry; live migration and ZFS may be affected",
    }
}
```

#### 5. Repository / Subscription Config

```go
// internal/collectors/pve_repo.go

func checkPVERepo() string {
    enterprise, _ := os.ReadFile("/etc/apt/sources.list.d/pve-enterprise.list")
    nosub, _      := os.ReadFile("/etc/apt/sources.list.d/pve-no-subscription.list")

    eActive := len(enterprise) > 0 &&
        !strings.Contains(string(enterprise), "#")
    nActive := len(nosub) > 0 &&
        !strings.Contains(string(nosub), "#")

    switch {
    case eActive:  return "enterprise"
    case nActive:  return "no-subscription"
    default:       return "unknown"
    }
}
```

---

### Proxmox KVM VM Checks (Context B)

#### QEMU Guest Agent

Without the guest agent, Proxmox cannot perform clean shutdown, live snapshot, or live migration. A common misconfiguration that causes mysterious failures.

```go
// internal/collectors/pve_vm.go

func checkQEMUGuestAgent(ctx context.Context) (bool, string) {
    out, err := exec.CommandContext(ctx,
        "systemctl", "is-active", "qemu-guest-agent").Output()
    if err != nil {
        return false, "qemu-guest-agent not installed or not running — Proxmox live migration and snapshots may fail"
    }
    return strings.TrimSpace(string(out)) == "active", ""
}
```

#### Virtio Driver Detection

Emulated `IDE`/`SATA` drivers give ~10x worse IO than `virtio-blk`/`virtio-scsi`. Silent performance degradation.

```go
func checkVirtioDrivers() []string {
    var nonVirtio []string
    entries, _ := filepath.Glob("/sys/block/*/device/model")
    for _, path := range entries {
        data, err := os.ReadFile(path)
        if err != nil {
            continue
        }
        model := strings.TrimSpace(string(data))
        // "QEMU HARDDISK" = emulated IDE/SATA, not virtio
        if strings.Contains(model, "QEMU HARDDISK") {
            dev := strings.Split(path, "/")[3]
            nonVirtio = append(nonVirtio, dev)
        }
    }
    return nonVirtio
}
```

---

### Proxmox LXC Container Note (Context C)

Memory and CPU limits set at the Proxmox host level are not visible from inside an unprivileged LXC container. The cgroup values show `max` (unlimited) even when the host has set hard limits. Report this clearly:

```go
// In container awareness banner when IsProxmoxLXC = true:
// "ℹ️  Proxmox LXC container — memory/CPU limits set by hypervisor are not
//     visible from inside. Run 'pct config <id>' on the host to see actual limits."
```

---

### AI Prompts for Proxmox Collectors

**Context detection:**
```
Prompt:
"Write internal/platform/proxmox.go with DetectProxmoxContext() returning ProxmoxContext.
Detection priority:
  1. Host: /usr/bin/pveversion exists → IsProxmoxHost=true, run pveversion for version
  2. LXC: /proc/1/environ contains 'container=lxc' OR /.lxc exists → IsProxmoxLXC=true
  3. KVM VM: /sys/class/dmi/id/sys_vendor contains 'QEMU' AND
     /sys/class/dmi/id/product_name contains 'Standard PC' → IsProxmoxVM=true
  4. None of above: return zero-value ProxmoxContext (all false)
All file reads are best-effort — no errors returned from DetectProxmoxContext()."
```

**Host collector:**
```
Prompt:
"Write internal/collectors/pve_host.go with PVEHostCollector.
Timeout: 10 seconds.
Collect concurrently:
  1. Cluster: try 'pvesh get /cluster/status --output-format json' first,
     fall back to 'corosync-quorumtool -s' if pvesh fails or returns permission error,
     if neither available → InCluster=false (single node)
  2. ZFS pools: 'zpool list -H -p -o name,health,size,alloc,free,cap,frag'
     If zpool not found → return empty slice (not an error)
     ZFS-specific thresholds: WARN usage > 75% (NOT 80%), CRIT > 85%
     Also flag: frag > 50% → WARN
  3. Guests: 'qm list' for VMs, 'pct list' for LXC
     If commands not found → skip (not an error)
     Flag any guest not in running/stopped state as error guest
  4. Kernel: read /proc/version, WARN if 'pve' or 'proxmox' not in string
  5. Repo: read /etc/apt/sources.list.d/pve-*.list files, return repo type string
All exec calls use exec.CommandContext. Permission errors return INFO, not CRIT."
```

**VM collector:**
```
Prompt:
"Write internal/collectors/pve_vm.go with PVEVMCollector.
Only runs when ProxmoxContext.IsProxmoxVM == true.
Timeout: 3 seconds.
Collect:
  1. QEMU guest agent: 'systemctl is-active qemu-guest-agent'
     WARN if not active — affects Proxmox live migration and clean snapshot
  2. Virtio drivers: scan /sys/block/*/device/model
     Flag any device with 'QEMU HARDDISK' as using emulated driver (INFO level)
     Emulated = 10x worse IO than virtio — useful to know, not critical
Both checks are best-effort. Not installed = INFO, not WARN."
```

---

### Target Output — `dsd pve` on healthy host

```
🖥️  Proxmox VE diagnostics… (pve-manager/8.1.3)

[Cluster]
✅ proxmox-cluster  Quorate: Yes  |  Nodes: 3/3 online

[ZFS Pools]
✅ rpool    ONLINE  2.3TB  42% used  frag: 8%
✅ vmdata   ONLINE  7.8TB  61% used  frag: 12%

[Guests]
✅ VMs:  12 running  /  3 stopped
✅ LXC:  8 running   /  2 stopped

[Kernel]
✅ Running PVE kernel 6.5.13-3-pve

[Repo]
ℹ️  Repository: no-subscription (homelab/dev — not for production)

— Summary —
Node: pve-node1  |  PVE: 8.1.3  |  Status: ✅ Healthy
```

### Target Output — `dsd pve` with problems

```
🖥️  Proxmox VE diagnostics…

[Cluster]
❌ proxmox-cluster  Quorate: NO  |  Nodes: 1/3 online  ← SPLIT-BRAIN RISK
   → corosync-quorumtool -s | journalctl -u corosync

[ZFS Pools]
✅ rpool    ONLINE  2.3TB  44% used  frag: 9%
❌ vmdata   DEGRADED        7.8TB     ← drive failure, redundancy lost
   → zpool status vmdata | zpool scrub vmdata

[Guests]
⚠️  VMs:  11 running  /  3 stopped  /  1 error  ← VM 102 (webserver)
   → qm status 102 | journalctl -u pve-manager

[Kernel]
⚠️  NOT running PVE kernel (running: 6.1.0-17-amd64)
   → check /etc/default/grub — wrong boot entry selected

— Summary —
Node: pve-node1  |  PVE: 8.1.3  |  Status: ❌ 3 issues need attention
```

---

### Privilege Summary — Proxmox Checks

| Check | Requires | Fallback |
|---|---|---|
| `pvesh` cluster status | Root or `PVEAuditor` role | `corosync-quorumtool` (no perms needed) |
| `zpool list` | None (world-readable) | — |
| `qm list` / `pct list` | Root or `PVEAdmin` group | Skip with INFO |
| `/proc/version` kernel | None | — |
| `/etc/apt/sources.list.d/` | None (world-readable) | — |
| QEMU guest agent check | None (`systemctl`) | — |
| Virtio driver detection | None (`/sys/block/*/`) | — |

---

### Threshold Summary — Proxmox Checks

| Check | OK | WARN | CRIT |
|---|---|---|---|
| Cluster quorum | Yes, all nodes online | Yes, 1+ node offline | No quorum |
| ZFS pool health | ONLINE | — | DEGRADED / FAULTED / UNAVAIL |
| ZFS pool usage | < 75% | 75–85% | > 85% |
| ZFS fragmentation | < 30% | 30–50% | > 50% |
| Guest in error state | 0 | 1+ | — |
| PVE kernel | Running PVE kernel | Not PVE kernel | — |
| QEMU guest agent | Running | Not running | — |

## 11. Missing Critical Checks

These checks are not in the initial roadmap but belong in MVP or Phase 2.

### NTP / Clock Synchronization

Clock skew causes TLS failures, JWT rejections, log correlation errors, Kubernetes certificate issues, and distributed tracing drift. It is one of the top causes of "nothing changed but something broke" incidents. Costs one system call to check.

```go
// internal/collectors/clock.go

// ClockInfo — result model for clock synchronization check.
// Lives in internal/models/clock.go
type ClockInfo struct {
    Synced        bool    `json:"synced"`
    OffsetMs      float64 `json:"offset_ms"`       // -1 if unavailable (macOS)
    Source        string  `json:"source"`           // timedatectl / chronyc / systemsetup
    Status        string  `json:"status"`
    StatusReason  string  `json:"status_reason"`
}

// NetworkInfo — result model for network quick check.
// Lives in internal/models/network.go
type NetworkInfo struct {
    Interfaces    []InterfaceInfo `json:"interfaces"`
    GatewayPingMs float64         `json:"gateway_ping_ms"`
    InternetPingMs float64        `json:"internet_ping_ms"`
    DNSResolvesMs  float64        `json:"dns_resolves_ms"`
    CloseWaitCount int             `json:"close_wait_count"`
    NATDetected    bool            `json:"nat_detected"`
    Status         string          `json:"status"`
    StatusReason   string          `json:"status_reason"`
}

type InterfaceInfo struct {
    Name    string `json:"name"`
    Up      bool   `json:"up"`
    IP      string `json:"ip"`
    RxDrops uint64 `json:"rx_drops"`
    TxDrops uint64 `json:"tx_drops"`
}

// ClockInfo — result model for clock synchronization check.
// Lives in internal/models/clock.go
type ClockInfo struct {
    Synced       bool    `json:"synced"`
    OffsetMs     float64 `json:"offset_ms"`      // -1 if unavailable (macOS)
    Source       string  `json:"source"`          // timedatectl / chronyc / systemsetup
    Status       string  `json:"status"`
    StatusReason string  `json:"status_reason"`
}

// NetworkInfo — result model for network quick checks.
// Lives in internal/models/network.go
type NetworkInfo struct {
    Interfaces     []InterfaceInfo `json:"interfaces"`
    GatewayPingMs  float64         `json:"gateway_ping_ms"`
    InternetPingMs float64         `json:"internet_ping_ms"`
    DNSResolvesMs  float64         `json:"dns_resolves_ms"`
    CloseWaitCount int             `json:"close_wait_count"`
    NATDetected    bool            `json:"nat_detected"`
    Status         string          `json:"status"`
    StatusReason   string          `json:"status_reason"`
}

type InterfaceInfo struct {
    Name    string `json:"name"`
    Up      bool   `json:"up"`
    IP      string `json:"ip"`
    RxDrops uint64 `json:"rx_drops"`
    TxDrops uint64 `json:"tx_drops"`
}

type ClockCollector struct{}

func (c *ClockCollector) Name()    string        { return "Clock" }
func (c *ClockCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *ClockCollector) Collect(ctx context.Context) (interface{}, error) {
    // Method 1: timedatectl (systemd Linux systems)
    out, err := exec.CommandContext(ctx, "timedatectl", "show",
        "--property=NTPSynchronized,TimeUSec,NTPService").Output()
    if err == nil {
        return parseTimedatectl(string(out)), nil
    }

    // Method 2: chronyc tracking (non-systemd Linux / some macOS)
    out, err = exec.CommandContext(ctx, "chronyc", "tracking").Output()
    if err == nil {
        return parseChronyc(string(out)), nil
    }

    // Method 3: macOS — systemsetup (no root required, read-only)
    // "Network Time: On" or "Network Time: Off"
    out, err = exec.CommandContext(ctx, "systemsetup", "-getusingnetworktime").Output()
    if err == nil {
        return parseMacOSNetworkTime(string(out)), nil
    }

    // Method 4: /run/systemd/timesync/synchronized (read-only file)
    if _, err := os.Stat("/run/systemd/timesync/synchronized"); err == nil {
        return models.ClockInfo{Synchronized: true, Source: "systemd-timesyncd"}, nil
    }

    return models.ClockInfo{
        Synchronized: false,
        SkipReason:   "NTP status unavailable (no timedatectl, chronyc, systemsetup, or systemd-timesyncd)",
    }, nil
}

// parseMacOSNetworkTime parses the output of 'systemsetup -getusingnetworktime'.
// Output: "Network Time: On" or "Network Time: Off"
// Note: this only tells us if NTP is configured, not the actual offset.
// For offset we would need 'sntp -K /dev/null pool.ntp.org' which is slower.
func parseMacOSNetworkTime(out string) models.ClockInfo {
    lower := strings.ToLower(strings.TrimSpace(out))
    if strings.Contains(lower, "on") {
        return models.ClockInfo{
            Synchronized: true,
            Source:       "macOS systemsetup",
            // Offset not available without sntp — report as OK if NTP enabled
            OffsetMs:     0,
            Status:       "OK",
            StatusReason: "NTP enabled via macOS Network Time (offset not measurable without sntp)",
        }
    }
    return models.ClockInfo{
        Synchronized: false,
        Source:       "macOS systemsetup",
        Status:       "CRIT",
        StatusReason: "Network Time disabled — run: sudo systemsetup -setusingnetworktime on",
    }
}
```

**Thresholds:**
```
Synchronized, offset < 100ms  →  ✅ OK
Synchronized, offset 100–500ms →  ⚠️  WARN  (degraded sync)
Synchronized, offset > 500ms   →  ❌ CRIT  (will cause auth failures)
Not synchronized               →  ❌ CRIT  (clock may drift freely)
```

**Output:**
```
✅ Clock: synchronized via chrony  (offset: +2ms)
❌ Clock: NOT synchronized — 47s drift — TLS/JWT failures likely
   → systemctl start chronyd   or   timedatectl set-ntp true
```

### File Descriptor Limits

Running out of file descriptors causes mysterious connection failures, "too many open files" errors, and database connection pool exhaustion. Common in long-running services on default-configured systems.

```go
// internal/collectors/fdlimits.go

// FDInfo holds system-wide and per-process file descriptor stats.
// (struct definition lives in internal/models/fdlimits.go)

func collectFDLimits() (models.FDInfo, error) {
    // ── System-wide ──────────────────────────────────────────────────────────
    // /proc/sys/fs/file-nr: [open_count, unused_count, max_count]
    data, err := os.ReadFile("/proc/sys/fs/file-nr")
    if err != nil {
        return models.FDInfo{}, err
    }
    fields := strings.Fields(strings.TrimSpace(string(data)))
    if len(fields) < 3 {
        return models.FDInfo{}, fmt.Errorf("unexpected file-nr format")
    }
    open, _ := strconv.ParseUint(fields[0], 10, 64)
    max, _   := strconv.ParseUint(fields[2], 10, 64)
    usedPct  := float64(open) / float64(max) * 100

    info := models.FDInfo{
        OpenCount: open,
        MaxCount:  max,
        UsedPct:   usedPct,
    }

    // ── Per-process check ────────────────────────────────────────────────────
    // Scan each process for its soft FD limit vs actual open count.
    // A single process can hit ulimit -n (default 1024) while system-wide FDs are fine.
    info.HotProcesses = findFDHotProcesses()

    // ── Deleted-but-open files ("ghost space") ───────────────────────────────
    // Files deleted from the directory but held open by a process.
    // Disk blocks still consumed — invisible to df -h vs du gap.
    info.DeletedOpenFiles, info.DeletedOpenSizeGB = countDeletedOpenFiles()

    // ── Status ───────────────────────────────────────────────────────────────
    switch {
    case usedPct > 90:
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf("system FDs %.0f%% exhausted (%d/%d)", usedPct, open, max)
    case usedPct > 80:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf("system FDs %.0f%% used (%d/%d)", usedPct, open, max)
    case len(info.HotProcesses) > 0:
        info.Status = "WARN"
        p := info.HotProcesses[0]
        info.StatusReason = fmt.Sprintf(
            "process %s (PID %d) at %.0f%% of its FD limit (%d/%d)",
            p.Name, p.PID, p.UsedPct, p.OpenFDs, p.SoftLimit)
    case info.DeletedOpenSizeGB > 1.0:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf(
            "%d deleted-but-open file(s) holding %.1fGB — restart holding processes to reclaim",
            info.DeletedOpenFiles, info.DeletedOpenSizeGB)
    default:
        info.Status = "OK"
    }

    return info, nil
}

// findFDHotProcesses scans /proc/[0-9]*/limits for processes
// where open FD count > 80% of their per-process soft limit.
// Reads /proc/<PID>/limits for the soft limit and counts
// entries in /proc/<PID>/fd/ for actual open count.
func findFDHotProcesses() []FDProcessInfo {
    entries, _ := filepath.Glob("/proc/[0-9]*/limits")
    var hot []FDProcessInfo

    for _, limPath := range entries {
        pidStr := strings.Split(limPath, "/")[2]
        pid, err := strconv.Atoi(pidStr)
        if err != nil { continue }

        softLimit := readFDSoftLimit(limPath)
        if softLimit == 0 { continue }

        fdEntries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
        if err != nil { continue } // process may have exited

        openFDs := len(fdEntries)
        usedPct := float64(openFDs) / float64(softLimit) * 100

        if usedPct < 80 { continue }

        name := readProcessName(pid)
        hot = append(hot, FDProcessInfo{
            PID:       pid,
            Name:      name,
            OpenFDs:   openFDs,
            SoftLimit: softLimit,
            UsedPct:   usedPct,
        })
    }

    // Sort by UsedPct descending, cap at 5
    sort.Slice(hot, func(i, j int) bool { return hot[i].UsedPct > hot[j].UsedPct })
    if len(hot) > 5 { hot = hot[:5] }
    return hot
}

// readFDSoftLimit parses the "Max open files" soft limit from /proc/<PID>/limits.
func readFDSoftLimit(limPath string) int {
    data, err := os.ReadFile(limPath)
    if err != nil { return 0 }
    for _, line := range strings.Split(string(data), "
") {
        if !strings.HasPrefix(line, "Max open files") { continue }
        fields := strings.Fields(line)
        if len(fields) < 4 { continue }
        v, _ := strconv.Atoi(fields[3]) // "Soft Limit" column
        return v
    }
    return 0
}

// countDeletedOpenFiles counts files with link count 0 (deleted but still open).
// Scans /proc/[0-9]*/fd/* and checks link count via Lstat.
// Returns count and estimated total size in GB.
func countDeletedOpenFiles() (count int, sizeGB float64) {
    // Fast path: parse /proc/[0-9]*/maps and fd symlinks
    // For each /proc/<PID>/fd/<N>, stat the target — if nlink==0, file is deleted
    entries, _ := filepath.Glob("/proc/[0-9]*/fd/*")
    seen := make(map[string]bool)

    for _, fdPath := range entries {
        target, err := os.Readlink(fdPath)
        if err != nil { continue }
        if seen[target] { continue }
        seen[target] = true

        info, err := os.Lstat(target)
        if err != nil {
            // File no longer in filesystem — check if it is a deleted entry
            // /proc/<PID>/fd/<N> → "/path/to/file (deleted)"
            if strings.Contains(target, "(deleted)") {
                count++
                // Can't get size without the inode — estimate from /proc/<PID>/fdinfo
                // For now count only
            }
            continue
        }
        // Nlink == 0 means all directory entries removed but file still open
        if info.Sys() != nil {
            if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink == 0 {
                count++
                sizeGB += float64(stat.Size) / 1e9
            }
        }
    }
    return count, sizeGB
}

// readProcessName reads the process name from /proc/<PID>/comm.
func readProcessName(pid int) string {
    data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
    return strings.TrimSpace(string(data))
}
```

**`internal/models/fdlimits.go` — extended model:**

```go
package models

type FDInfo struct {
    OpenCount         uint64         `json:"open_count"`          // system-wide open FDs
    MaxCount          uint64         `json:"max_count"`           // kernel maximum
    UsedPct           float64        `json:"used_pct"`
    HotProcesses      []FDProcessInfo `json:"hot_processes"`      // processes near per-process limit
    DeletedOpenFiles  int            `json:"deleted_open_files"`  // deleted-but-open count
    DeletedOpenSizeGB float64        `json:"deleted_open_size_gb"` // disk held by deleted files
    Status            string         `json:"status"`
    StatusReason      string         `json:"status_reason"`
}

type FDProcessInfo struct {
    PID       int     `json:"pid"`
    Name      string  `json:"name"`
    OpenFDs   int     `json:"open_fds"`
    SoftLimit int     `json:"soft_limit"`
    UsedPct   float64 `json:"used_pct"`
}
```

**Output:**
```
✅ File descriptors: 4,821 / 524,288  (1%)

# Per-process saturation:
⚠️  nginx (PID 1234): 982/1024 FDs (96% of ulimit) ← about to hit limit
   → cat /proc/1234/limits | grep "open files"
   → ls /proc/1234/fd | wc -l
   → lsof -p 1234 | tail -20

# Deleted-but-open files (ghost space):
⚠️  3 deleted file(s) holding 4.2GB — df shows full but du doesn't
   → lsof +L1  (find which processes hold deleted files)
   → restart the holding process to reclaim disk space
```

### Self-Update

```go
// cmd/update.go

var updateCmd = &cobra.Command{
    Use:   "update",
    Short: "Check for and install latest version",
    Run: func(cmd *cobra.Command, args []string) {
        latest, err := fetchLatestVersion("yourusername/dashdiag")
        if err != nil {
            fmt.Fprintf(os.Stderr, "update check failed: %v
", err)
            return
        }
        if latest == version.Version {
            fmt.Printf("✅ dsd %s is up to date
", version.Version)
            return
        }
        fmt.Printf("⬆️  dsd %s → %s available
", version.Version, latest)
        fmt.Println("Update with:")
        fmt.Println("  brew upgrade dsd          # macOS/Linux Homebrew")
        fmt.Println("  curl -sSL https://install.dashdiag.sh | sh   # manual")
    },
}

// Background update notification — check once per day, non-blocking
func checkUpdateBackground() {
    cacheFile := filepath.Join(os.TempDir(), ".dsd-update-check")
    stat, err := os.Stat(cacheFile)
    if err == nil && time.Since(stat.ModTime()) < 24*time.Hour {
        return // checked recently
    }
    go func() {
        latest, err := fetchLatestVersion("yourusername/dashdiag")
        if err != nil || latest == version.Version {
            return
        }
        // Write to stderr so it doesn't corrupt --json output
        fmt.Fprintf(os.Stderr, "
ℹ️  dsd %s available — run: dsd update

", latest)
        os.WriteFile(cacheFile, []byte(latest), 0644)
    }()
}
```

### Check placement in commands

| Check | `dsd health` | `dsd full` | Phase |
|---|---|---|---|
| NTP sync | ✅ | ✅ | MVP |
| FD limits | ✅ | ✅ | MVP |
| Container detection | ✅ (banner) | ✅ | MVP |
| `--version` | ✅ | ✅ | MVP |
| Shell completions | N/A | N/A | MVP |
| Self-update check | background | background | MVP |

---

## 12. Roadmap

### Build-Order Rule

> **Never build `deep` before `fast` is in production use.**
>
> Each fast command (`dsd health`, `dsd net`, `dsd k8s`) must be shipped, used
> by real engineers on real servers, and generating feedback before its `deep`
> variant is started. If a fast command has not been run by at least 10 engineers
> in real incidents, the deep variant has not earned its place yet.
>
> This applies to every module:
> - `dsd net` ships → real usage → `dsd net deep` starts
> - `dsd k8s` ships → real usage → `dsd k8s deep` starts
> - `dsd health` ships → real usage → `dsd health deep` starts
>
> **Why:** The fast version defines the data model, collector interface, and renderer.
> The deep version reuses all of that. Real usage also tells you which `deep` checks
> engineers actually want — you may discover nobody needs `dsd net deep` but everyone
> wants `dsd k8s deep`. Ship fast, learn, then invest.

---

### Phase 1 — Ship `dsd health` + `dsd net` (weeks 1–3)

**Goal:** One working binary, two commands, real engineers running it daily.

- [ ] `dsd health` — 12 collectors: CPU, RAM (cgroup-aware), disk, swap (zram-aware),
      IO, network, clock, FD limits, systemd units, sysctl, SELinux/AppArmor, processes (~5s)
- [ ] `dsd net` — network snapshot: interfaces, gateway ping, DNS, TCP states (~3s)
- [ ] `--plain`, `--report`, `--report --out <file>`, `--json`, `--yaml`, `--debug`, `--compact` on all commands
- [ ] `--dry-run` on file-writing operations: `dsd init`, `dsd hook install`, `dsd policy check`
- [ ] `--diff` — baseline auto-save + delta renderer (Priority 1 viral, 1 day)
- [ ] `--since-deploy` — auto-detect last service restart + diff against pre-deploy baseline (Priority 1b, 0.5 days)
- [ ] `--story` — deterministic narrative renderer (Priority 2 viral, 2 days)
- [ ] `--post-mortem "title"` — incident template renderer (Priority 3 viral, 1 day)
- [ ] `--qr` — QR code terminal output alongside `--share` (Priority 6 viral, 2 hours)
- [ ] `--version` + `dsd version --json` with build-time ldflags injection
- [ ] `dsd completion bash|zsh|fish` shell completions
- [ ] Exit codes: `0` (all pass), `1` (warnings), `2` (critical)
- [ ] ICMP privilege fallback (CAP_NET_RAW → UDP ICMP → skip with INFO)
- [ ] Container detection + cgroup v1/v2 memory/CPU limit awareness
- [ ] Background update notification (once per day, non-blocking)
- [ ] Config file support (`~/.dsd.yaml`) for thresholds
- [ ] Multi-distro CI matrix (ubuntu-22.04, ubuntu-20.04, macOS, alpine, ubi8)
- [ ] Golden file output tests for all render paths
- [ ] Fuzz tests for all `/proc` and `/sys` parsers
- [ ] Contract tests: JSON schema in `schema/dsd-output.json`
- [ ] Smoke test script `scripts/smoke-test.sh`
- [ ] `govulncheck` + `gosec` + `gitleaks` in security CI (every PR)
- [ ] SBOM + cosign signing on every release
- [ ] Linux (amd64/arm64) + macOS (amd64/arm64) binary releases
- [ ] Install script + Homebrew tap + sha256 checksums
- [ ] GitHub repo with README and demo GIF

**Phase 1 is complete when:** Engineers run `dsd health` themselves, unprompted,
before deployments. Not when the feature list is done.
- [ ] `--json`, `--quiet`, `--plain`, `--report`, `--debug` flags on all commands
- [ ] `--compact` flag for horizontal one-line-per-row overview (`dsd health --compact`)
- [ ] `--version` + `dsd version --json` with build-time ldflags injection
- [ ] `dsd completion bash|zsh|fish` shell completions
- [ ] Exit codes: `0` (all pass), `1` (warnings), `2` (critical)
- [ ] ICMP privilege fallback (CAP_NET_RAW → UDP ICMP → skip with INFO)
- [ ] Container detection + cgroup v1/v2 memory/CPU limit awareness
- [ ] Background update notification (once per day, non-blocking)
- [ ] Config file support (`~/.dsd.yaml`) for thresholds
- [ ] Multi-distro CI matrix (ubuntu-22.04, ubuntu-20.04, macOS, alpine, ubi8)
- [ ] Golden file output tests for all render paths
- [ ] Fuzz tests for all `/proc` and `/sys` parsers
- [ ] Contract tests: JSON schema in `schema/dsd-output.json`
- [ ] Smoke test script `scripts/smoke-test.sh` runs in release CI
- [ ] `go vet` + `staticcheck` + `golangci-lint` in CI
- [ ] `govulncheck` + `gosec` + `gitleaks` in security CI (every PR)
- [ ] SBOM generated and attached to every release
- [ ] Release binaries signed with `cosign` — `cosign.pub` in repo root
- [ ] `go-licenses check` passes (no GPL/AGPL in deps)
- [ ] `SECURITY.md` in repo root with vulnerability policy and threat model
- [ ] Linux (amd64/arm64) + macOS (amd64/arm64) binary releases
- [ ] Install script + Homebrew tap + sha256 checksums
- [ ] GitHub repo with README and demo GIF

**MVP Pass/Fail Thresholds:**

| Module | Data Collected | Warn | Critical |
|---|---|---|---|
| CPU | Load avg, cores, usage % | Load > cores × 0.7 | Load > cores × 0.9 |
| Memory | RAM used/free, swap used | Free < 10% | Free < 5% |
| Disk | Root FS free, inode usage | Free < 20% or inodes < 10% | Free < 10% or inodes < 5% |
| Network | Interface status, gateway ping, internet ping | Gateway unreachable | All interfaces DOWN |
| Swap usage (traditional) | Swap used % | 20–60% used | > 60% used |
| Swap activity | si/so pages/sec from `/proc/vmstat` | > 0/sec | > 100/sec |
| No swap of any kind | Missing swap + RAM % | RAM > 80% | RAM > 90% |
| zram utilization | mem_used / disksize | > 70% | > 90% |
| zram compression ratio | orig / compr data | 1.5–2.0x | < 1.5x |
| IO utilization | Disk util % from dual-sample delta | > 60% | > 85% |
| IO await (HDD) | ms per operation | > 20ms | > 50ms |
| IO await (SSD) | ms per operation | > 1ms | > 5ms |
| IO await (AWS EBS) | ms per operation | > 5ms | > 20ms |
| IO await (GCP PD) | ms per operation | > 5ms | > 20ms |
| IO await (container) | ms per operation | > 5ms | > 20ms |
| IO await (unknown cloud) | ms per operation | > 2ms | > 10ms |
| NTP offset | ms clock skew | > 100ms | not synced or > 500ms |
| Swap usage | % of swap used | > 20% | > 60% |
| Swap activity | si/so pages/sec | > 0/sec | > 100/sec |
| FD system-wide | % of file descriptors | > 80% | > 90% |
| Zombie processes | count | > 5 | — |
| Systemd failed units | count | — | 1+ |
| Journal size | GB | > 2GB | > 5GB |
| SELinux AVC denials | per hour | 1–10 | > 10 |

### Phase 2 — Polish & Early Adoption (weeks 4–6)
- [ ] Package managers: Homebrew, apt, yum, winget
- [ ] `--output markdown` for pasting into GitHub issues
- [ ] `dsd logs scan` — basic grep patterns (`failed`, `error`, `timeout`) from `/var/log` and journald
- [ ] `--report --weekly` and `--report --monthly` — usage summary from state.json
- [ ] Community feedback loop: post to r/devops, r/sysadmin, Hacker News

### Phase 3 — Containers & Plugins (months 2–3)
- [ ] `dsd docker` — auto-detects Docker then Podman (same SDK, different socket); container states, restart counts, image ages, health check status; containerd and CRI-O detected as names only
- [ ] Simple plugin system: drop `.dsd` scripts into a directory, output merged into final report
- [ ] `dsd net` deep checks — jitter, traceroute, bonds, ethtool speed/duplex, wireless, connection states, NAT
- [ ] `--report --out <file>` flag — save markdown report from any command to file
- [ ] `dsd full` — combines all Phase 1 + 2 + 3 checks

### Phase 4 — Proxmox & Kubernetes (months 4–6)
- [ ] `dsd pve` — Proxmox host diagnostics: cluster quorum, ZFS pool health, VM/LXC inventory, PVE kernel check, QEMU guest agent
- [ ] Proxmox context detection at startup: host / KVM VM / LXC — adjusts checks and shows banner
- [ ] `dsd k8s` — node conditions, pod OOMKill/eviction/CrashLoop/ImagePull/Pending, PVC binding, CoreDNS health, deployment status; reads kubeconfig automatically
- [ ] `dsd security` — security posture: failed SSH logins, listening ports vs whitelist, SSH config, sudo rules, world-writable /etc files
- [ ] `dsd logs` — error aggregation: journalctl errors last hour, top recurring messages, container log errors

### Phase 5 — Integrations (months 6–9)
- [ ] Prometheus exporter mode: `dsd export metrics` for enterprise integration
- [ ] `dsd logs` advanced: cross-service correlation, error trend sparklines
- [ ] AI-assisted analysis: deferred — see §25 Possible Future Development

---

---

---

## 12b. Prioritised Build Order — Viral, Sticky, Revenue

**Scoring:** each feature scored on Viral (V), Sticky (S), Revenue (R), 1–5.
ROI = composite score ÷ build days. Higher ROI = build sooner.

**Two timelines:** solo engineer ~14 weeks · 2-person team ~7 weeks to first paying customer.

---

### Sprint 0 — Foundation (week 1) · 6.6 dev-days
*All viral and sticky features ride on top of this.*

| Days | Feature | Why first |
|---|---|---|
| 5.0 | `dsd health` (12 collectors) | Foundation. Nothing else works without this |
| 0.5 | `--json` output | CI users from day 1. Scripting users = highest LTV |
| 0.5 | `--report` flag | Slack/GitHub sharing. Already in `tty.go` skeleton |
| 0.1 | Typo correction | One line of Cobra config. Ship with everything |
| 0.5 | Empty state guidance | Never show blank output again |

---

### Sprint 1 — Maximum virality in minimum time (week 2) · 3.8 dev-days
*Pure renderers. No new collectors. Every item reuses existing health output.*

| ROI | Days | Feature | Viral mechanic |
|---|---|---|---|
| 10.0 | 0.5 | `--since-deploy` | Post-deploy habit. Zero effort after week 1 |
| 5.0 | 1.0 | `--diff` | Incident diffs shared in Slack every time |
| 4.1 | 1.0 | `--post-mortem "title"` | Team virality — whole eng team reviews post-mortems |
| 15.6 | 0.25 | Usage milestones | Run-500 → team upgrade conversation |
| 12.8 | 0.25 | NPS survey at run-10 | Most valuable product data you can collect |
| 13.2 | 0.25 | Re-engagement message | 7-day gap → welcome back + what is new |
| 12.8 | 0.25 | `◆` Pro labels in `--help` | Engineers notice `◆ Team` immediately |
| 11.2 | 0.25 | `--qr` code | Surprise delight. Screenshot sharing |

**First viral moment:** Day 3 of Sprint 1. An engineer runs `dsd health --diff`
during an incident, pastes the output in Slack. A colleague asks "what tool is that?"
That is the acquisition flywheel starting.

---

### Sprint 2 — Habit formation + first paying signal (week 3) · 6.5 dev-days
*Build the retention loop. Capture first team interest.*

| ROI | Days | Feature | Retention mechanic |
|---|---|---|---|
| 7.8 | 0.5 | Streak tracking | 7-day streak → habit identity |
| 6.4 | 0.5 | Pro trial auto-trigger | 10 runs + 5-day streak → 14-day trial |
| 7.2 | 0.5 | `dsd examples` | Scenario 2 (pre-deploy policy) → paid question |
| 3.5 | 1.0 | Tip of the day | Tips 3/8/10 surface paid features |
| 1.9 | 2.0 | `--story` renderer | Post-mortem paste virality |
| 1.7 | 2.0 | dashdiag.sh landing | **Email capture from day 1. Do not skip.** |

---

### Sprint 3 — Onboarding depth + Phase 1 complete (week 4) · 7.0 dev-days
*Complete the Phase 1 product. Every install now has a guided experience.*

| Days | Feature | Why now |
|---|---|---|
| 2.0 | `dsd net` | Phase 1 complete. Network story told |
| 1.0 | `dsd services` | Phase 1. Port health checks |
| 2.0 | `dsd init` wizard | First-run retention. −40% early churn |
| 1.0 | `dsd hook install` | CI hook → daily habit → policy question → Tier 2 |
| 0.5 | Contextual upsell | After `--share` URL. 24h expiry → 90-day upgrade |
| 0.5 | `--dry-run` | Trust building for dsd init + dsd hook |

**Launch publicly at the end of Sprint 3:** r/devops, r/sysadmin, Hacker News.
Do not launch before this sprint completes.

---

### Sprint 4 — Launch + first revenue (weeks 5–6) · 15.5 dev-days
*Ship publicly. Collect first payment.*

| Days | Feature | Revenue path |
|---|---|---|
| 1.0 | Weekly/monthly report | "See 90-day history" → team plan |
| 1.0 | `--watch` mode | Incident habit |
| 0.5 | `--yaml` output | K8s/Ansible engineers |
| 3.0 | `--share` (hosted URL) | Core paid funnel. Requires dashdiag.sh backend |
| 10.0 | Team workspace MVP | **First paid product.** $29/month |

**Target: first paying team by end of Sprint 4.**

---

### Post-Launch — Phase gate dependent (months 2–4) · 29.0 dev-days
*Only build after phase gates pass. Wait for real user requests.*

| Gate | Feature | Signal to wait for |
|---|---|---|
| health in daily use | `dsd health deep` | Requests for per-core CPU detail |
| net validated | `dsd net deep` | Requests for jitter / traceroute |
| Phase 1 solid | `dsd docker` | GitHub issues requesting containers |
| docker in use | `dsd compare` | "Can you check multiple servers?" |
| docker in use | `dsd policy` | "Can I fail CI when memory is high?" |
| Phase 3 solid | `dsd logs`, `dsd security` | Requests in GitHub issues |
| docker in use | `dsd k8s` | "Does it work with Kubernetes?" |
| k8s in use | `dsd k8s deep` | K8s power users asking for BestEffort/throttle |
| Phase 4 solid | `dsd pve` | Proxmox community requests |
| backend live | `--badge` | Requests for README status badges |

---

### The single most important rule

**Sprint 1 must ship before Sprint 0 is launched publicly.**

The first engineer who installs DashDiag must be able to run `--diff` and
`--post-mortem` on the same day. A tool that only outputs green checkmarks gets
installed once and forgotten. A tool that produces a post-mortem template gets
shared in every incident channel and added to every team runbook.

---

### Time to key milestones

| Milestone | Solo | 2-person team |
|---|---|---|
| First viral moment (`--diff` in Slack) | Day 8 | Day 4 |
| Phase 1 complete (ready to launch) | Week 4 | Week 2 |
| First waitlist email captured | Week 3 | Week 2 |
| First paying customer | Week 6 | Week 3 |
| 10 paying teams | Month 4 | Month 2 |
| Full feature set (k8s, pve, fleet) | Month 6 | Month 3 |


## 13. Security & SDLC

#### Threat Model (STRIDE)

DashDiag is a read-only local CLI tool — no network listener, no database, no authentication. The threat surface is narrow but real. Three threats dominate.

**Primary threat: supply chain compromise.** You distribute a binary installed on production servers, often with `CAP_NET_RAW`. A compromised dependency, build pipeline, or release artifact installs malware on prod. This happened to `xz-utils`, `event-stream`, `codecov`. It is your top risk.

**Secondary threat: dependency CVEs.** 15–20 Go modules, each potentially vulnerable. Must be checked continuously, not just at first import.

**Tertiary threat: information disclosure.** `dsd --json` output contains IP addresses, hostnames, kernel version, container names, network topology. If piped to an insecure endpoint or accidentally committed, it leaks infrastructure details.

| Threat | Vector | Mitigation |
|---|---|---|
| Supply chain compromise | Compromised dep or build pipeline | govulncheck, SBOM, cosign binary signing |
| Binary tampering | Compromised GitHub release | cosign signatures + sha256 checksums on every release |
| Dependency CVEs | Vulnerable transitive dependency | govulncheck weekly + on every PR |
| Information disclosure | `--json` output leaked | Document sensitive fields; future `--redact` flag |
| Privilege escalation | Bug in `CAP_NET_RAW` ping code path | Minimal privileged surface; fuzz tests on ping parsers |
| TOCTOU temp file | Symlink attack on update cache | `os.CreateTemp()` — never `os.Create()` on predictable paths |

**Out of scope:** network attacks (no listener), authentication bypass (no auth), SQL injection (no database).

---

### SDLC Tools — CI Pipeline

**Tool summary:**

| Tool | Purpose | When |
|---|---|---|
| `govulncheck` | Go vuln DB — checks only functions you actually call | Every PR + weekly |
| `gosec` | SAST: file perms, path traversal, exec injection, integer overflow | Every PR |
| `semgrep` | SAST + secrets: Go rules + supply chain | Every PR |
| `gitleaks` | Scan git history for accidentally committed secrets | Every PR + pre-commit hook |
| `syft` + `grype` | Generate SBOM + scan for vulnerabilities | Every release |
| `cosign` | Sign release binaries (Sigstore) | Every release |
| `go-licenses` | Check all dep licenses for compatibility | Every PR |
| `CodeQL` | GitHub SAST — catches data flow bugs gosec misses | Every PR |

**`.github/workflows/security.yml`:**

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 3 * * 1'  # weekly Monday 03:00 UTC

jobs:
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: golang/govulncheck-action@v1
        with:
          go-version-file: go.mod

  gosec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: '-fmt sarif -out results.sarif ./...'
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep ci --config p/go --config p/secrets --config p/supply-chain

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history for secret scanning
      - uses: gitleaks/gitleaks-action@v2

  sbom-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json
      - uses: anchore/scan-action@v3
        with:
          sbom: sbom.json
          fail-build: true
          severity-cutoff: high

  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: |
          go install github.com/google/go-licenses@latest
          go-licenses check ./...

  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: go
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

**Binary signing in `.github/workflows/release.yml` — add after build:**

```yaml
  sign:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - name: Sign binaries
        env:
          COSIGN_KEY: ${{ secrets.COSIGN_KEY }}
        run: |
          for binary in dist/dsd-*; do
            [[ "$binary" == *.sig ]] && continue
            cosign sign-blob --key env://COSIGN_KEY               --output-signature "${binary}.sig"               "${binary}"
          done
      # Verification command for users:
      # cosign verify-blob --key cosign.pub --signature dsd-linux-amd64.sig dsd-linux-amd64
```

**Add `cosign.pub` to the repo root** so users can verify downloads.

---

### SECURITY.md

Add this file to the repo root before first public release:

```markdown
# Security Policy

### Supported Versions
Only the latest release receives security fixes.

### Reporting a Vulnerability
- GitHub private security advisory (preferred): 
  https://github.com/yourusername/dashdiag/security/advisories/new
- Email: security@dashdiag.sh
- Response time: 48 hours acknowledgement
- Fix timeline: 7 days critical / 30 days high / 90 days medium

### Verifying Release Integrity

Every release binary is signed with cosign (Sigstore).

    # Install cosign: https://docs.sigstore.dev/cosign/installation/
    cosign verify-blob \
      --key https://raw.githubusercontent.com/yourusername/dashdiag/main/cosign.pub \
      --signature dsd-linux-amd64.sig \
      dsd-linux-amd64

Verify sha256 checksum:
    sha256sum -c checksums.txt

### Threat Model
See docs/THREAT_MODEL.md for full STRIDE analysis.

### Known Security Properties
- Read-only: no system state is modified
- No network listener: no incoming connections
- No persistent storage beyond ~/.dsd.yaml, ~/.dsd/state.json, ~/.dsd/baselines/, and /tmp/.dsd-update-check
- CAP_NET_RAW used only for ICMP ping with UDP fallback
- Startup line communicates read-only intent: "System snapshot (read-only)"
- --debug flag shows every file read and command executed — no hidden behaviour
```

---

### Makefile — developer workflow targets

```makefile
# Makefile

.PHONY: build test lint security fuzz smoke install

VERSION  ?= $(shell git describe --tags --always --dirty)
COMMIT   ?= $(shell git rev-parse --short HEAD)
BUILT    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -X dsd/internal/version.Version=$(VERSION) \
            -X dsd/internal/version.Commit=$(COMMIT) \
            -X dsd/internal/version.Built=$(BUILT)

build:
	go build -ldflags "$(LDFLAGS)" -o dist/dsd ./cmd/dsd

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-integration:
	go test -tags integration -race ./...

test-e2e:
	go test -tags e2e ./test/e2e/...

fuzz:
	go test -fuzz=FuzzReadVMStat     ./internal/collectors/ -fuzztime=60s
	go test -fuzz=FuzzParseIOCounters ./internal/collectors/ -fuzztime=60s

bench:
	go test -bench=. -benchmem -benchtime=10s ./internal/collectors/

lint:
	go vet ./...
	staticcheck ./...
	golangci-lint run

security:
	govulncheck ./...
	gosec ./...
	go-licenses check ./...

smoke:
	bash scripts/smoke-test.sh

install: build
	install -m 755 dist/dsd /usr/local/bin/dsd
	sudo setcap cap_net_raw+ep /usr/local/bin/dsd

update-golden:
	go test ./internal/render/... -update
```

---

## 14. Testing Strategy

### The Testing Pyramid

```
                    ┌──────┐
                    │  E2E │  5%  — real binary in real containers
                   ┌┴──────┴┐
                   │Contract│  5%  — JSON schema stability
                  ┌┴────────┴┐
                  │  Fuzz   │  5%  — parser panic prevention
                 ┌┴──────────┴┐
                 │Integration │  15% — real syscalls, controlled env
                ┌┴────────────┴┐
                │     Unit    │  70% — mocked interfaces, deterministic
               └──────────────┘
```

All unit tests are fast (< 100ms total suite). Integration tests require a real Linux/macOS environment and run in the CI matrix. E2E tests use `testcontainers-go` and run pre-release.

---

### Unit Tests — Interface Injection Pattern

Every collector must be testable without real system state. Inject a reader interface:

```go
// internal/collectors/memory.go

type MemoryReader interface {
    VirtualMemory() (*mem.VirtualMemoryStat, error)
    SwapMemory()    (*mem.SwapMemoryStat, error)
}

type MemoryCollector struct {
    Reader       MemoryReader
    ContainerCtx platform.ContainerContext
}

// Production: wraps real gopsutil
type gopsutilMemReader struct{}
func (r *gopsutilMemReader) VirtualMemory() (*mem.VirtualMemoryStat, error) {
    return mem.VirtualMemory()
}
func (r *gopsutilMemReader) SwapMemory() (*mem.SwapMemoryStat, error) {
    return mem.SwapMemory()
}

func NewMemoryCollector(ctx platform.ContainerContext) *MemoryCollector {
    return &MemoryCollector{Reader: &gopsutilMemReader{}, ContainerCtx: ctx}
}
```

Table-driven tests covering every threshold combination:

```go
// internal/collectors/memory_test.go

func TestMemoryCollector(t *testing.T) {
    tests := []struct {
        name        string
        totalMB     uint64
        availMB     uint64
        swapTotalMB uint64
        swapUsedMB  uint64
        zramPresent bool
        wantStatus  string
    }{
        {"healthy",              16384, 8192,  4096, 512,  false, "OK"},
        {"ram warn 85pct",       16384, 2457,  4096, 512,  false, "WARN"},
        {"ram crit 96pct",       16384,  655,  4096, 512,  false, "CRIT"},
        {"swap warn 35pct",      16384, 8192,  4096, 1433, false, "WARN"},
        {"swap crit 65pct",      16384, 8192,  4096, 2662, false, "CRIT"},
        {"no swap high ram",     16384, 2457,     0,    0, false, "WARN"},
        {"no swap crit ram",     16384,  655,     0,    0, false, "CRIT"},
        // zram present — must NOT fire "no swap" warning
        {"no trad swap + zram",  16384, 8192,     0,    0, true,  "OK"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            col := &MemoryCollector{
                Reader: &mockMemReader{
                    vmem: &mem.VirtualMemoryStat{
                        Total:     tt.totalMB * 1024 * 1024,
                        Available: tt.availMB * 1024 * 1024,
                    },
                    swap: &mem.SwapMemoryStat{
                        Total: tt.swapTotalMB * 1024 * 1024,
                        Used:  tt.swapUsedMB  * 1024 * 1024,
                    },
                },
            }
            result, err := col.Collect(context.Background())
            require.NoError(t, err)
            info := result.(models.MemoryInfo)
            assert.Equal(t, tt.wantStatus, info.Status)
        })
    }
}
```

**AI prompt for unit test generation:**
```
Prompt:
"Write table-driven unit tests for internal/collectors/<module>.go.
Define a <Module>Reader interface that wraps all gopsutil calls.
Write a mock implementation that returns configurable test data.
Test cases must cover every threshold boundary:
  - Each metric at: healthy / at WARN boundary / just past WARN /
    at CRIT boundary / just past CRIT / zero / max uint64
  - Error path: reader returns error → collector returns wrapped error
  - Context cancellation: ctx cancelled mid-collection → returns ctx.Err()
  - Container context: if collector uses cgroup limits, test both
    container-limited and unlimited paths
Use github.com/stretchr/testify/assert and require."
```

---

### Fuzz Tests — Parser Panic Prevention

All `/proc` and `/sys` file parsers must be fuzz-tested. Kernel versions, distros, and container environments produce unexpected formats.

```go
// internal/collectors/fuzz_test.go

func FuzzReadVMStat(f *testing.F) {
    // Seed with real /proc/vmstat samples
    f.Add("pswpin 0
pswpout 0
")
    f.Add("pswpin 12345
pswpout 6789
other_field 0
")
    f.Add("")
    f.Add("pswpin
")              // missing value
    f.Add("pswpin -1
")          // negative (invalid)
    f.Add("pswpin 99999999999999999999
") // overflow

    f.Fuzz(func(t *testing.T, content string) {
        // Must never panic, must return valid uint64 or zero
        in, out, _ := parseVMStat(strings.NewReader(content))
        _ = in
        _ = out
    })
}

func FuzzParseIOCounters(f *testing.F) {
    f.Add("sda 12345 0 98765 1000 0 0 0 0 0 500 500
")
    f.Add("")
    f.Add("not valid
")
    f.Add("sda
")

    f.Fuzz(func(t *testing.T, content string) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("panic on input %q: %v", content, r)
            }
        }()
        parseIOStat(strings.NewReader(content))
    })
}

func FuzzZRAMStats(f *testing.F) {
    f.Add("4294967296
")  // valid disksize
    f.Add("max
")         // cgroup v2 "unlimited"
    f.Add("")
    f.Add("not_a_number
")

    f.Fuzz(func(t *testing.T, content string) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("panic on input %q: %v", content, r)
            }
        }()
        parseZRAMStat(content)
    })
}
```

Run in CI weekly: `go test -fuzz=. ./internal/collectors/ -fuzztime=120s`
Store corpus in `testdata/fuzz/` — committed to repo.

---

### Integration Tests — Real System Calls

```go
// internal/collectors/disk_integration_test.go
//go:build integration

func TestDiskCollector_RealFS(t *testing.T) {
    col := NewDiskCollector()
    result, err := col.Collect(context.Background())
    require.NoError(t, err)

    info := result.(models.DiskInfo)

    var foundRoot bool
    for _, fs := range info.Filesystems {
        if fs.MountPoint == "/" {
            foundRoot = true
            assert.Greater(t, fs.TotalGB, float64(0), "root fs must have size")
            assert.GreaterOrEqual(t, fs.FreeGB, float64(0))
            assert.LessOrEqual(t, fs.UsedPct, float64(100))
            assert.NotEmpty(t, fs.Status)
        }
        // No filesystem should have empty mount point
        assert.NotEmpty(t, fs.MountPoint)
        // Status must be one of known values
        assert.Contains(t, []string{"OK", "WARN", "CRIT"}, fs.Status)
    }
    assert.True(t, foundRoot, "root filesystem must always be present")
}

func TestIOCollector_RealDevice(t *testing.T) {
    col := &IOCollector{}
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    result, err := col.Collect(ctx)
    require.NoError(t, err)

    info := result.(models.IOInfo)
    // Must complete within timeout — verifies 1s sample doesn't block
    assert.Greater(t, info.SampleSecs, float64(0.9))
    assert.Less(t, info.SampleSecs, float64(2.0))

    for _, dev := range info.Devices {
        assert.NotEmpty(t, dev.Device)
        assert.Contains(t, []string{"OK", "WARN", "CRIT"}, dev.Status)
        assert.GreaterOrEqual(t, dev.UtilPct, float64(0))
        assert.LessOrEqual(t, dev.UtilPct, float64(100))
    }
}
```

Run: `go test -tags integration -race ./...`

---

### Golden File Tests — Renderer Output

Locks the terminal output format. Any formatting change that breaks copy-paste into Slack is caught immediately.

```go
// internal/render/golden_test.go

var update = flag.Bool("update", false, "update golden files")

func TestRenderQuick_Healthy(t *testing.T)    { testGolden(t, "quick_healthy",    mockHealthySnapshot()) }
func TestRenderQuick_Warn(t *testing.T)       { testGolden(t, "quick_warn",       mockWarnSnapshot()) }
func TestRenderQuick_Crit(t *testing.T)       { testGolden(t, "quick_crit",       mockCritSnapshot()) }
func TestRenderQuick_Container(t *testing.T)  { testGolden(t, "quick_container",  mockContainerSnapshot()) }
func TestRenderNet_Healthy(t *testing.T)      { testGolden(t, "net_healthy",      mockNetworkHealthy()) }
func TestRenderNet_NoInternet(t *testing.T)   { testGolden(t, "net_no_internet",  mockNetworkNoInternet()) }
func TestRenderPlain_Healthy(t *testing.T)    { testGoldenPlain(t, "plain_healthy", mockHealthySnapshot()) }

func testGolden(t *testing.T, name string, snapshot interface{}) {
    t.Helper()
    renderer := render.NewRenderer(false) // colored mode
    got := renderer.RenderQuick(snapshot)
    goldenPath := filepath.Join("testdata", "golden", name+".txt")

    if *update {
        os.WriteFile(goldenPath, []byte(got), 0644)
        return
    }
    want, err := os.ReadFile(goldenPath)
    require.NoError(t, err, "golden file missing — run: go test ./... -update")
    assert.Equal(t, string(want), got)
}
```

Regenerate: `go test ./internal/render/... -update`

---

### Smoke Tests — Post-Install Verification

```bash
#!/bin/bash
# scripts/smoke-test.sh
set -euo pipefail

echo "=== DashDiag Smoke Tests ==="
PASS=0; FAIL=0

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        echo "  ✅ $desc"; ((PASS++))
    else
        echo "  ❌ $desc"; ((FAIL++))
    fi
}

# Binary present
check "binary in PATH"               which dsd

# Version
check "dsd --version"                dsd --version
check "version contains v"           bash -c 'dsd --version | grep -qE "v[0-9]"'

# Help
check "dsd --help exits cleanly"     dsd --help

# Quick check exit code 0 or 1
dsd health; code=$?
[ $code -le 1 ] && echo "  ✅ dsd health exit code ($code)" && ((PASS++))                 || echo "  ❌ dsd health exit code ($code)" && ((FAIL++))

# JSON output is valid
check "dsd health --json valid JSON"  bash -c 'dsd health --json | python3 -m json.tool'

# JSON has required fields
check "JSON has timestamp field"     bash -c 'dsd health --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert "timestamp" in d"'
check "JSON has hostname field"      bash -c 'dsd health --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert "hostname" in d"'
check "JSON has checks field"        bash -c 'dsd health --json | python3 -c "import sys,json; d=json.load(sys.stdin); assert "checks" in d"'

# Plain mode — no ANSI escape codes
output=$(dsd health --plain 2>&1)
echo "$output" | grep -qP '\['     && echo "  ❌ --plain contains ANSI codes" && ((FAIL++))     || echo "  ✅ --plain output is ANSI-free" && ((PASS++))

# Shell completions
check "bash completion"              bash -c 'dsd completion bash > /dev/null'
check "zsh completion"               bash -c 'dsd completion zsh  > /dev/null'

# Debug flag doesn't crash
check "dsd health --debug"            dsd health --debug

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] || exit 1
```

---

### E2E Tests — testcontainers-go

```go
// test/e2e/quick_test.go
//go:build e2e

package e2e

import (
    "context"
    "encoding/json"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/testcontainers/testcontainers-go"
)

func TestE2E_QuickCheck_Ubuntu(t *testing.T) {
    ctx := context.Background()
    ctr := startContainer(t, ctx, "ubuntu:22.04")
    defer ctr.Terminate(ctx)

    code, out, err := ctr.Exec(ctx, []string{"/usr/local/bin/dsd", "quick", "--json"})
    require.NoError(t, err)
    assert.LessOrEqual(t, code, 1, "exit code must be 0 (OK) or 1 (WARN)")

    var result map[string]interface{}
    require.NoError(t, json.Unmarshal(out, &result), "output must be valid JSON")
    assert.Contains(t, result, "timestamp")
    assert.Contains(t, result, "hostname")
    assert.Contains(t, result, "checks")
}

func TestE2E_ContainerDetection(t *testing.T) {
    ctx := context.Background()
    ctr := startContainer(t, ctx, "ubuntu:22.04")
    defer ctr.Terminate(ctx)

    // dsd should detect it's inside a container and show banner
    _, out, _ := ctr.Exec(ctx, []string{"/usr/local/bin/dsd", "quick", "--plain"})
    assert.Contains(t, string(out), "container", "must show container detection banner")
}

func TestE2E_NoPing_GracefulFallback(t *testing.T) {
    ctx := context.Background()
    // Run as non-root, no setcap — ping must not crash
    ctr := startContainerAsUser(t, ctx, "ubuntu:22.04", "nobody")
    defer ctr.Terminate(ctx)

    code, out, err := ctr.Exec(ctx, []string{"/usr/local/bin/dsd", "quick", "--json"})
    require.NoError(t, err)
    // Must not exit 2 (CRIT) just because ping failed
    assert.LessOrEqual(t, code, 1)
    // Output must mention ping was skipped, not crashed
    assert.Contains(t, string(out), "skip")
}

func TestE2E_PlainMode_NoANSI(t *testing.T) {
    ctx := context.Background()
    ctr := startContainer(t, ctx, "ubuntu:22.04")
    defer ctr.Terminate(ctx)

    _, out, _ := ctr.Exec(ctx, []string{"/usr/local/bin/dsd", "quick", "--plain"})
    assert.NotContains(t, string(out), "\x1b[", "plain mode must not contain ANSI codes")
}

func startContainer(t *testing.T, ctx context.Context, image string) testcontainers.Container {
    t.Helper()
    req := testcontainers.ContainerRequest{
        Image: image,
        Cmd:   []string{"sleep", "300"},
        Files: []testcontainers.ContainerFile{{
            HostFilePath:      "../../dist/dsd-linux-amd64",
            ContainerFilePath: "/usr/local/bin/dsd",
            FileMode:          0755,
        }},
    }
    ctr, err := testcontainers.GenericContainer(ctx,
        testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
    require.NoError(t, err)
    return ctr
}
```

---

### Contract Tests — JSON Schema

```go
// test/contract/json_schema_test.go

func TestJSONOutput_MatchesSchema(t *testing.T) {
    schemaBytes, err := os.ReadFile("../../schema/dsd-output.json")
    require.NoError(t, err, "schema/dsd-output.json must exist")

    compiler := jsonschema.NewCompiler()
    compiler.AddResource("schema.json", bytes.NewReader(schemaBytes))
    schema, err := compiler.Compile("schema.json")
    require.NoError(t, err)

    // Run actual quick with mock data
    result := runMockQuickCheck()
    jsonBytes, _ := json.Marshal(result)

    var v interface{}
    json.Unmarshal(jsonBytes, &v)

    err = schema.Validate(v)
    assert.NoError(t, err,
        "JSON output must match published schema — breaking schema change detected")
}
```

**`schema/dsd-output.json`** is a public contract. Version it with the tool:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://dashdiag.sh/schema/v1/output.json",
  "type": "object",
  "required": ["version", "timestamp", "hostname", "checks"],
  "properties": {
    "version":   { "type": "string", "pattern": "^v[0-9]" },
    "timestamp": { "type": "string", "format": "date-time" },
    "hostname":  { "type": "string" },
    "in_container": { "type": "boolean" },
    "checks": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "status", "value"],
        "properties": {
          "name":   { "type": "string" },
          "status": { "type": "string", "enum": ["OK", "WARN", "CRIT", "INFO"] },
          "value":  { "type": "string" },
          "message": { "type": "string" }
        }
      }
    }
  }
}
```

Once published, never remove required fields or change enum values in a minor version.

---

### Benchmark Tests

```go
// internal/collectors/bench_test.go

func BenchmarkCPUCollector(b *testing.B) {
    col := NewCPUCollector(platform.ContainerContext{})
    ctx := context.Background()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        col.Collect(ctx)
    }
}

func BenchmarkIOCollector(b *testing.B) {
    // IO collector takes ~1s per run (sampling interval)
    // This benchmark validates the overhead beyond the sample window
    col := &IOCollector{}
    ctx := context.Background()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        col.Collect(ctx)
    }
}

// Run: go test -bench=. -benchmem -benchtime=3x ./internal/collectors/
// Target: dsd health completes in < 5s wall time on any healthy machine
```

---

### Complete Test Coverage Requirements

| Module | Min coverage | Critical paths |
|---|---|---|
| `collectors/memory.go` | 90% | All threshold combinations |
| `collectors/swap.go` | 85% | zram detection, vmstat parsing, activity rate |
| `collectors/io.go` | 85% | Virtual device filter, zram tier, await calc |
| `collectors/network_*.go` | 80% | Permission fallback, ping timeout, DNS fail |
| `collectors/clock.go` | 80% | All three detection methods |
| `analysis/heuristics.go` | 95% | Every heuristic rule independently |
| `output/tty.go` | 100% | All StatusIcon combinations + TTY detection |
| `render/*.go` | 80% | Covered by golden file tests |
| `platform/container.go` | 85% | cgroup v1, v2, hybrid, not-in-container |

Run coverage: `go test -race -coverprofile=coverage.out ./... && go tool cover -func=coverage.out`

## 15. Distribution & Growth Strategy

### Open Source First
- MIT or Apache 2.0 license — non-negotiable for DevOps adoption
- Host on GitHub with clean README, demo GIF in first line, badges

### Positioning

**The wrong description kills adoption before it starts.** Every word in your GitHub description, HN post, and README first line needs to be chosen deliberately.

**Positioning contrast:**

| ❌ Weak — skip-worthy | ✅ Strong — star-worthy |
|---|---|
| "CLI tool for system diagnostics" | "The fastest way to understand your system in 10 seconds" |
| "Wrapper around htop, df, ping" | "One command to instantly understand your system health" |
| "DevOps monitoring helper" | "Your daily DevOps system snapshot" |
| "System health checker" | "A decision acceleration layer for DevOps engineers" |

The weak versions describe **what the tool is**. The strong versions describe **what the engineer gets**. Always lead with the outcome, not the mechanism.

**Three copy-ready descriptions for different contexts:**

*GitHub description (one line):*
> "One command. Instant system health. dsd health — the fastest way to understand what's happening on any Linux or macOS machine."

*HN Show HN title:*
> "Show HN: DashDiag — one command to replace htop+df+ping+docker ps, with shareable output"

*LinkedIn/Reddit intro line:*
> "I got tired of running 8 commands just to get a system health snapshot before a deployment. So I built dsd — one command, instant overview, output you can paste directly into Slack."

**The "neofetch for DevOps diagnostics" analogy** — this is your elevator pitch to engineers. Neofetch succeeded because it is beautiful, fast, shareable, and reflexively runnable. DashDiag is the same pattern but for operational health instead of system specs.

**The "decision acceleration layer" framing** — use this when talking to CTOs, SRE leads, or enterprise buyers. It positions DashDiag as reducing time-to-decision, not as a monitoring replacement. "We cut our incident triage time from 5 minutes to 10 seconds" is a concrete ROI claim.

**The "structured output" framing** — for technical audiences: "DashDiag's `--json` output is structured and typed, which means it can feed any downstream tool — monitoring systems, dashboards, scripts, or future analysis tools — without any changes to DashDiag itself."

### Launch Channels (in order)
1. **Hacker News** — "Show HN: DashDiag — one command to replace htop+df+ping+docker ps"
2. **r/devops** and **r/sysadmin** on Reddit
3. **Dev.to / Hashnode** — write "Why I built DashDiag" post
4. **CNCF Slack / DevOps communities**
5. **Homebrew tap** — makes it viral among macOS devs
6. **GitHub trending** — aim for it day-1 with coordinated launch

### Adoption Path: Bottom-Up
Engineers discover it → like it → share it → evangelize at their company. Your early evangelists are SREs and DevOps consultants (they work across many systems and value consistency). Junior engineers are good early adopters but poor evangelists.

### Virality Hook
The emoji + color output is screenshot-friendly. When engineers share `dsd full` output in Slack incident channels, it naturally promotes the tool. Include a "Generated by DashDiag" footer (opt-out with `--no-footer`). In `--plain` mode the footer uses ASCII only: "-- Generated by DashDiag --".

### README Section Order (locked spec)

The README section order is not arbitrary — it is optimised for the 8-second attention span of someone landing on the GitHub page from a Reddit post or HN comment.

```
1. Title + tagline      ← one line that earns the star before anything is read
2. Demo GIF             ← before any text, immediately after the tagline
3. Key features         ← 3 bullets maximum, outcome-focused not feature-focused
4. Example output       ← the healthy + issues-detected pair from §2
5. Quick install        ← the one-liner, nothing else
6. Commands overview    ← single table: command / what it does
7. Roadmap              ← 3-line phase summary only, link to full roadmap
8. Contributing         ← one paragraph + link to CONTRIBUTING.md
```

**Rules:**
- The install command is on screen before the user has to scroll on desktop
- No wall-of-text feature descriptions — every feature is one line
- The demo GIF shows `dsd health` with an issues-detected scenario (not a healthy run — healthy is boring)

---

### Launch Copy (ready to post)

Copy these verbatim on launch day. Do not rewrite under launch pressure.

**Reddit / Hacker News:**
```
Title: DashDiag (dsd) — one command to instantly understand your system health

Body:
I got tired of running htop, df -h, free -h, ping, and docker ps separately 
just to get a system health snapshot before a deployment.

So I built dsd — one command, instant overview:

  $ dsd health

  CPU ✅  Memory ⚠️ 92%  Disk ✅  Network ✅

  1 issue detected
  → ps aux --sort=-%mem | head -10

Lightweight, read-only, safe on prod. Pastes directly into Slack or GitHub.

GitHub: [link]
Would love feedback from the community.
```

**LinkedIn:**
```
DevOps reality:
You SSH into a server and run 6 commands just to understand what's happening.

I built a small CLI tool to fix that:

DashDiag (dsd) — one command → instant system snapshot

$ dsd health

CPU ✅  Memory ⚠️ High (92%)  Disk ✅  Network ✅

Summary: 1 issue detected
→ ps aux --sort=-%mem | head -10

Lightweight, read-only, designed for fast diagnostics and Slack sharing.

Open source: [link]
Curious how others handle quick system checks.
```

**Twitter / X:**
```
Instead of running 6 commands to check your system health:

dsd health ⚡

CPU ✅
Memory ⚠️ 92% used
Disk ✅
Network ✅

1 issue detected → ps aux --sort=-%mem | head -10

Lightweight CLI. Read-only. Output pastes clean into Slack.
[link]
```

---

### Enterprise Path (later)
- `--plain` mode: no emoji, no color, no decorative borders — auto-enabled when stdout is not a TTY (pipes, CI, redirects)
- Prometheus exporter for Datadog/Grafana integration
- Static binary with zero external deps (already your default with Go)
- Security review-friendly: read-only, no agents, no hooks

---

## 16. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| **"Just use aliases" objection** | Emphasize structured output, pass/fail logic, cross-machine consistency. Show it's faster than 5 commands. |
| **ICMP permission denied on install** | `pingWithFallback()` tries CAP_NET_RAW → UDP mode → skip with helpful message. README shows `setcap` command. |
| **Wrong metrics inside containers** | `DetectContainerContext()` at startup. Memory/CPU collectors use cgroup limits. Output shows container banner. |
| **Clock skew causing silent failures** | NTP check in MVP. `❌ Clock: NOT synchronized` is immediately actionable. |
| **OS differences break parsers** | Use `gopsutil` and `gns` libraries — never parse command text output manually. Test on Ubuntu, RHEL, macOS. |
| **Installation friction** | Provide multiple install paths: curl one-liner, Homebrew, apt/yum, Docker image. |
| **Enterprise skepticism (emoji)** | `--plain` flag + auto-TTY detection + `--json` mode from day one. |
| **Scope creep** | Strictly follow phased roadmap. Don't touch Kubernetes until core is solid and used daily. |
| **Output-parsing fragility** | Abstract via `/proc` directly on Linux, `sysctl` on macOS. Never shell out to `free`, `df`, `ip`. |
| **"It's just a shell script" perception** | Proper CLI arg parsing (cobra), exit codes, config file, unit tests. Static binary distribution. |
| **Supply chain compromise** | govulncheck on every PR, cosign binary signing, SBOM attached to every release. |
| **Vulnerable dependency** | govulncheck weekly schedule + PR gate. Blocks merge if vulnerable function is called. |
| **Renderer regression** | Golden file tests catch any output format change before it ships. |
| **Parser panic on unexpected kernel** | Fuzz tests on all `/proc`/`/sys` parsers. Corpus stored in `testdata/fuzz/`. |
| **Proxmox pvesh needs root** | Fallback to `corosync-quorumtool` (no perms needed) for cluster health; `zpool` is world-readable; `qm`/`pct` skip with INFO if unavailable. |
| **Wrong context in Proxmox LXC** | Explicit LXC detection runs before generic container check; banner warns that hypervisor-level limits are not visible from inside. |

---

## 17. How to Use AI to Build This — Step by Step

This is your AI-assisted development workflow. The key principle: **AI writes code, you review architecture and test outputs. One module per session.**

### Step 0: Scaffold the Project

```
Prompt:
"Scaffold a Go CLI project called 'dsd' (DashDiag) using cobra and gopsutil.
Create this structure:
  dashdiag/
  ├── cmd/root.go, quick.go, version.go
  ├── internal/collectors/collector.go, cpu.go
  ├── internal/models/cpu.go
  ├── internal/output/formatter.go
  ├── main.go
  └── go.mod

Dependencies: cobra, viper, gopsutil/v3, lipgloss, go-ping, gns
Root command shows help. Stub 'quick' subcommand with --output flag (human/json/quiet) and --plain flag.
Add output.IsPlain() in internal/output/tty.go."
```

**Reference scaffold — use this as baseline:**

`main.go`:
```go
package main

import "github.com/yourusername/dashdiag/cmd"

func main() {
    cmd.Execute()
}
```

`cmd/root.go`:
```go
package cmd

import (
    "fmt"
    "os"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var (
    cfgFile     string
    outputFmt   string // "human", "json", "quiet"
    plainMode   bool   // --plain: ASCII only, no emoji/color (auto when not a TTY)
    reportMode  bool   // --report: markdown tables for Slack/GitHub/incident rooms
    debugMode   bool   // --debug: timing, raw values, skipped checks → stderr
)

// Version variables — injected at build time via ldflags:
// go build -ldflags="-X dsd/internal/version.Version=1.2.3
//                     -X dsd/internal/version.Commit=abc123
//                     -X dsd/internal/version.Built=2026-03-20"
var rootCmd = &cobra.Command{
    Use:     "dsd",
    Short:   "DashDiag - System & Network Diagnostics",
    Long:    "DashDiag (dsd) — one command instant system health overview.",
    Version: version.Version, // enables dsd --version automatically
    // Zero-config value: running bare `dsd` runs quick, not help.
    // An engineer who just installed it gets value from the first keystroke.
    RunE: func(cmd *cobra.Command, args []string) error {
        return runHealth(cmd, args)
    },
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func init() {
    cobra.OnInitialize(initConfig)

    // Output flags
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.dsd.yaml)")
    rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "human", "output format: human, json, quiet")
    rootCmd.PersistentFlags().BoolVar(&plainMode,  "plain",  false, "plain text: no emoji, no color, ASCII only (auto when not a TTY)")
    rootCmd.PersistentFlags().BoolVar(&reportMode, "report", false, "markdown output for Slack/GitHub/incident rooms (tables, bold headers, emoji)")
    rootCmd.PersistentFlags().BoolVar(&debugMode,  "debug",  false, "print internal diagnostics to stderr (timing, raw values, skipped checks)")

    // Shell completions — dsd completion bash|zsh|fish|powershell
    rootCmd.AddCommand(completionCmd)

    // Version — dsd version (human) or dsd version --json
    rootCmd.AddCommand(versionCmd)

    // Update check — dsd update (manual) or background notification
    rootCmd.AddCommand(updateCmd)
}

// completionCmd generates shell completion scripts
var completionCmd = &cobra.Command{
    Use:   "completion [bash|zsh|fish|powershell]",
    Short: "Generate shell completion script",
    Example: `  dsd completion bash > /etc/bash_completion.d/dsd
  dsd completion zsh > "${fpath[1]}/_dsd"
  dsd completion fish > ~/.config/fish/completions/dsd.fish`,
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        switch args[0] {
        case "bash":       return rootCmd.GenBashCompletion(os.Stdout)
        case "zsh":        return rootCmd.GenZshCompletion(os.Stdout)
        case "fish":       return rootCmd.GenFishCompletion(os.Stdout, true)
        case "powershell": return rootCmd.GenPowerShellCompletion(os.Stdout)
        default:
            return fmt.Errorf("unsupported shell: %s", args[0])
        }
    },
}

// versionCmd prints version info (human or JSON)
var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Print version information",
    Run: func(cmd *cobra.Command, args []string) {
        if outputFmt == "json" {
            fmt.Printf(`{"version":%q,"commit":%q,"built":%q}`+"
",
                version.Version, version.Commit, version.Built)
        } else {
            fmt.Printf("dsd %s (commit %s, built %s)
",
                version.Version, version.Commit, version.Built)
        }
    },
}

func initConfig() {
    if cfgFile != "" {
        viper.SetConfigFile(cfgFile)
    } else {
        home, _ := os.UserHomeDir()
        viper.AddConfigPath(home)
        viper.SetConfigType("yaml")
        viper.SetConfigName(".dsd")
    }
    viper.AutomaticEnv()
    viper.ReadInConfig()
}
```

`internal/collectors/collector.go` — the interface every module implements:
```go
package collectors

import (
    "context"
    "time"
)

type Collector interface {
    Name()    string
    Timeout() time.Duration
    Collect(ctx context.Context) (interface{}, error)
}

// DebugCollector wraps any Collector and prints timing + raw values to stderr
// when --debug is active. Injected by the runner, not by collectors themselves.
type DebugCollector struct {
    Inner   Collector
    Enabled bool
}

func (d *DebugCollector) Name()    string        { return d.Inner.Name() }
func (d *DebugCollector) Timeout() time.Duration { return d.Inner.Timeout() }
func (d *DebugCollector) Collect(ctx context.Context) (interface{}, error) {
    start := time.Now()
    result, err := d.Inner.Collect(ctx)
    if d.Enabled {
        status := "ok"
        if err != nil {
            status = "ERROR: " + err.Error()
        }
        fmt.Fprintf(os.Stderr, "[debug] %-20s  %6.1fms  %s
",
            d.Inner.Name(), float64(time.Since(start).Microseconds())/1000, status)
    }
    return result, err
}
```

`internal/models/cpu.go` — shared data types (avoids import cycles):
```go
package models

// CPUInfo — aggregate CPU snapshot used by dsd health.
type CPUInfo struct {
    Cores         int     `json:"cores"`
    LoadAvg1      float64 `json:"load_avg_1"`
    LoadAvg5      float64 `json:"load_avg_5"`
    LoadAvg15     float64 `json:"load_avg_15"`
    PercentUsed   float64 `json:"percent_used"`
    // LoadPct = LoadAvg1 / Cores * 100 — contextualises load on any machine size
    // "load 4.5 on 16 cores = 28%" vs "load 4.5 on 4 cores = 112%"
    LoadPct       float64 `json:"load_pct"`
    InContainer   bool    `json:"in_container"`
    CPUQuota      float64 `json:"cpu_quota"` // container CPU quota (cores), 0=unlimited
    Status        string  `json:"status"`
    StatusReason  string  `json:"status_reason"`
}

// CPUCoreInfo — per-core detail used by dsd health deep.
// Temperature and throttle data is Linux-only via /sys/class/thermal
// and /sys/devices/system/cpu/cpu*/cpufreq/.
type CPUCoreInfo struct {
    CoreID       int     `json:"core_id"`
    UsagePct     float64 `json:"usage_pct"`
    TempCelsius  float64 `json:"temp_celsius"`   // 0 = unavailable
    FreqMHz      int     `json:"freq_mhz"`        // current frequency
    MaxFreqMHz   int     `json:"max_freq_mhz"`
    Throttled    bool    `json:"throttled"`       // cur_freq < max_freq * 0.9
    Status       string  `json:"status"`
    StatusReason string  `json:"status_reason"`
}

// CPUDetailInfo — full per-core breakdown returned by CPUDetailCollector.
type CPUDetailInfo struct {
    Cores      []CPUCoreInfo `json:"cores"`
    AvgUsagePct float64      `json:"avg_usage_pct"`
    HotCores   []int         `json:"hot_cores"`      // core IDs with temp > 85°C
    ThrottledCores []int     `json:"throttled_cores"`
    Status      string       `json:"status"`
    StatusReason string      `json:"status_reason"`
}
```

`internal/collectors/cpu.go`:
```go
package collectors

import (
    "fmt"
    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/shirou/gopsutil/v3/load"
    "github.com/yourusername/dashdiag/internal/models"
)

type CPUCollector struct{}

func (c *CPUCollector) Name() string { return "CPU" }

func (c *CPUCollector) Collect() (interface{}, error) {
    cores, err := cpu.Counts(true)
    if err != nil {
        return nil, fmt.Errorf("cpu count: %w", err)
    }

    avg, err := load.Avg()
    if err != nil {
        return nil, fmt.Errorf("load avg: %w", err)
    }

    pct, err := cpu.Percent(0, false)
    if err != nil {
        return nil, fmt.Errorf("cpu percent: %w", err)
    }
    var used float64
    if len(pct) > 0 {
        used = pct[0]
    }

    return models.CPUInfo{
        Cores:       cores,
        LoadAvg1:    avg.Load1,
        LoadAvg5:    avg.Load5,
        LoadAvg15:   avg.Load15,
        PercentUsed: used,
    }, nil
}
```

`internal/output/tty.go` — auto-TTY detection (create this first, used by everything):
```go
package output

import "os"

// OutputMode describes which rendering style to use.
type OutputMode int

const (
    ModeHuman  OutputMode = iota // colored terminal, emoji, lipgloss
    ModePlain                    // ASCII only, no emoji, no color (--plain or non-TTY)
    ModeReport                   // markdown tables for Slack/GitHub/incident rooms (--report)
    ModeJSON                     // raw JSON for scripting (--json)
    ModeYAML                     // YAML output for K8s/Ansible workflows (--yaml)
)

// DetectMode resolves the output mode from flags and TTY state.
// Priority: explicit flags win over auto-detection.
func DetectMode(plain, report bool, outputFmt string) OutputMode {
    switch {
    case outputFmt == "json":  return ModeJSON
    case outputFmt == "yaml":  return ModeYAML
    case outputFmt == "quiet": return ModePlain
    case report:               return ModeReport
    case plain:                return ModePlain
    default:
        // Auto-detect: non-TTY → plain
        stat, err := os.Stdout.Stat()
        if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
            return ModePlain
        }
        return ModeHuman
    }
}

// IsPlain returns true for any non-human, non-report mode.
func IsPlain(flagValue bool) bool {
    stat, err := os.Stdout.Stat()
    if flagValue || err != nil {
        return true
    }
    return (stat.Mode() & os.ModeCharDevice) == 0
}

// StatusIcon returns the right status symbol for the current output mode.
func StatusIcon(status string, mode OutputMode) string {
    switch mode {
    case ModePlain:
        switch status {
        case "OK":      return "OK"
        case "WARN":    return "WARN"
        case "CRIT":    return "FAIL"
        case "INFO":    return "INFO"
        case "PENDING": return "PENDING"
        default:        return "?"
        }
    case ModeReport:
        // Markdown/Slack — emoji + text for screen-reader friendliness
        switch status {
        case "OK":      return "✅ OK"
        case "WARN":    return "⚠️ WARN"
        case "CRIT":    return "❌ FAIL"
        case "INFO":    return "ℹ️ INFO"
        case "PENDING": return "⏳ PENDING"
        default:        return "?"
        }
    default: // ModeHuman
        switch status {
        case "OK":      return "✅"
        case "WARN":    return "⚠️ "
        case "CRIT":    return "❌"
        case "INFO":    return "ℹ️ "
        case "PENDING": return "⏳"
        default:        return "?"
        }
    }
}
```

`internal/output/progress.go` — expectation transparency (Principle 8):

```go
package output

import (
    "fmt"
    "os"
    "strings"
    "time"
)

// CommandProgress prints the startup line and live progress for any command.
// It must be created and Start() called before runner.RunAll() is invoked —
// the estimate must appear within 50ms of the command starting.
//
// Usage in cmd/net_deep.go:
//   p := output.NewCommandProgress("Deep network analysis", 30*time.Second, mode)
//   p.Start()
//   defer p.Done()
//   results := runner.RunAll(ctx, cols)
//   for result := range results {
//       p.Step(result.Name)  // updates "Running: <collector>" line
//       renderer.PrintSection(result)
//   }
type CommandProgress struct {
    label    string
    estimate time.Duration
    mode     OutputMode
    total    int          // total number of collectors
    done     int          // completed collectors
    start    time.Time
}

func NewCommandProgress(label string, estimate time.Duration, mode OutputMode, total int) *CommandProgress {
    return &CommandProgress{
        label:    label,
        estimate: estimate,
        mode:     mode,
        total:    total,
    }
}

// Start prints the startup line immediately — before any async work begins.
func (p *CommandProgress) Start() {
    p.start = time.Now()
    estSecs := int(p.estimate.Seconds())

    if p.mode == ModePlain || !isaTTY() {
        fmt.Fprintf(os.Stderr, "[INFO] Starting %s (~%ds)
", p.label, estSecs)
        return
    }
    // Human mode: startup line to stderr so it does not corrupt --json
    fmt.Fprintf(os.Stderr, "⚡ %s (read-only) — ~%ds
", p.label, estSecs)
}

// Step updates the "Running: <name>" progress line.
// Called as each collector result arrives from the runner channel.
func (p *CommandProgress) Step(collectorName string) {
    p.done++
    if p.mode == ModePlain || !isaTTY() {
        fmt.Fprintf(os.Stderr, "[INFO] Running: %s
", collectorName)
        return
    }
    // Build progress bar: 16 chars wide
    pct     := float64(p.done) / float64(p.total)
    filled  := int(pct * 16)
    bar     := strings.Repeat("▓", filled) + strings.Repeat("░", 16-filled)
    // 
 overwrites the current line — progress stays on one line
    fmt.Fprintf(os.Stderr, "
   Running: %-30s [%s] %3.0f%%",
        collectorName+"…", bar, pct*100)
}

// Note prints an informational note on a new line — used for slow conditional
// steps like traceroute: "ℹ️  This may take up to 15s — tracing path to 8.8.8.8"
func (p *CommandProgress) Note(msg string) {
    if p.mode == ModePlain || !isaTTY() {
        fmt.Fprintf(os.Stderr, "[INFO] %s
", msg)
        return
    }
    fmt.Fprintf(os.Stderr, "
   ℹ️  %s
", msg)
}

// Done clears the progress line and prints the completion time.
func (p *CommandProgress) Done() {
    elapsed := time.Since(p.start).Round(time.Millisecond)
    if p.mode == ModePlain || !isaTTY() {
        fmt.Fprintf(os.Stderr, "[INFO] Completed in %s
", elapsed)
        return
    }
    // Clear progress line, print completion
    fmt.Fprintf(os.Stderr, "
%-60s
", "") // clear line
    fmt.Fprintf(os.Stderr, "⚡ Completed in %s

", elapsed)
}

// isaTTY returns true if stderr is a real terminal.
// Progress output goes to stderr so it never corrupts --json stdout.
func isaTTY() bool {
    stat, err := os.Stderr.Stat()
    if err != nil { return false }
    return (stat.Mode() & os.ModeCharDevice) != 0
}
```

**Usage pattern in every command file:**

```go
// cmd/net_deep.go
func runNetDeep(cmd *cobra.Command, args []string) {
    mode := output.DetectMode(plainMode, reportMode, outputFmt)

    // Principle 8: print estimate BEFORE any work starts
    p := output.NewCommandProgress(
        "Deep network analysis", 30*time.Second, mode,
        len(deepNetCollectors))
    p.Start()
    defer p.Done()

    // Conditional step warning — traceroute may trigger
    fmt.Fprintln(os.Stderr, "")
    p.Note("Traceroute runs only if packet loss > 5% or latency > 200ms")

    results := runner.RunAll(ctx, deepNetCollectors)
    for result := range results {
        p.Step(result.Name)  // updates live progress line

        // Special note when traceroute triggers
        if result.Name == "Traceroute" && result.Data != nil {
            p.Note("Tracing path to 8.8.8.8 — this may take up to 15s")
        }

        result = analysis.ApplyThresholds(result, thresh)
        renderer.PrintSection(result)
    }
    renderer.PrintSummary()
}
```

**Startup lines per command (locked spec):**

```
dsd health       → ⚡ System health (read-only) — ~5s
dsd health deep  → ⚡ System health deep (read-only) — ~8s
dsd net          → ⚡ Network snapshot (read-only) — ~3s
dsd net deep     → ⚡ Deep network analysis (read-only) — ~30s
                   ℹ️  Traceroute runs only if a problem is detected
dsd k8s          → ⚡ Kubernetes cluster check (read-only) — ~10s
dsd k8s deep     → ⚡ Kubernetes full audit (read-only) — ~15s
dsd docker       → ⚡ Container runtime check (read-only) — ~5s
dsd security     → ⚡ Security posture check (read-only) — ~10s
dsd logs         → ⚡ Log analysis (read-only) — ~8s
dsd full         → ⚡ Full diagnostic (read-only) — ~45s
```

**Critical implementation rules:**
- Progress output ALWAYS goes to `stderr` — stdout stays clean for `--json`
- Progress line uses `
` to overwrite in place — no scrolling status spam
- In `--plain` / non-TTY mode: static `[INFO]` lines replace animated bar
- `p.Start()` is called BEFORE `runner.RunAll()` — estimate appears in < 50ms
- `defer p.Done()` ensures cleanup even on early return or error
```

`internal/output/formatter.go`:
```go
package output

import (
    "encoding/json"
    "fmt"
    "os"
    "github.com/yourusername/dashdiag/internal/models"
)

type Formatter struct {
    format string
    plain  bool   // --plain flag or auto-TTY detected
}

func NewFormatter(format string, plainFlag bool) *Formatter {
    return &Formatter{
        format: format,
        plain:  IsPlain(plainFlag),
    }
}

func (f *Formatter) Format(data map[string]interface{}) error {
    switch f.format {
    case "json":
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        return enc.Encode(data)
    case "quiet":
        return nil
    default:
        return f.humanFormat(data)
    }
}

func (f *Formatter) humanFormat(data map[string]interface{}) error {
    for name, value := range data {
        fmt.Printf("\n=== %s ===\n", name)
        switch v := value.(type) {
        case models.CPUInfo:
            icon := StatusIcon("OK", f.plain)
            fmt.Printf("  %s Cores:        %d\n", icon, v.Cores)
            fmt.Printf("  %s Load average: %.2f (1m)  %.2f (5m)  %.2f (15m)\n",
                icon, v.LoadAvg1, v.LoadAvg5, v.LoadAvg15)
            fmt.Printf("  %s Usage:        %.1f%%\n", icon, v.PercentUsed)
        default:
            fmt.Printf("  %+v\n", v)
        }
    }
    return nil
}
```

---

### Step 1: Build Checks One at a Time

**Memory check:**
```
Prompt:
"Using gopsutil/v3/mem, write internal/collectors/memory.go + internal/models/memory.go.
Return: total RAM, free RAM, used %, swap total, swap used.
CheckResult struct: Status (OK/WARN/CRIT), Label, Value string.
WARN if RAM > 80% used, CRIT if > 95%."
```

**Disk check:**
```
Prompt:
"Using gopsutil/v3/disk, write internal/collectors/disk.go.
Check all mounted filesystems. Skip: tmpfs, devtmpfs, overlay, squashfs.
Return list of CheckResult with free space and usage %.
WARN at 80%, CRIT at 90%. Also check inode usage."
```

On macOS: use gopsutil IOCounters() — rotational detection not available, skip await thresholds."
```

**Network check (quick — for `dsd health`):**
```
Prompt:
"Using gopsutil/v3/net for interface list and go-ping for ICMP,
and gns for gateway/DNS detection, write internal/collectors/network_quick.go.
Collect:
- All non-loopback, non-virtual interfaces (name/status/IPv4/IPv6)
- Gateway reachability (3 pings, 500ms timeout each, concurrent)
- 8.8.8.8 internet (3 pings, concurrent with gateway ping)
- DNS server list via gns
- TCP CLOSE_WAIT count via gopsutil net.Connections('tcp')
  — flag WARN if > 10 even in quick mode (it is always a bug)
- Default route exists via gns.GetGateways() — CRIT if missing + interfaces UP
- NAT detection: PublicIP != interface IPs (best effort, 2s timeout)
Skip: loopback, docker0, virbr*, veth* interfaces.
Handle: no default gateway gracefully (container environments).
Total timeout: 5 seconds max for the entire collector."
```

---

### Step 1b: Swap & IO Reference Implementation

**Data models — `internal/models/swap.go` and `internal/models/io.go`:**

```go
// internal/models/swap.go
package models

type SwapInfo struct {
    // Traditional swap (file or partition)
    Configured    bool
    TotalGB       float64
    UsedGB        float64
    UsedPct       float64

    // Activity rate from /proc/vmstat (Linux) or vm_stat output (macOS)
    SIPerSec      float64  // pages swapped IN per sec  — RAM was needed
    SOPerSec      float64  // pages swapped OUT per sec — RAM is full
    ActivityAvail bool     // false on unsupported OS

    // zram (compressed RAM swap) — nil if not present
    ZRAMDevices   []ZRAMDevice

    // zswap (compressed cache in front of real swap) — zero value if absent
    ZSwap         ZSwapInfo

    // True if ANY swap is available (traditional OR zram)
    // Used to suppress false "no swap" warnings on zram-only systems
    HasAnySwap    bool

    Status        string
    StatusReason  string
}

type ZRAMDevice struct {
    Device       string
    DiskSizeGB   float64
    MemUsedGB    float64  // actual RAM consumed by this zram device
    OrigDataGB   float64  // uncompressed logical size stored
    ComprDataGB  float64  // actual compressed size in RAM
    ComprRatio   float64  // OrigData / ComprData — higher is better
    Algorithm    string   // lz4, zstd, lzo-rle, etc.
    UtilPct      float64  // MemUsed / DiskSize * 100
    Status       string
    StatusReason string
}

type ZSwapInfo struct {
    Enabled      bool
    MaxPoolPct   int     // % of RAM configured as max pool
    PoolUsedMB   float64 // current pool usage (requires debugfs/root)
    StoredPages  uint64  // pages currently in pool (requires debugfs/root)
    StatsAvail   bool    // false if debugfs not accessible
}

// internal/models/io.go
package models

type IODeviceResult struct {
    Device        string
    Rotational    bool    // true = HDD, false = SSD/NVMe
    IsZRAM        bool    // true = zram compressed swap device
    UtilPct       float64 // 0-100
    AwaitMs       float64 // avg IO wait per operation (ms)
    ReadMBs       float64
    WriteMBs      float64
    QueueDepth    int     // current IO queue length (from /sys/block/<dev>/stat field 9)
    MaxQueueDepth int     // configured queue depth (/sys/block/<dev>/queue/nr_requests)
    Status        string
    StatusReason  string
}

type IOInfo struct {
    Devices    []IODeviceResult
    SampleSecs float64 // actual elapsed time between samples
}
```

**Swap collector — full zram/zswap-aware implementation:**

```go
// internal/collectors/swap.go
package collectors

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "github.com/shirou/gopsutil/v3/mem"
    "github.com/yourusername/dashdiag/internal/models"
)

type SwapCollector struct{}

func (c *SwapCollector) Name()    string        { return "Swap" }
func (c *SwapCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *SwapCollector) Collect(ctx context.Context) (interface{}, error) {
    vmem, err := mem.VirtualMemory()
    if err != nil {
        return nil, fmt.Errorf("virtual memory: %w", err)
    }
    smem, err := mem.SwapMemory()
    if err != nil {
        return nil, fmt.Errorf("swap memory: %w", err)
    }

    // Detect zram and zswap before evaluating "no swap" warnings
    zramDevs, _ := detectZRAM()
    zswap        := detectZSwap()

    info := models.SwapInfo{
        Configured:   smem.Total > 0,
        TotalGB:      float64(smem.Total) / 1024 / 1024 / 1024,
        UsedGB:       float64(smem.Used) / 1024 / 1024 / 1024,
        UsedPct:      smem.UsedPercent,
        ZRAMDevices:  zramDevs,
        ZSwap:        zswap,
        HasAnySwap:   smem.Total > 0 || len(zramDevs) > 0,
    }

    ramUsedPct := vmem.UsedPercent

    // Check 1: swap safety net — only warn if NO swap of any kind exists
    if !info.HasAnySwap {
        switch {
        case ramUsedPct > 90:
            info.Status = "CRIT"
            info.StatusReason = fmt.Sprintf(
                "no swap or zram configured, RAM at %.0f%% — OOM imminent", ramUsedPct)
        case ramUsedPct > 80:
            info.Status = "WARN"
            info.StatusReason = fmt.Sprintf(
                "no swap or zram configured, RAM at %.0f%% — no safety net", ramUsedPct)
        default:
            info.Status = "OK"
        }
        return info, nil
    }

    // Check 2: traditional swap usage
    if info.Configured {
        switch {
        case info.UsedPct > 60:
            info.Status = "CRIT"
            info.StatusReason = fmt.Sprintf("swap %.0f%% full", info.UsedPct)
        case info.UsedPct > 20:
            info.Status = "WARN"
            info.StatusReason = fmt.Sprintf("swap %.0f%% used", info.UsedPct)
        default:
            info.Status = "OK"
        }
    }

    // Check 3: zram health (may override status upward)
    for _, z := range zramDevs {
        if z.Status == "CRIT" {
            info.Status = "CRIT"
            info.StatusReason = z.StatusReason
        } else if z.Status == "WARN" && info.Status == "OK" {
            info.Status = "WARN"
            info.StatusReason = z.StatusReason
        }
    }

    // Check 4: swap activity rate from /proc/vmstat
    si1, so1, err := readVMStat()
    if err == nil {
        select {
        case <-time.After(time.Second):
        case <-ctx.Done():
            return info, nil
        }
        si2, so2, _ := readVMStat()
        info.SIPerSec = float64(si2 - si1)
        info.SOPerSec = float64(so2 - so1)
        info.ActivityAvail = true

        switch {
        case info.SIPerSec > 100 || info.SOPerSec > 100:
            info.Status = "CRIT"
            info.StatusReason = fmt.Sprintf(
                "active thrashing: si=%.0f so=%.0f pages/sec — check for memory leaks",
                info.SIPerSec, info.SOPerSec)
        case info.SIPerSec > 0 || info.SOPerSec > 0:
            if info.Status == "OK" {
                info.Status = "WARN"
                info.StatusReason = fmt.Sprintf(
                    "paging active: si=%.0f so=%.0f pages/sec", info.SIPerSec, info.SOPerSec)
            }
        }
    }

    if info.Status == "" {
        info.Status = "OK"
    }
    return info, nil
}

// detectZRAM scans /sys/block/zram* and reads per-device stats.
func detectZRAM() ([]models.ZRAMDevice, error) {
    entries, _ := filepath.Glob("/sys/block/zram*")
    if len(entries) == 0 {
        return nil, nil
    }
    var devices []models.ZRAMDevice
    for _, path := range entries {
        dev       := filepath.Base(path)
        diskSize  := readSysUint64(path + "/disksize")
        memUsed   := readSysUint64(path + "/mem_used_total")
        origData  := readSysUint64(path + "/orig_data_size")
        comprData := readSysUint64(path + "/compr_data_size")
        algoBytes, _ := os.ReadFile(path + "/comp_algorithm")

        var ratio float64
        if comprData > 0 {
            ratio = float64(origData) / float64(comprData)
        }
        var utilPct float64
        if diskSize > 0 {
            utilPct = float64(memUsed) / float64(diskSize) * 100
        }

        status, reason := zramStatus(utilPct, ratio)
        devices = append(devices, models.ZRAMDevice{
            Device:       dev,
            DiskSizeGB:   float64(diskSize) / 1e9,
            MemUsedGB:    float64(memUsed) / 1e9,
            OrigDataGB:   float64(origData) / 1e9,
            ComprDataGB:  float64(comprData) / 1e9,
            ComprRatio:   ratio,
            Algorithm:    strings.TrimSpace(string(algoBytes)),
            UtilPct:      utilPct,
            Status:       status,
            StatusReason: reason,
        })
    }
    return devices, nil
}

func zramStatus(utilPct, ratio float64) (string, string) {
    switch {
    case utilPct > 90:
        return "CRIT", fmt.Sprintf("zram %.0f%% full — compressed RAM nearly exhausted", utilPct)
    case utilPct > 70:
        return "WARN", fmt.Sprintf("zram %.0f%% full", utilPct)
    case ratio > 0 && ratio < 1.5:
        return "WARN", fmt.Sprintf("poor compression ratio %.1fx — binary/encrypted data?", ratio)
    default:
        return "OK", ""
    }
}

// detectZSwap reads zswap kernel parameters.
func detectZSwap() models.ZSwapInfo {
    enabled, _ := os.ReadFile("/sys/module/zswap/parameters/enabled")
    maxPool, _  := os.ReadFile("/sys/module/zswap/parameters/max_pool_percent")

    info := models.ZSwapInfo{
        Enabled: strings.TrimSpace(string(enabled)) == "Y",
    }
    if v, err := strconv.Atoi(strings.TrimSpace(string(maxPool))); err == nil {
        info.MaxPoolPct = v
    }
    // debugfs requires root — best effort only
    if pages, err := strconv.ParseUint(strings.TrimSpace(
        readSysString("/sys/kernel/debug/zswap/stored_pages")), 10, 64); err == nil {
        info.StoredPages = pages
        info.StatsAvail  = true
    }
    if pool, err := strconv.ParseUint(strings.TrimSpace(
        readSysString("/sys/kernel/debug/zswap/pool_total_size")), 10, 64); err == nil {
        info.PoolUsedMB = float64(pool) / 1024 / 1024
    }
    return info
}

// readVMStat reads swap page-in/out counters.
// On Linux: parses /proc/vmstat (pswpin / pswpout).
// On macOS: runs 'vm_stat' and parses "Pageins" / "Pageouts".
// Returns an error on unsupported OS — SwapInfo.ActivityAvail will be false.
func readVMStat() (pswpin, pswpout uint64, err error) {
    // Linux path: /proc/vmstat
    if data, e := os.ReadFile("/proc/vmstat"); e == nil {
        for _, line := range strings.Split(string(data), "
") {
            fields := strings.Fields(line)
            if len(fields) < 2 {
                continue
            }
            val, _ := strconv.ParseUint(fields[1], 10, 64)
            switch fields[0] {
            case "pswpin":  pswpin = val
            case "pswpout": pswpout = val
            }
        }
        return pswpin, pswpout, nil
    }

    // macOS path: vm_stat
    // Output lines look like: "Pages swapped in:                     12345."
    out, e := exec.Command("vm_stat").Output()
    if e != nil {
        return 0, 0, fmt.Errorf("vm_stat: %w", e)
    }
    for _, line := range strings.Split(string(out), "
") {
        lower := strings.ToLower(line)
        // Strip trailing period and whitespace, parse last field as number
        clean := strings.TrimRight(strings.TrimSpace(line), ".")
        fields := strings.Fields(clean)
        if len(fields) == 0 {
            continue
        }
        val, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
        if err != nil {
            continue
        }
        switch {
        case strings.Contains(lower, "swapped in"):
            pswpin = val
        case strings.Contains(lower, "swapped out"):
            pswpout = val
        }
    }
    if pswpin == 0 && pswpout == 0 {
        // vm_stat ran but no swap lines found — swap may be disabled or macOS version varies
        return 0, 0, fmt.Errorf("vm_stat: no swap counters found")
    }
    return pswpin, pswpout, nil
}

func readSysUint64(path string) uint64 {
    data, err := os.ReadFile(path)
    if err != nil {
        return 0
    }
    v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
    return v
}

func readSysString(path string) string {
    data, err := os.ReadFile(path)
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(data))
}
```

**IO collector — dual-sample delta pattern:**

```go
// internal/collectors/io.go
package collectors

import (
    "context"
    "fmt"
    "os"
    "strings"
    "time"

    "github.com/shirou/gopsutil/v3/disk"
    "github.com/yourusername/dashdiag/internal/models"
)

type IOCollector struct{}

func (c *IOCollector) Name()    string        { return "Disk IO" }
func (c *IOCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *IOCollector) Collect(ctx context.Context) (interface{}, error) {
    c1, err := disk.IOCounters()
    if err != nil {
        return nil, fmt.Errorf("io counters: %w", err)
    }
    t1 := time.Now()

    select {
    case <-time.After(time.Second):
    case <-ctx.Done():
        return nil, ctx.Err()
    }

    c2, _ := disk.IOCounters()
    elapsed := time.Since(t1).Seconds()

    var results []models.IODeviceResult

    for name, s2 := range c2 {
        s1, ok := c1[name]
        if !ok || isVirtualDevice(name) {
            continue
        }

        deltaIOs    := float64((s2.ReadCount + s2.WriteCount) - (s1.ReadCount + s1.WriteCount))
        deltaIOTime := float64(s2.IoTime - s1.IoTime)
        deltaRBytes := float64(s2.ReadBytes - s1.ReadBytes)
        deltaWBytes := float64(s2.WriteBytes - s1.WriteBytes)

        utilPct := (deltaIOTime / (elapsed * 1000)) * 100
        if utilPct > 100 {
            utilPct = 100
        }

        var awaitMs float64
        if deltaIOs > 0 {
            awaitMs = float64((s2.ReadTime+s2.WriteTime)-(s1.ReadTime+s1.WriteTime)) / deltaIOs
        }

        rotational := isRotational(name)

        status, reason := ioStatus(utilPct, awaitMs, rotational)

        results = append(results, models.IODeviceResult{
            Device:       name,
            Rotational:   rotational,
            UtilPct:      utilPct,
            AwaitMs:      awaitMs,
            ReadMBs:      deltaRBytes / elapsed / 1024 / 1024,
            WriteMBs:     deltaWBytes / elapsed / 1024 / 1024,
            Status:       status,
            StatusReason: reason,
        })
    }

    return models.IOInfo{Devices: results, SampleSecs: elapsed}, nil
}

func ioStatus(util, await float64, rotational bool, zram bool) (string, string) {
    if zram {
        // zram is RAM-speed — thresholds are in fractions of a millisecond
        switch {
        case await > 2.0:
            return "CRIT", fmt.Sprintf("zram await %.1fms — abnormal for RAM device, check memory pressure", await)
        case await > 0.5:
            return "WARN", fmt.Sprintf("zram await %.2fms — elevated for RAM device", await)
        case util > 90:
            return "WARN", fmt.Sprintf("zram util %.0f%% — heavily loaded", util)
        default:
            return "OK", ""
        }
    }
    warnAwait, critAwait := 1.0, 5.0
    if rotational {
        warnAwait, critAwait = 20.0, 50.0
    }
    switch {
    case util > 85:
        return "CRIT", fmt.Sprintf("util %.0f%% — device saturated", util)
    case await > critAwait:
        return "CRIT", fmt.Sprintf("await %.1fms — IO severely degraded", await)
    case util > 60:
        return "WARN", fmt.Sprintf("util %.0f%% — high utilization", util)
    case await > warnAwait:
        return "WARN", fmt.Sprintf("await %.1fms — elevated IO latency", await)
    default:
        return "OK", ""
    }
}

func isRotational(dev string) bool {
    data, err := os.ReadFile("/sys/block/" + dev + "/queue/rotational")
    if err != nil {
        return false // assume SSD
    }
    return strings.TrimSpace(string(data)) == "1"
}

func isVirtualDevice(name string) bool {
    // zram* devices are NOT virtual — they are real swap devices
    // that need their own threshold tier (RAM-speed, not disk-speed)
    for _, prefix := range []string{"loop", "ram", "sr", "dm-", "md"} {
        if strings.HasPrefix(name, prefix) {
            return true
        }
    }
    return false
}

func isZRAMDevice(name string) bool {
    return strings.HasPrefix(name, "zram")
}
```

**Threshold reference table:**

| Device / Metric | OK | WARN | CRIT |
|---|---|---|---|
| Traditional swap usage | < 20% | 20–60% | > 60% |
| Swap activity si/so | 0 pages/sec | > 0/sec | > 100/sec |
| No swap of any kind + RAM | < 80% | 80–90% | > 90% |
| zram utilization | < 70% | 70–90% | > 90% |
| zram compression ratio | > 2.0x | 1.5–2.0x | < 1.5x |
| zram IO await | < 0.5ms | 0.5–2ms | > 2ms |
| zswap pool usage | < 50% max | 50–80% max | > 80% max |
| IO utilization (any disk) | < 60% | 60–85% | > 85% |
| IO await (HDD) | < 20ms | 20–50ms | > 50ms |
| IO await (SSD/NVMe) | < 1ms | 1–5ms | > 5ms |
| IO queue depth | < 50% max | 50–80% max | > 80% max |

**Where each check runs:**

| Check | `dsd health` | `dsd full` |
|---|---|---|
| Swap usage % | ✅ | ✅ |
| Swap activity rate (1s sample) | ✅ (runs concurrently) | ✅ |
| No-swap + RAM warning | ✅ | ✅ |
| IO utilization % | ✅ (root device) | ✅ (all devices) |
| IO await per device type | ✅ | ✅ |
| IO throughput MB/s | — | ✅ |

**Target output — healthy system with zram:**

```
[Swap]
✅ zram0 (lz4):  1.4GB used / 4GB  (35%)  ratio: 2.8x  compression working well
✅ Activity:     si=0  so=0 pages/sec  (no active paging)
ℹ️  zswap:       enabled, pool max 20% RAM

[Disk IO]           util%   await    read      write     type
✅ nvme0n1          34%     0.3ms    245 MB/s  88 MB/s   NVMe
✅ sda              12%     4.2ms    1.2 MB/s  0.8 MB/s  HDD
✅ zram0            18%     0.04ms   —         —         zram
```

**Target output — traditional swap (no zram):**

```
[Swap]
✅ Swap: 512MB used / 4GB  (13%)
✅ Activity: si=0  so=0 pages/sec  (no active paging)

[Disk IO]           util%   await    read      write     type
✅ nvme0n1          34%     0.3ms    245 MB/s  88 MB/s   NVMe
```

**Target output — problems detected:**

```
[Swap]
⚠️  zram0 (lz4):  3.7GB used / 4GB  (92%)  ratio: 1.2x  ← full + poor compression
❌  Activity:      si=210  so=180 pages/sec  (thrashing — zram full, spilling to disk)
    → ps aux --sort=-%mem | head -10
    → dmesg | grep -i oom

[Disk IO]           util%   await     read     write     type
❌ sda              97%     180ms     —        42 MB/s   HDD  ← saturated
✅ nvme0n1          8%      0.2ms     12 MB/s  3 MB/s    NVMe
⚠️  zram0           88%     0.9ms     —        —         zram ← high util
   → iostat -x 1 5   or   iotop -ao
```

**Heuristics — add to `internal/analysis/heuristics.go`:**

```go
// Swap thrashing
if snapshot.Swap.ActivityAvail &&
    (snapshot.Swap.SIPerSec > 100 || snapshot.Swap.SOPerSec > 100) {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf("swap thrashing: si=%.0f so=%.0f pages/sec — OOM approaching",
            snapshot.Swap.SIPerSec, snapshot.Swap.SOPerSec),
        Hints: []string{
            "ps aux --sort=-%mem | head -10",
            "cat /proc/meminfo | grep -i swap",
            "dmesg | grep -i 'oom\|killed'",
        },
    })
}

// zram full with poor compression — data not compressible, RAM actually exhausted
for _, z := range snapshot.Swap.ZRAMDevices {
    if z.UtilPct > 90 && z.ComprRatio < 1.5 {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf("zram %s: %.0f%% full, poor compression (%.1fx) — likely binary/encrypted data, consider traditional swap",
                z.Device, z.UtilPct, z.ComprRatio),
            Hints: []string{
                "cat /proc/swaps",
                "zramctl",
                "ps aux --sort=-%mem | head -10",
            },
        })
    }
}

// IO saturated
for _, dev := range snapshot.IO.Devices {
    if dev.UtilPct > 85 && !dev.IsZRAM {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf("device %s saturated (%.0f%% util, %.1fms await)",
                dev.Device, dev.UtilPct, dev.AwaitMs),
            Hints: []string{"iostat -x 1 5", "iotop -ao"},
        })
    }
}

// Swap paging with RAM headroom — memory leak signal
if snapshot.Swap.ActivityAvail &&
    snapshot.Swap.SOPerSec > 0 &&
    snapshot.Memory.FreePercent > 20 {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: "swap-out occurring despite free RAM — possible memory leak in specific process",
        Hints: []string{
            "ps aux --sort=-%mem | head -10",
            "smem -rs pss 2>/dev/null | head -10",
        },
    })
}

// TCP CLOSE_WAIT — application not closing connections (almost always a bug)
if snapshot.Network.Connections.CloseWait > 100 {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf("TCP CLOSE_WAIT: %d connections — application not closing sockets, likely a bug",
            snapshot.Network.Connections.CloseWait),
        Hints: []string{
            "lsof -i | grep CLOSE_WAIT",
            "ss -tnp state close-wait",
            "check application logs for connection handling errors",
        },
    })
}

// Proxmox: ZFS pool degraded — data at risk
for _, pool := range snapshot.PVE.ZFSPools {
    if pool.Health == "DEGRADED" || pool.Health == "FAULTED" {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf("ZFS pool '%s' is %s — redundancy lost, replace failed device",
                pool.Name, pool.Health),
            Hints: []string{
                fmt.Sprintf("zpool status %s", pool.Name),
                fmt.Sprintf("zpool scrub %s", pool.Name),
                "zpool replace <pool> <failed-device> <new-device>",
            },
        })
    }
}

// Proxmox: cluster no quorum — VMs cannot start
if snapshot.PVE.Cluster.InCluster && !snapshot.PVE.Cluster.QuorumOK {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf("Proxmox cluster '%s': NO QUORUM (%d/%d nodes online) — split-brain risk",
            snapshot.PVE.Cluster.ClusterName,
            snapshot.PVE.Cluster.NodesOnline,
            snapshot.PVE.Cluster.NodesTotal),
        Hints: []string{
            "corosync-quorumtool -s",
            "journalctl -u corosync --since '10 minutes ago'",
            "pvecm status",
        },
    })
}

// Proxmox: ZFS pool degraded
for _, pool := range snapshot.PVE.ZFSPools {
    if pool.Health == "DEGRADED" || pool.Health == "FAULTED" {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf("ZFS pool '%s' is %s — redundancy lost, replace failed device",
                pool.Name, pool.Health),
            Hints: []string{
                fmt.Sprintf("zpool status %s", pool.Name),
                "zpool replace <pool> <failed-device> <new-device>",
            },
        })
    }
}

// Proxmox: cluster no quorum
if snapshot.PVE.Cluster.InCluster && !snapshot.PVE.Cluster.QuorumOK {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf("Proxmox cluster: NO QUORUM (%d/%d nodes online) — split-brain risk",
            snapshot.PVE.Cluster.NodesOnline,
            snapshot.PVE.Cluster.NodesTotal),
        Hints: []string{
            "corosync-quorumtool -s",
            "pvecm status",
            "journalctl -u corosync --since '10 minutes ago'",
        },
    })
}


// Systemd failed units — service down silently
for _, unit := range snapshot.Systemd.FailedUnits {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf("systemd unit %s is in failed state", unit),
        Hints: []string{
            fmt.Sprintf("systemctl status %s", unit),
            fmt.Sprintf("journalctl -u %s -n 50 -xe", unit),
            // ldd hint: if the unit exits immediately with "not found" or
            // "error while loading shared libraries", this reveals missing .so
            fmt.Sprintf(
                "ldd $(systemctl show -p ExecStart %s --value | awk '{print $1}')",
                unit),
        },
    })
}

// SELinux denials — application silently blocked
if snapshot.KernelSecurity.SELinuxDenials > 0 {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf("SELinux: %d AVC denial(s) in last hour — application may be silently blocked",
            snapshot.KernelSecurity.SELinuxDenials),
        Hints: []string{
            "ausearch -m avc -ts recent",
            "sealert -l "*"  (if setroubleshoot installed)",
        },
    })
}

// FD: deleted-but-open files holding ghost disk space
// "df full but du doesn't match" — classic deleted-file-held-open problem
if snapshot.FD.DeletedOpenSizeGB > 1.0 {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "%d deleted file(s) holding %.1fGB — disk appears full but du shows less",
            snapshot.FD.DeletedOpenFiles, snapshot.FD.DeletedOpenSizeGB),
        Hints: []string{
            "lsof +L1               (show processes holding deleted files)",
            "lsof +L1 | awk '{print $1, $2, $7, $9}'  (name, PID, size, file)",
            "restart the process shown above to reclaim disk space",
        },
    })
}

// FD: per-process saturation
for _, p := range snapshot.FD.HotProcesses {
    if p.UsedPct >= 90 {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf(
                "%s (PID %d) using %.0f%% of FD limit (%d/%d) — will fail to open files/sockets",
                p.Name, p.PID, p.UsedPct, p.OpenFDs, p.SoftLimit),
            Hints: []string{
                fmt.Sprintf("lsof -p %d | wc -l", p.PID),
                fmt.Sprintf("cat /proc/%d/limits | grep 'open files'", p.PID),
                "increase ulimit or fix FD leak in application",
            },
        })
    }
}

// FD: deleted-but-open files holding ghost disk space
// "df full but du doesn't match" — the deleted-file-held-open problem
if snapshot.FD.DeletedOpenSizeGB > 1.0 {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "%d deleted file(s) holding %.1fGB — df shows full but du shows less",
            snapshot.FD.DeletedOpenFiles, snapshot.FD.DeletedOpenSizeGB),
        Hints: []string{
            "lsof +L1  (show processes holding deleted files)",
            "lsof +L1 | awk '{print $1, $2, $7, $9}'",
            "restart the process listed above to reclaim disk space",
        },
    })
}

// FD: per-process saturation — single process hitting ulimit
for _, p := range snapshot.FD.HotProcesses {
    if p.UsedPct >= 90 {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf(
                "%s (PID %d) at %.0f%% FD limit (%d/%d) — will fail to open files/sockets",
                p.Name, p.PID, p.UsedPct, p.OpenFDs, p.SoftLimit),
            Hints: []string{
                fmt.Sprintf("lsof -p %d | wc -l", p.PID),
                fmt.Sprintf("cat /proc/%d/limits | grep 'open files'", p.PID),
                "increase per-process ulimit or fix FD leak in application",
            },
        })
    }
}

// Memory overcommit — OOM risk despite free RAM
if snapshot.Memory.OverCommitted {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf("memory overcommitted: %.0fMB committed / %.0fMB limit — OOM possible despite free RAM",
            snapshot.Memory.CommittedAsMB, snapshot.Memory.CommitLimitMB),
        Hints: []string{
            "ps aux --sort=-%mem | head -10",
            "cat /proc/meminfo | grep -E 'CommitLimit|Committed_AS'",
        },
    })
}

// Bond slave failure — silent redundancy loss
for _, bond := range snapshot.Network.Bonds {
    if bond.UpSlaves < bond.TotalSlaves && bond.UpSlaves > 0 {
        insights = append(insights, models.Insight{
            Level:   "WARN",
            Message: fmt.Sprintf("%s: %d/%d slaves UP — redundancy reduced, single point of failure",
                bond.Name, bond.UpSlaves, bond.TotalSlaves),
            Hints: []string{
                fmt.Sprintf("cat /proc/net/bonding/%s", bond.Name),
                fmt.Sprintf("ip link show %s", bond.Name),
                "check physical cable and switch port",
            },
        })
    }
}

// Link speed/duplex mismatch — silent performance degradation
for _, link := range snapshot.Network.Links {
    if link.Duplex == "Half" {
        insights = append(insights, models.Insight{
            Level:   "WARN",
            Message: fmt.Sprintf("%s: half-duplex negotiation — expect significant throughput degradation",
                link.Interface),
            Hints: []string{
                fmt.Sprintf("ethtool %s", link.Interface),
                "check cable integrity and switch port auto-negotiation settings",
            },
        })
    }
}
```

**Updated AI prompt for swap collector:**

```
Prompt:
"Update internal/collectors/swap.go to handle zram and zswap.

Add detectZRAM() scanning /sys/block/zram* per device:
  disksize, mem_used_total, orig_data_size, compr_data_size, comp_algorithm
  Compression ratio = orig_data_size / compr_data_size (higher = better)
  Utilization % = mem_used_total / disksize * 100
  Thresholds: WARN util > 70% or ratio < 1.5x; CRIT util > 90%

Add detectZSwap() reading:
  /sys/module/zswap/parameters/enabled  (Y/N)
  /sys/module/zswap/parameters/max_pool_percent
  /sys/kernel/debug/zswap/* (best-effort, requires root, set StatsAvail=false if unavailable)

Update SwapInfo.HasAnySwap = smem.Total > 0 OR len(ZRAMDevices) > 0
Only fire 'no swap' warning when HasAnySwap == false

Add readSysUint64(path) and readSysString(path) helpers.

Update internal/collectors/io.go:
  isVirtualDevice() must NOT exclude zram* devices
  Add isZRAMDevice(name string) bool helper
  IODeviceResult add IsZRAM bool field
  ioStatus() add zram tier: WARN await > 0.5ms, CRIT await > 2ms
  Call ioStatus(util, await, rotational, isZRAMDevice(name)) everywhere"
```

---

### Step 1c: Per-Core CPU, SMART Disk, IO Queue Depth, Services

**`internal/models/disk.go` — add SMART and complete FilesystemInfo:**

```go
package models

type SMARTResult struct {
    Device       string
    Available    bool   // false if smartctl not installed or not a physical device
    Overall      string // "PASSED" / "FAILED" / "UNKNOWN"
    ReallocSectors int  // reallocated sector count (> 0 = WARN)
    PendingSectors  int  // pending reallocation (> 0 = WARN)
    PowerOnHours int
    Status       string
    StatusReason string
}

type DiskInfo struct {
    Filesystems []FilesystemInfo
    SMART       []SMARTResult // one per physical block device
}
```

**`internal/models/services.go` — new:**

```go
package models

import "time"

type ServiceCheck struct {
    Name         string        `json:"name"`
    Host         string        `json:"host"`          // default: localhost
    Port         int           `json:"port"`
    Protocol     string        `json:"protocol"`      // "tcp" / "http" / "https"
    ResponseTime time.Duration `json:"response_time"` // 0 if unreachable
    Reachable    bool          `json:"reachable"`
    StatusCode   int           `json:"status_code"`   // HTTP only, 0 if TCP
    Status       string        `json:"status"`
    StatusReason string        `json:"status_reason"`
}

type ServicesInfo struct {
    Checks []ServiceCheck `json:"checks"`
    Status string         `json:"status"`
}
```

**`internal/models/progress.go` — progress bar spec:**

```go
package models

// ProgressBar renders the canonical DashDiag progress bar.
// Format: [███████████-----] 70% success rate
// Always 16 chars wide between brackets.
func ProgressBar(passed, total int) string {
    if total == 0 {
        return "[----------------] 0% success rate"
    }
    pct     := float64(passed) / float64(total)
    filled  := int(pct * 16)
    empty   := 16 - filled
    bar     := strings.Repeat("█", filled) + strings.Repeat("-", empty)
    return fmt.Sprintf("[%s] %.0f%% success rate", bar, pct*100)
}
```

---

**`internal/collectors/cpu_detail.go` — per-core CPU with temperature and throttle:**

```go
package collectors

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "github.com/shirou/gopsutil/v3/cpu"
    "github.com/yourusername/dashdiag/internal/models"
)

type CPUDetailCollector struct{}

func (c *CPUDetailCollector) Name()    string        { return "CPU Detail" }
func (c *CPUDetailCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *CPUDetailCollector) Collect(ctx context.Context) (interface{}, error) {
    // Per-core usage (100ms sample for responsiveness)
    perCorePct, err := cpu.PercentWithContext(ctx, 100*time.Millisecond, true)
    if err != nil {
        return nil, fmt.Errorf("per-core usage: %w", err)
    }

    var cores []models.CPUCoreInfo
    var hotCores, throttledCores []int

    for i, usagePct := range perCorePct {
        core := models.CPUCoreInfo{
            CoreID:   i,
            UsagePct: usagePct,
        }

        // Temperature: /sys/class/thermal/thermal_zone*/temp
        // Match core to thermal zone via /sys/bus/platform/drivers/coretemp/
        core.TempCelsius = readCoreTemp(i)

        // Frequency: /sys/devices/system/cpu/cpu<N>/cpufreq/
        core.FreqMHz    = readCPUFreq(i, "scaling_cur_freq")
        core.MaxFreqMHz = readCPUFreq(i, "scaling_max_freq")

        // Throttle detection: current < 90% of max frequency
        if core.MaxFreqMHz > 0 && core.FreqMHz > 0 {
            core.Throttled = float64(core.FreqMHz) < float64(core.MaxFreqMHz)*0.9
        }

        // Apply thresholds
        switch {
        case usagePct > 95 || core.TempCelsius > 90:
            core.Status = "CRIT"
            core.StatusReason = fmt.Sprintf("core %d: %.0f%% usage, %.0f°C", i, usagePct, core.TempCelsius)
        case usagePct > 80 || core.TempCelsius > 80 || core.Throttled:
            core.Status = "WARN"
        default:
            core.Status = "OK"
        }

        if core.TempCelsius > 80 { hotCores = append(hotCores, i) }
        if core.Throttled         { throttledCores = append(throttledCores, i) }

        cores = append(cores, core)
    }

    avgUsage := averagePct(perCorePct)
    status, reason := aggregateCoreStatus(cores, avgUsage, len(hotCores), len(throttledCores))

    return models.CPUDetailInfo{
        Cores:          cores,
        AvgUsagePct:    avgUsage,
        HotCores:       hotCores,
        ThrottledCores: throttledCores,
        Status:         status,
        StatusReason:   reason,
    }, nil
}

// readCoreTemp reads the temperature for a CPU core from /sys/class/thermal/.
// Returns 0 if not available (macOS, containers, no sensors).
func readCoreTemp(coreID int) float64 {
    // Try coretemp hwmon path first (most x86 Linux)
    patterns := []string{
        fmt.Sprintf("/sys/bus/platform/drivers/coretemp/*/hwmon/hwmon*/temp%d_input", coreID+2),
        "/sys/class/thermal/thermal_zone0/temp", // fallback: package temp
    }
    for _, pattern := range patterns {
        matches, _ := filepath.Glob(pattern)
        if len(matches) == 0 {
            continue
        }
        data, err := os.ReadFile(matches[0])
        if err != nil {
            continue
        }
        milliC, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
        if err != nil {
            continue
        }
        return milliC / 1000.0 // millidegrees → Celsius
    }
    return 0
}

// readCPUFreq reads current or max CPU frequency in MHz.
func readCPUFreq(coreID int, file string) int {
    path := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/%s", coreID, file)
    data, err := os.ReadFile(path)
    if err != nil {
        return 0
    }
    khz, err := strconv.Atoi(strings.TrimSpace(string(data)))
    if err != nil {
        return 0
    }
    return khz / 1000 // kHz → MHz
}

func averagePct(pcts []float64) float64 {
    if len(pcts) == 0 { return 0 }
    var sum float64
    for _, p := range pcts { sum += p }
    return sum / float64(len(pcts))
}

func aggregateCoreStatus(cores []models.CPUCoreInfo, avg float64, hot, throttled int) (string, string) {
    for _, c := range cores {
        if c.Status == "CRIT" {
            return "CRIT", c.StatusReason
        }
    }
    switch {
    case throttled > 0:
        return "WARN", fmt.Sprintf("%d core(s) throttled — check cooling", throttled)
    case hot > 0:
        return "WARN", fmt.Sprintf("%d core(s) above 80°C", hot)
    case avg > 80:
        return "WARN", fmt.Sprintf("average CPU usage %.0f%%", avg)
    default:
        return "OK", ""
    }
}
```

**`internal/collectors/disk.go` — add SMART via smartctl:**

```go
// collectSMART runs smartctl for each physical block device.
// Requires smartctl installed; skips gracefully if unavailable.
// Needs CAP_SYS_RAWIO or root for full data — falls back to basic check.
func collectSMART(ctx context.Context) []models.SMARTResult {
    entries, _ := filepath.Glob("/sys/block/sd*") // physical SATA/SAS/NVMe
    nvme, _    := filepath.Glob("/sys/block/nvme*")
    entries     = append(entries, nvme...)

    var results []models.SMARTResult
    for _, path := range entries {
        dev := "/dev/" + filepath.Base(path)
        result := models.SMARTResult{Device: dev}

        out, err := exec.CommandContext(ctx, "smartctl", "-H", "-A", dev).Output()
        if err != nil {
            // smartctl not installed or no permission
            result.Available    = false
            result.Status       = "INFO"
            result.StatusReason = "smartctl not available (install smartmontools)"
            results = append(results, result)
            continue
        }

        result.Available = true
        text := string(out)

        // Overall health: "SMART overall-health self-assessment test result: PASSED"
        if strings.Contains(text, "PASSED") {
            result.Overall = "PASSED"
            result.Status  = "OK"
        } else if strings.Contains(text, "FAILED") {
            result.Overall = "FAILED"
            result.Status  = "CRIT"
            result.StatusReason = "SMART self-assessment FAILED — drive may be dying"
        }

        // Reallocated sectors (ID 5): any non-zero = WARN
        result.ReallocSectors = parseSMARTAttribute(text, "5 ")
        result.PendingSectors  = parseSMARTAttribute(text, "197 ")

        if result.ReallocSectors > 0 || result.PendingSectors > 0 {
            if result.Status == "OK" {
                result.Status = "WARN"
                result.StatusReason = fmt.Sprintf(
                    "reallocated: %d, pending: %d — monitor closely",
                    result.ReallocSectors, result.PendingSectors)
            }
        }
        results = append(results, result)
    }
    return results
}

// parseSMARTAttribute extracts the RAW_VALUE for a SMART attribute by ID prefix.
func parseSMARTAttribute(text, idPrefix string) int {
    for _, line := range strings.Split(text, "\n") {
        if !strings.HasPrefix(strings.TrimSpace(line), idPrefix) {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) < 10 {
            continue
        }
        v, _ := strconv.Atoi(fields[len(fields)-1])
        return v
    }
    return 0
}
```

**`internal/collectors/io.go` — add queue depth reading:**

```go
// readIOQueueDepth reads the current IO queue depth from /sys/block/<dev>/stat field 9.
// Field 9 = IOs currently in flight.
func readIOQueueDepth(dev string) int {
    data, err := os.ReadFile("/sys/block/" + dev + "/stat")
    if err != nil {
        return 0
    }
    fields := strings.Fields(strings.TrimSpace(string(data)))
    if len(fields) < 9 {
        return 0
    }
    v, _ := strconv.Atoi(fields[8]) // field 9, 0-indexed = 8
    return v
}

// readMaxQueueDepth reads the configured queue depth from /sys/block/<dev>/queue/nr_requests.
func readMaxQueueDepth(dev string) int {
    data, err := os.ReadFile("/sys/block/" + dev + "/queue/nr_requests")
    if err != nil {
        return 0
    }
    v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
    return v
}
```

**Add to `ioStatus()` — queue depth tier:**

```go
// Add to ioStatus() after existing checks:
// High queue depth with moderate utilization = IO queuing up faster than draining
if queueDepth > maxQueueDepth/2 && util < 85 {
    return "WARN", fmt.Sprintf(
        "queue depth %d/%d — IO backlog building", queueDepth, maxQueueDepth)
}
```

**`internal/collectors/services.go` — new:**

```go
package collectors

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

// ServiceConfig defines a service to check. Loaded from ~/.dsd.yaml.
type ServiceConfig struct {
    Name     string `yaml:"name"`
    Host     string `yaml:"host"`     // default: localhost
    Port     int    `yaml:"port"`
    Protocol string `yaml:"protocol"` // "tcp" / "http" / "https"
}

// DefaultServices are checked when no config is provided.
var DefaultServices = []ServiceConfig{
    {Name: "SSH",   Host: "localhost", Port: 22,   Protocol: "tcp"},
    {Name: "HTTP",  Host: "localhost", Port: 80,   Protocol: "http"},
    {Name: "HTTPS", Host: "localhost", Port: 443,  Protocol: "https"},
}

type ServicesCollector struct {
    Services []ServiceConfig // from config, falls back to DefaultServices
}

func (c *ServicesCollector) Name()    string        { return "Services" }
func (c *ServicesCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *ServicesCollector) Collect(ctx context.Context) (interface{}, error) {
    svcs := c.Services
    if len(svcs) == 0 {
        svcs = DefaultServices
    }

    results := make([]models.ServiceCheck, len(svcs))
    // Run all checks concurrently
    var wg sync.WaitGroup
    for i, svc := range svcs {
        i, svc := i, svc
        wg.Add(1)
        go func() {
            defer wg.Done()
            results[i] = checkService(ctx, svc)
        }()
    }
    wg.Wait()

    status := "OK"
    for _, r := range results {
        if r.Status == "CRIT" { status = "CRIT"; break }
        if r.Status == "WARN" { status = "WARN" }
    }

    return models.ServicesInfo{Checks: results, Status: status}, nil
}

func checkService(ctx context.Context, svc ServiceConfig) models.ServiceCheck {
    host := svc.Host
    if host == "" { host = "localhost" }
    addr := fmt.Sprintf("%s:%d", host, svc.Port)

    result := models.ServiceCheck{
        Name:     svc.Name,
        Host:     host,
        Port:     svc.Port,
        Protocol: svc.Protocol,
    }

    start := time.Now()

    switch svc.Protocol {
    case "http", "https":
        url := fmt.Sprintf("%s://%s:%d", svc.Protocol, host, svc.Port)
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        client := &http.Client{Timeout: 5 * time.Second}
        resp, err := client.Do(req)
        result.ResponseTime = time.Since(start)
        if err != nil {
            result.Reachable    = false
            result.Status       = "CRIT"
            result.StatusReason = fmt.Sprintf("connection failed: %v", err)
            return result
        }
        defer resp.Body.Close()
        result.Reachable   = true
        result.StatusCode  = resp.StatusCode

    default: // tcp
        conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
        result.ResponseTime = time.Since(start)
        if err != nil {
            result.Reachable    = false
            result.Status       = "CRIT"
            result.StatusReason = fmt.Sprintf("port %d unreachable", svc.Port)
            return result
        }
        conn.Close()
        result.Reachable = true
    }

    // Apply latency thresholds
    ms := result.ResponseTime.Milliseconds()
    switch {
    case ms > 1000:
        result.Status       = "CRIT"
        result.StatusReason = fmt.Sprintf("response %dms — critically slow", ms)
    case ms > 200:
        result.Status       = "WARN"
        result.StatusReason = fmt.Sprintf("response %dms — elevated latency", ms)
    default:
        result.Status = "OK"
    }
    return result
}
```

**`~/.dsd.yaml` — services configuration example:**

```yaml
# ~/.dsd.yaml — DashDiag configuration

thresholds:
  disk_warn_pct: 80
  disk_crit_pct: 90
  ram_warn_pct: 80
  ram_crit_pct: 95
  cpu_load_warn_multiplier: 0.7    # WARN at load > cores * 0.7
  io_util_warn_pct: 60
  io_util_crit_pct: 85

logs:
  since_minutes: 60
  error_warn_threshold: 10
  error_crit_threshold: 100

security:
  allowed_ports: [22, 80, 443, 8080, 8443, 5432]
  ssh_failed_login_warn: 20
  ssh_failed_login_crit: 50

logs:
  since_minutes: 60                # look-back window for error counting
  error_warn_threshold: 10
  error_crit_threshold: 100

security:
  allowed_ports: [22, 80, 443, 8080, 8443, 5432]
  ssh_failed_login_warn: 20
  ssh_failed_login_crit: 50

services:
  - name: SSH
    host: localhost
    port: 22
    protocol: tcp
  - name: PostgreSQL
    host: localhost
    port: 5432
    protocol: tcp
  - name: Redis
    host: localhost
    port: 6379
    protocol: tcp
  - name: App API
    host: localhost
    port: 8080
    protocol: http
  - name: Nginx
    host: localhost
    port: 443
    protocol: https
```

**AI prompts for new collectors:**

```
Prompt — cpu_detail.go (used by dsd health deep):
"Write internal/collectors/cpu_detail.go with CPUDetailCollector.
Timeout: 2 seconds.
1. Per-core usage: gopsutil cpu.PercentWithContext(ctx, 100ms, true)
2. Temperature per core: read /sys/bus/platform/drivers/coretemp/*/hwmon/hwmon*/temp<N>_input
   Convert millidegrees to Celsius. Return 0 if path not found (macOS/container safe).
3. Current frequency: /sys/devices/system/cpu/cpu<N>/cpufreq/scaling_cur_freq (kHz → MHz)
4. Max frequency: /sys/devices/system/cpu/cpu<N>/cpufreq/scaling_max_freq
5. Throttled = cur_freq < max_freq * 0.9
6. Thresholds per core: WARN usage > 80% OR temp > 80°C OR throttled; CRIT > 95% OR > 90°C
7. Aggregate: CRIT if any core CRIT; WARN if throttled or hot cores exist
Return models.CPUDetailInfo with []CPUCoreInfo, HotCores []int, ThrottledCores []int."
```

```
Prompt — services.go:
"Write internal/collectors/services.go with ServicesCollector.
Load service list from viper config key 'services' ([]ServiceConfig: name/host/port/protocol).
Fall back to DefaultServices (SSH:22, HTTP:80, HTTPS:443) if config empty.
Run all checks concurrently with sync.WaitGroup, respect ctx cancellation.
TCP check: net.Dialer.DialContext, measure time to connect.
HTTP/HTTPS check: http.NewRequestWithContext GET /, measure time to first byte.
Thresholds: WARN > 200ms, CRIT > 1000ms or connection refused.
Timeout per check: 5 seconds (inner), 10 seconds total collector Timeout().
Return models.ServicesInfo{Checks, Status}."
```

```
Prompt — SMART in disk.go:
"Add collectSMART(ctx context.Context) []models.SMARTResult to internal/collectors/disk.go.
Glob /sys/block/sd* and /sys/block/nvme* for physical devices.
For each: exec.CommandContext(ctx, 'smartctl', '-H', '-A', '/dev/<device>').
If smartctl not found → return SMARTResult{Available: false, Status: INFO}.
If permission denied → same INFO result with hint to run with sudo.
Parse: 'SMART overall-health self-assessment test result: PASSED/FAILED'
Parse attribute 5 (Reallocated_Sector_Ct) and 197 (Current_Pending_Sector) RAW_VALUE.
WARN if reallocated > 0 or pending > 0. CRIT if overall = FAILED.
Return []SMARTResult — one per physical device."
```

**Target output — `dsd health deep` (per-core CPU section):**

```
🖥️  CPU detail… (4 cores)

Core | Usage  | Temp   | Freq      | Throttled | Status
-----|--------|--------|-----------|-----------|-------
0    | 12%    | 45°C   | 2400 MHz  | No        | ✅
1    | 88%    | 78°C   | 2400 MHz  | No        | ⚠️
2    | 7%     | 42°C   | 2400 MHz  | No        | ✅
3    | 91%    | 81°C   | 1800 MHz  | Yes ⚠️    | ⚠️  ← throttled

Average: 49% | Hot cores: 2 | Throttled: 1

— Summary —
Status: ⚠️ WARN  |  Core 3 throttled (1800/2400 MHz) — check cooling
Next:
  → cat /sys/class/thermal/thermal_zone*/temp
  → watch -n1 "cat /sys/devices/system/cpu/cpu3/cpufreq/scaling_cur_freq"
```

**Target output — `dsd services`:**

```
🔌 Service health checks…

Service      | Host      | Port | Protocol | Response | Status
-------------|-----------|------|----------|----------|-------
SSH          | localhost | 22   | tcp      | 2ms      | ✅
HTTP         | localhost | 80   | http     | 8ms      | ✅
HTTPS        | localhost | 443  | https    | 11ms     | ✅
PostgreSQL   | localhost | 5432 | tcp      | 142ms    | ⚠️  ← slow
Redis        | localhost | 6379 | tcp      | 1ms      | ✅
App API      | localhost | 8080 | http     | —        | ❌  ← unreachable

— Summary —
Services: 6 | ✅ 4 | ⚠️ 1 | ❌ 1
Next:
  → systemctl status myapp
  → journalctl -u myapp --since "5 minutes ago"
```

**Target output — disk with SMART:**

```
[Disk & IO]
Mount   | Used  | Total | IO Avg | SMART   | Status
--------|-------|-------|--------|---------|-------
/       | 52%   | 500G  | 0.8ms  | PASSED  | ✅
/home   | 40%   | 1TB   | 5.2ms  | PASSED  | ✅
/var    | 75%   | 250G  | 12ms   | WARN ⚠️  | ⚠️  ← 3 reallocated sectors
```

**Progress bar — locked spec:**

```
[███████████-----] 70% success rate

Implementation: always 16 chars wide between brackets
  filled = int(passed/total * 16) × "█"
  empty  = (16 - filled) × "-"

Examples:
  22/22  [████████████████] 100% success rate
  12/22  [████████--------] 55% success rate
  0/22   [----------------] 0% success rate
```

---

---

### Step 1d: Process Health, Filesystem Integrity, Logs, Security

**`internal/models/process.go` — new:**

```go
package models

type ProcessState struct {
    PID         int     `json:"pid"`
    Name        string  `json:"name"`
    State       string  `json:"state"`   // "Z" = zombie, "D" = hung (uninterruptible)
    PPID        int     `json:"ppid"`
    CPU         float64 `json:"cpu_pct"`
    MemMB       float64 `json:"mem_mb"`
    WChan       string  `json:"wchan"`   // kernel function process is waiting in (D-state only)
    //   read from /proc/<PID>/wchan — world-readable, single word
    //   examples: "io_schedule" (disk wait), "nfs_wait" (NFS stale), "futex_wait" (lock)
}

type ProcessInfo struct {
    ZombieCount   int            `json:"zombie_count"`
    HungCount     int            `json:"hung_count"`   // D-state processes
    ZombieProcs   []ProcessState `json:"zombie_procs"`
    HungProcs     []ProcessState `json:"hung_procs"`
    Status        string         `json:"status"`
    StatusReason  string         `json:"status_reason"`
}
```

**`internal/models/disk.go` — add filesystem health fields:**

```go
// Add to FilesystemInfo:
type FilesystemInfo struct {
    MountPoint       string  `json:"mount_point"`
    Device           string  `json:"device"`
    FSType           string  `json:"fstype"`
    TotalGB          float64 `json:"total_gb"`
    FreeGB           float64 `json:"free_gb"`
    UsedPct          float64 `json:"used_pct"`
    InodesUsedPct    float64 `json:"inodes_used_pct"`
    // Filesystem health fields
    MountHealthy     bool    `json:"mount_healthy"`     // stat() responds within timeout
    FSErrors         int     `json:"fs_errors"`         // ext4/xfs error count (0 = clean)
    ReadOnly         bool    `json:"read_only"`         // remounted ro due to errors
    Status           string  `json:"status"`
    StatusReason     string  `json:"status_reason"`
}
```

**`internal/models/logs.go` — new:**

```go
package models

type LogError struct {
    Count   int    `json:"count"`
    Message string `json:"message"` // top/first occurrence
    Service string `json:"service"` // unit name if from journald
}

type LogsInfo struct {
    ErrorCount    int        `json:"error_count"`    // errors in last hour
    WarnCount     int        `json:"warn_count"`
    TopErrors     []LogError `json:"top_errors"`     // top 3 by count
    Sources       []string   `json:"sources"`        // journals/files checked
    SinceMinutes  int        `json:"since_minutes"`  // look-back window
    JournalSizeGB float64    `json:"journal_size_gb"` // current journal disk usage
    Status        string     `json:"status"`
    StatusReason  string     `json:"status_reason"`
}
```

**`internal/models/security.go` — new:**

```go
package models

type PortEntry struct {
    Port      int    `json:"port"`
    Protocol  string `json:"protocol"` // tcp / udp
    Process   string `json:"process"`
    Whitelisted bool `json:"whitelisted"` // in ~/.dsd.yaml whitelist
}

type SecurityInfo struct {
    FailedSSHLogins24h int         `json:"failed_ssh_logins_24h"`
    ListeningPorts     []PortEntry `json:"listening_ports"`
    UnexpectedPorts    []PortEntry `json:"unexpected_ports"` // not in whitelist
    SSHPasswordAuth    bool        `json:"ssh_password_auth"`  // true = WARN
    SSHPermitRoot      bool        `json:"ssh_permit_root"`    // true = WARN
    SudoNOPASSWD       []string    `json:"sudo_nopasswd"`      // entries found
    WorldWritableEtc   []string    `json:"world_writable_etc"` // files in /etc
    Status             string      `json:"status"`
    StatusReason       string      `json:"status_reason"`
}
```

---

**`internal/collectors/processes.go` — zombie and hung process detection:**

```go
package collectors

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

type ProcessCollector struct{}

func (c *ProcessCollector) Name()    string        { return "Processes" }
func (c *ProcessCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *ProcessCollector) Collect(ctx context.Context) (interface{}, error) {
    entries, err := filepath.Glob("/proc/[0-9]*/stat")
    if err != nil {
        return nil, fmt.Errorf("proc glob: %w", err)
    }

    info := models.ProcessInfo{}

    for _, statPath := range entries {
        data, err := os.ReadFile(statPath)
        if err != nil {
            continue // process may have exited
        }
        ps := parseProcessStat(string(data))

        switch ps.State {
        case "Z":
            info.ZombieCount++
            if len(info.ZombieProcs) < 10 { // cap list
                info.ZombieProcs = append(info.ZombieProcs, ps)
            }
        case "D":
            info.HungCount++
            if len(info.HungProcs) < 10 {
                // Read wchan — the kernel function this process is waiting in.
                // World-readable, single word. Reveals WHY the process is hung:
                //   "io_schedule"      → waiting for disk I/O
                //   "nfs_wait_on_page" → stuck on NFS (stale handle?)
                //   "futex_wait"       → waiting on a userspace lock
                //   "pipe_wait"        → blocked reading a pipe
                ps.WChan = readWChan(pidStr)
                info.HungProcs = append(info.HungProcs, ps)
            }
        }
    }

    switch {
    case info.HungCount > 10:
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf(
            "%d processes in uninterruptible sleep (D) — possible stuck mount or dying disk",
            info.HungCount)
    case info.HungCount > 0:
        info.Status = "WARN"
        // Include wchan of first hung process if available — it identifies the cause immediately
        wchan := ""
        if len(info.HungProcs) > 0 && info.HungProcs[0].WChan != "" {
            wchan = fmt.Sprintf(" (waiting in %s)", info.HungProcs[0].WChan)
        }
        info.StatusReason = fmt.Sprintf(
            "%d process(es) hung on IO (D-state)%s — check mounts and disk health",
            info.HungCount, wchan)
    case info.ZombieCount > 5:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf(
            "%d zombie processes — parent not reaping children",
            info.ZombieCount)
    default:
        info.Status = "OK"
    }

    return info, nil
}

// parseProcessStat parses /proc/<pid>/stat.
// Format: pid (name) state ppid ...
// The name field can contain spaces and is wrapped in parentheses.
func parseProcessStat(raw string) models.ProcessState {
    // Find closing paren — name ends there
    end := strings.LastIndex(raw, ")")
    if end < 0 {
        return models.ProcessState{}
    }
    start := strings.Index(raw, "(")
    if start < 0 || start >= end {
        return models.ProcessState{}
    }

    pidStr := strings.TrimSpace(raw[:start])
    name   := raw[start+1 : end]
    rest   := strings.Fields(raw[end+1:])
    if len(rest) < 2 {
        return models.ProcessState{}
    }

    pid, _ := strconv.Atoi(pidStr)
    ppid, _ := strconv.Atoi(rest[1]) // field 4 (0-indexed: 1 after state)

    return models.ProcessState{
        PID:   pid,
        Name:  name,
        State: rest[0], // field 3
        PPID:  ppid,
    }
}

// readWChan reads /proc/<PID>/wchan — the kernel function the process is
// waiting in. World-readable, single token, no special permissions needed.
// Returns empty string on any error (process may have exited).
func readWChan(pidStr string) string {
    data, err := os.ReadFile("/proc/" + pidStr + "/wchan")
    if err != nil {
        return ""
    }
    wchan := strings.TrimSpace(string(data))
    // "0" means the process is running (not actually stuck), skip it
    if wchan == "0" || wchan == "" {
        return ""
    }
    return wchan
}
```

**`internal/collectors/fshealth.go` — filesystem health (stuck mounts + error flags):**

```go
package collectors

import (
    "context"
    "fmt"
    "os/exec"
    "strings"
    "time"

    "github.com/shirou/gopsutil/v3/disk"
    "github.com/yourusername/dashdiag/internal/models"
)

// checkMountHealth verifies a mount point responds to stat() within timeout.
// A stuck NFS/CIFS mount hangs indefinitely without this timeout.
func checkMountHealth(ctx context.Context, mountPoint string) bool {
    done := make(chan bool, 1)
    go func() {
        _, err := disk.Usage(mountPoint)
        done <- (err == nil)
    }()
    select {
    case ok := <-done:
        return ok
    case <-time.After(3 * time.Second):
        return false // mount is stuck
    }
}

// checkFSErrors reads filesystem error count for ext2/3/4 via tune2fs.
// Returns 0 for non-ext filesystems or if tune2fs not available.
// Requires no special permissions for read.
func checkFSErrors(ctx context.Context, device string) int {
    out, err := exec.CommandContext(ctx, "tune2fs", "-l", device).Output()
    if err != nil {
        return 0
    }
    for _, line := range strings.Split(string(out), "\n") {
        if strings.HasPrefix(line, "FS errors behavior:") {
            // "FS errors behavior: Remount read-only" = errors detected
            if strings.Contains(line, "Remount read-only") {
                return 1 // flag: errors caused RO remount
            }
        }
        if strings.HasPrefix(line, "Mount count:") {
            // Could parse for unusual mount counts
        }
    }
    return 0
}

// checkReadOnly checks if a filesystem is mounted read-only when it should be RW.
// Reads /proc/mounts and checks mount options.
func checkReadOnly(mountPoint string) bool {
    data, _ := os.ReadFile("/proc/mounts")
    for _, line := range strings.Split(string(data), "\n") {
        fields := strings.Fields(line)
        if len(fields) < 4 || fields[1] != mountPoint {
            continue
        }
        opts := strings.Split(fields[3], ",")
        for _, opt := range opts {
            if opt == "ro" {
                return true
            }
        }
    }
    return false
}
```

**`internal/collectors/logs.go` — log error aggregation:**

```go
package collectors

import (
    "context"
    "fmt"
    "os/exec"
    "sort"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

type LogsCollector struct {
    SinceMinutes int // default: 60
}

func (c *LogsCollector) Name()    string        { return "Logs" }
func (c *LogsCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *LogsCollector) Collect(ctx context.Context) (interface{}, error) {
    since := c.SinceMinutes
    if since == 0 {
        since = 60
    }
    sinceArg := fmt.Sprintf("%d minutes ago", since)

    info := models.LogsInfo{
        SinceMinutes: since,
    }

    // Source 1: journald (systemd systems)
    journalErrors := collectJournaldErrors(ctx, sinceArg)
    info.ErrorCount += journalErrors.count
    info.WarnCount  += journalErrors.warnCount
    info.TopErrors   = append(info.TopErrors, journalErrors.top...)
    if journalErrors.available {
        info.Sources = append(info.Sources, "journald")
    }

    // Source 2: /var/log/syslog or /var/log/messages (non-systemd fallback)
    syslogErrors := collectSyslogErrors(ctx, since)
    if syslogErrors.available {
        info.ErrorCount += syslogErrors.count
        info.Sources     = append(info.Sources, syslogErrors.path)
    }

    // Sort top errors by count, keep top 3
    sort.Slice(info.TopErrors, func(i, j int) bool {
        return info.TopErrors[i].Count > info.TopErrors[j].Count
    })
    if len(info.TopErrors) > 3 {
        info.TopErrors = info.TopErrors[:3]
    }

    switch {
    case info.ErrorCount > 100:
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf("%d errors in last %dm", info.ErrorCount, since)
    case info.ErrorCount > 10:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf("%d errors in last %dm", info.ErrorCount, since)
    default:
        info.Status = "OK"
    }

    return info, nil
}

type journaldResult struct {
    available bool
    count     int
    warnCount int
    top       []models.LogError
}

func collectJournaldErrors(ctx context.Context, since string) journaldResult {
    // journalctl -p err --since "60 minutes ago" --no-pager -o short-monotonic
    out, err := exec.CommandContext(ctx,
        "journalctl", "-p", "err", "--since", since,
        "--no-pager", "-o", "cat").Output()
    if err != nil {
        return journaldResult{available: false}
    }

    lines := strings.Split(strings.TrimSpace(string(out)), "\n")
    counts := make(map[string]int)
    services := make(map[string]string)

    for _, line := range lines {
        if line == "" {
            continue
        }
        // Deduplicate by first 60 chars (message prefix)
        key := line
        if len(key) > 60 {
            key = key[:60]
        }
        counts[key]++
    }

    var top []models.LogError
    for msg, count := range counts {
        top = append(top, models.LogError{
            Count:   count,
            Message: msg,
            Service: services[msg],
        })
    }

    return journaldResult{
        available: true,
        count:     len(lines),
        top:       top,
    }
}

type syslogResult struct {
    available bool
    path      string
    count     int
}

func collectSyslogErrors(ctx context.Context, sinceMinutes int) syslogResult {
    // Try /var/log/syslog then /var/log/messages
    for _, path := range []string{"/var/log/syslog", "/var/log/messages"} {
        if _, err := os.Stat(path); err != nil {
            continue
        }
        // Use grep for speed — avoid loading entire file
        cutoff := time.Now().Add(-time.Duration(sinceMinutes) * time.Minute)
        // Simple approach: grep for "error" and "crit" in last N lines
        out, err := exec.CommandContext(ctx,
            "grep", "-ciE", "error|crit|fail", path).Output()
        if err != nil {
            continue
        }
        count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
        _ = cutoff
        return syslogResult{available: true, path: path, count: count}
    }
    return syslogResult{available: false}
}
```

**`internal/collectors/security.go` — security posture (read-only, configuration checks):**

```go
package collectors

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

// SecurityCollector checks security CONFIGURATION posture only.
// It never scans, probes, or modifies anything.
// It reads config files and logs that are world-readable where possible.
type SecurityCollector struct{}

func (c *SecurityCollector) Name()    string        { return "Security" }
func (c *SecurityCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *SecurityCollector) Collect(ctx context.Context) (interface{}, error) {
    info := models.SecurityInfo{}

    // 1. Failed SSH logins (last 24h)
    info.FailedSSHLogins24h = countFailedSSH(ctx)

    // 2. Listening ports via ss
    info.ListeningPorts, info.UnexpectedPorts = checkListeningPorts(ctx)

    // 3. SSH configuration
    info.SSHPasswordAuth, info.SSHPermitRoot = checkSSHConfig()

    // 4. Sudo NOPASSWD entries
    info.SudoNOPASSWD = checkSudoNOPASSWD()

    // 5. World-writable files in /etc (limited depth)
    info.WorldWritableEtc = checkWorldWritableEtc(ctx)

    // Aggregate status
    issues := 0
    if info.SSHPermitRoot         { issues++ }
    if info.SSHPasswordAuth       { issues++ }
    if len(info.SudoNOPASSWD) > 0 { issues++ }
    if len(info.UnexpectedPorts) > 0 { issues++ }
    if info.FailedSSHLogins24h > 50  { issues++ }
    if len(info.WorldWritableEtc) > 0 { issues++ }

    switch {
    case issues >= 3:
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf("%d security configuration issues found", issues)
    case issues > 0:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf("%d security configuration issue(s) found", issues)
    default:
        info.Status = "OK"
    }

    return info, nil
}

func countFailedSSH(ctx context.Context) int {
    // Try journald first
    out, err := exec.CommandContext(ctx,
        "journalctl", "-u", "ssh", "-u", "sshd",
        "--since", "24 hours ago",
        "--no-pager", "-o", "cat").Output()
    if err == nil {
        count := 0
        for _, line := range strings.Split(string(out), "\n") {
            if strings.Contains(line, "Failed password") ||
               strings.Contains(line, "Invalid user") {
                count++
            }
        }
        return count
    }
    // Fallback: grep auth.log
    out, err = exec.CommandContext(ctx,
        "grep", "-c", "Failed password",
        "/var/log/auth.log").Output()
    if err != nil {
        return 0
    }
    n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
    return n
}

func checkListeningPorts(ctx context.Context) (all, unexpected []models.PortEntry) {
    out, err := exec.CommandContext(ctx, "ss", "-tuln").Output()
    if err != nil {
        return nil, nil
    }
    // Load whitelist from viper config key "security.allowed_ports"
    whitelist := loadPortWhitelist()

    for _, line := range strings.Split(string(out), "\n")[1:] {
        fields := strings.Fields(line)
        if len(fields) < 5 {
            continue
        }
        addr := fields[4] // e.g., "0.0.0.0:22" or "*:80"
        parts := strings.Split(addr, ":")
        if len(parts) < 2 {
            continue
        }
        port, err := strconv.Atoi(parts[len(parts)-1])
        if err != nil {
            continue
        }
        proto := strings.ToLower(fields[0]) // tcp/udp
        entry := models.PortEntry{Port: port, Protocol: proto}
        entry.Whitelisted = whitelist[port]
        all = append(all, entry)
        if !entry.Whitelisted && port > 1024 {
            // Only flag non-standard ports not in whitelist
            unexpected = append(unexpected, entry)
        }
    }
    return
}

func checkSSHConfig() (passwordAuth, permitRoot bool) {
    data, err := os.ReadFile("/etc/ssh/sshd_config")
    if err != nil {
        return false, false
    }
    scanner := bufio.NewScanner(strings.NewReader(string(data)))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "#") {
            continue
        }
        switch {
        case strings.HasPrefix(strings.ToLower(line), "passwordauthentication yes"):
            passwordAuth = true
        case strings.HasPrefix(strings.ToLower(line), "permitrootlogin yes"):
            permitRoot = true
        }
    }
    return
}

func checkSudoNOPASSWD() []string {
    var entries []string
    paths, _ := filepath.Glob("/etc/sudoers.d/*")
    paths = append([]string{"/etc/sudoers"}, paths...)
    for _, p := range paths {
        data, err := os.ReadFile(p)
        if err != nil {
            continue
        }
        for _, line := range strings.Split(string(data), "\n") {
            if strings.Contains(line, "NOPASSWD") &&
               !strings.HasPrefix(strings.TrimSpace(line), "#") {
                entries = append(entries, strings.TrimSpace(line))
            }
        }
    }
    return entries
}

func checkWorldWritableEtc(ctx context.Context) []string {
    out, err := exec.CommandContext(ctx,
        "find", "/etc", "-maxdepth", "2",
        "-perm", "-o+w",
        "-not", "-type", "l").Output() // skip symlinks
    if err != nil {
        return nil
    }
    var files []string
    for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
        if f != "" {
            files = append(files, f)
        }
    }
    return files
}

func loadPortWhitelist() map[int]bool {
    // Load from viper: security.allowed_ports: [22, 80, 443, 5432]
    // Default well-known ports always allowed
    defaults := []int{22, 80, 443, 8080, 8443}
    whitelist := make(map[int]bool)
    for _, p := range defaults {
        whitelist[p] = true
    }
    // TODO: merge with viper.GetIntSlice("security.allowed_ports")
    return whitelist
}
```

**AI prompts:**

```
Prompt — processes.go:
"Write internal/collectors/processes.go with ProcessCollector.
Timeout: 2 seconds.
Glob /proc/[0-9]*/stat and parse each file.
The stat format: 'pid (name) state ppid ...'
Name is inside parentheses and may contain spaces — find last ')' to parse correctly.
Count state='Z' (zombie) and state='D' (uninterruptible/hung) processes.
Store up to 10 examples of each type in []ProcessState.
For D-state processes: also read /proc/<PID>/wchan and store in ProcessState.WChan.
  wchan is world-readable, returns single kernel function name (e.g. 'io_schedule').
  If wchan == '0' or empty, leave WChan blank.
Include wchan in StatusReason for first hung process: 'mysqld (PID 123) waiting in io_schedule'.
Thresholds:
  Hung CRIT > 10, WARN > 0
  Zombie WARN > 5
Return models.ProcessInfo{ZombieCount, HungCount, ZombieProcs, HungProcs, Status}."

Prompt — fdlimits.go (extended):
"Extend internal/collectors/fdlimits.go with three checks:

1. System-wide (existing): /proc/sys/fs/file-nr
   WARN > 80%, CRIT > 90%

2. Per-process saturation: scan /proc/[0-9]*/limits for 'Max open files' soft limit.
   For each, count entries in /proc/<PID>/fd/.
   Flag any process where open count > 80% of soft limit.
   Sort by saturation %, keep top 5. Store in FDInfo.HotProcesses.
   WARN for any at 80%+, CRIT for any at 90%+.

3. Deleted-but-open files: iterate /proc/[0-9]*/fd/*, readlink each.
   If readlink target contains '(deleted)', increment count.
   For targets still in filesystem: check syscall.Stat_t.Nlink == 0 (deleted inode).
   Sum file sizes. Store in FDInfo.DeletedOpenFiles and FDInfo.DeletedOpenSizeGB.
   WARN if DeletedOpenSizeGB > 1.0.

Use filepath.Glob and os.ReadDir — never exec lsof (too slow, requires binary).
All errors are best-effort — a process exiting mid-scan must not crash the collector."
```

```
Prompt — logs.go:
"Write internal/collectors/logs.go with LogsCollector.
Timeout: 8 seconds. Default look-back: 60 minutes.
Source 1: exec 'journalctl -p err --since \"60 minutes ago\" --no-pager -o cat'
  Count output lines as error count.
  Deduplicate by first 60 chars of message, count occurrences.
  Return top 3 most frequent errors as []LogError{Count, Message, Service}.
  If journalctl not found: mark source unavailable.
Source 2: grep -ciE 'error|crit|fail' /var/log/syslog (fallback to /var/log/messages)
  Add count to total. Mark path in Sources[].
Thresholds: WARN > 10 errors, CRIT > 100 errors in window.
Return models.LogsInfo{ErrorCount, WarnCount, TopErrors, Sources, SinceMinutes, Status}."
```

```
Prompt — security.go:
"Write internal/collectors/security.go with SecurityCollector.
This is READ-ONLY configuration posture. Never scan, probe, or modify.
Timeout: 10 seconds. Run all sub-checks concurrently.

1. Failed SSH logins 24h: journalctl -u sshd --since '24 hours ago'
   Count lines with 'Failed password' or 'Invalid user'.
   Fallback: grep -c 'Failed password' /var/log/auth.log

2. Listening ports: ss -tuln, parse port numbers.
   Load whitelist from viper key 'security.allowed_ports' (default: 22,80,443,8080,8443).
   Flag ports > 1024 not in whitelist as UnexpectedPorts.

3. SSH config: read /etc/ssh/sshd_config.
   WARN if PasswordAuthentication yes.
   WARN if PermitRootLogin yes.

4. Sudo NOPASSWD: read /etc/sudoers and /etc/sudoers.d/*.
   Return any line containing NOPASSWD (skip comments).

5. World-writable /etc: find /etc -maxdepth 2 -perm -o+w -not -type l
   Return list of paths.

Status: CRIT if 3+ issues, WARN if 1+ issues, OK if clean.
Permission errors on any check → return INFO result, not WARN/CRIT."
```

**Target output — `dsd health` with process issues:**

```
[Processes]
⚠️  Zombie processes: 8   (nginx×3, worker×5)
❌  Hung processes: 3     (mysqld×2, nfsd×1) ← blocked on IO (waiting in nfs_wait_on_page)
   → cat /proc/<PID>/wchan   (confirm kernel wait function)
   → ps aux | grep ' [DZ] '
   → dmesg | tail -20        (check for IO / NFS errors)

[File Descriptors]
⚠️  nginx (PID 4821): 982/1024 FDs (96%) ← approaching limit
   → lsof -p 4821 | wc -l
   → cat /proc/4821/limits | grep 'open files'
⚠️  2 deleted file(s) holding 3.1GB ← ghost space (df≠du)
   → lsof +L1
```

**Target output — `dsd logs`:**

```
📋 Log analysis… (last 60 minutes, 2 sources)

Source: journald  →  47 errors
Source: /var/log/syslog  →  12 errors

Top errors:
  23×  kernel: EXT4-fs error (device sdb): ext4_find_entry
   8×  mysqld: Table './app/sessions' is marked as crashed
   5×  sshd: Failed password for root from 185.23.44.1

— Summary —
Total errors: 59 | Status: ⚠️ WARN
Next: → journalctl -p err --since "1 hour ago" | less
```

**Target output — `dsd security`:**

```
🔒 Security posture… (read-only configuration checks)

[SSH Config]
✅ PasswordAuthentication: No
❌ PermitRootLogin: Yes  ← WARN

[Listening Ports]
✅ 22 (SSH), 80 (HTTP), 443 (HTTPS), 5432 (PostgreSQL)
⚠️  8888 (unexpected — not in whitelist)

[Auth]
⚠️  Failed SSH logins (24h): 147  ← brute force pattern

[Sudo]
✅ No NOPASSWD entries

[/etc Permissions]
✅ No world-writable files in /etc

— Summary —
Issues: 3 | Status: ⚠️ WARN
Not in scope: port scanning, CVE checking, vulnerability assessment
Next:
  → grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
  → namei -l /path/to/file   (trace full permission chain if "permission denied" reported)
  → ausearch -m avc -ts recent  (if SELinux active)
```

---

### Scope Boundary Table — What DashDiag Is Not

| Tool / Category | Why out of scope | Recommendation |
|---|---|---|
| `perf` / eBPF profiling | Time-sampled, interactive, requires kernel headers or root; not a snapshot | `perf stat -a sleep 5` or `bcc-tools/execsnoop` |
| Vulnerability/CVE scanning | Separate security toolchain; slow, network-dependent | Use `trivy`, `grype`, or `osv-scanner` |
| `nmap` port scanning | Active probing; changes system state (SYN packets); may trigger IDS | Use `nmap -sV localhost` for local checks |
| `fsck` repair | DashDiag is read-only; fsck modifies filesystem metadata | `fsck -n /dev/<device>` for dry-run check |
| Package update checking | Slow, network call, not a health check | `apt list --upgradable` or `dnf check-update` |
| Firewall rule management | `iptables -A` / `ufw allow` — modifies state | `iptables -L -n -v` to view only |
| Application-level tracing | APM domain (Datadog, Jaeger, OpenTelemetry) | Not a CLI diagnostic; use APM tools |
| Active network scanning | `arpscan`, `masscan` — active probing | Use dedicated network scanner |

**Rule:** if the check requires more than reading files or making a single TCP connect/HTTP GET, it does not belong in DashDiag. DashDiag observes; it never probes or modifies.

---

---

### Step 1e: Systemd Units, Sysctl, SELinux/AppArmor, Memory Slab, Journal Size

**`internal/models/systemd.go`:**

```go
package models

type SystemdInfo struct {
    Available    bool     `json:"available"`     // false on non-systemd systems
    FailedUnits  []string `json:"failed_units"`  // units in state=failed
    StuckUnits   []string `json:"stuck_units"`   // units stuck in state=activating
    Status       string   `json:"status"`
    StatusReason string   `json:"status_reason"`
}
```

**`internal/models/sysctl.go`:**

```go
package models

type SysctlInfo struct {
    VMSwappiness int    `json:"vm_swappiness"`
    NetSomaxconn int    `json:"net_core_somaxconn"`
    FSFileMax    int    `json:"fs_file_max"`
    KernelPIDMax int    `json:"kernel_pid_max"`
    PIDCount     int    `json:"pid_count"`       // current live process count
    Status       string `json:"status"`
    StatusReason string `json:"status_reason"`
}
```

**`internal/models/kernel_security.go`:**

```go
package models

type KernelSecurityInfo struct {
    SELinuxPresent  bool   `json:"selinux_present"`
    SELinuxMode     string `json:"selinux_mode"`    // "enforcing" / "permissive" / "disabled"
    SELinuxDenials  int    `json:"selinux_denials"` // AVC denials in last hour
    AppArmorPresent bool   `json:"apparmor_present"`
    AppArmorMode    string `json:"apparmor_mode"`   // "enforce" / "complain" / "disabled"
    Status          string `json:"status"`
    StatusReason    string `json:"status_reason"`
}
```

---

**`internal/collectors/systemd.go` — failed and stuck unit detection:**

```go
package collectors

import (
    "context"
    "fmt"
    "os/exec"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

type SystemdCollector struct{}

func (c *SystemdCollector) Name()    string        { return "Systemd" }
func (c *SystemdCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *SystemdCollector) Collect(ctx context.Context) (interface{}, error) {
    out, err := exec.CommandContext(ctx,
        "systemctl", "list-units",
        "--state=failed,activating",
        "--no-legend", "--no-pager", "--plain").Output()
    if err != nil {
        // systemd not present (Alpine, some containers) — not an error
        return models.SystemdInfo{Available: false, Status: "INFO"}, nil
    }

    var failed, activating []string
    for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
        if line == "" {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) < 4 {
            continue
        }
        unit      := fields[0]
        subState  := fields[3] // e.g. "failed" or "start" (activating substate)
        loadState := fields[1] // "loaded"
        _ = loadState

        switch {
        case subState == "failed":
            failed = append(failed, unit)
        case fields[2] == "activating": // ActiveState
            activating = append(activating, unit)
        }
    }

    info := models.SystemdInfo{Available: true}
    info.FailedUnits = failed
    info.StuckUnits  = activating

    switch {
    case len(failed) > 0:
        preview := failed
        if len(preview) > 3 { preview = preview[:3] }
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf("%d failed unit(s): %s",
            len(failed), strings.Join(preview, ", "))
        if len(failed) > 3 {
            info.StatusReason += fmt.Sprintf(" (+%d more)", len(failed)-3)
        }
    case len(activating) > 0:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf(
            "%d unit(s) stuck in activating: %s",
            len(activating), strings.Join(activating, ", "))
    default:
        info.Status = "OK"
    }

    return info, nil
}
```

**`internal/collectors/sysctl.go` — key kernel parameter checks:**

```go
package collectors

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

type SysctlCollector struct{}

func (c *SysctlCollector) Name()    string        { return "Kernel Parameters" }
func (c *SysctlCollector) Timeout() time.Duration { return 1 * time.Second }

// All reads from /proc/sys/ — no exec calls, no permissions needed.
func (c *SysctlCollector) Collect(ctx context.Context) (interface{}, error) {
    info := models.SysctlInfo{
        VMSwappiness: readSysctlInt("vm/swappiness"),
        NetSomaxconn: readSysctlInt("net/core/somaxconn"),
        FSFileMax:    readSysctlInt("fs/file-max"),
        KernelPIDMax: readSysctlInt("kernel/pid_max"),
    }

    // Count live processes from /proc
    entries, _ := filepath.Glob("/proc/[0-9]*")
    info.PIDCount = len(entries)

    var issues []string

    // net.core.somaxconn: low value silently drops connections under load
    if info.NetSomaxconn > 0 && info.NetSomaxconn < 1024 {
        issues = append(issues, fmt.Sprintf(
            "net.core.somaxconn=%d — low, connections may be dropped under load "+
                "(recommended ≥ 1024)", info.NetSomaxconn))
    }

    // PID exhaustion: fork() fails when pid_max is reached
    if info.KernelPIDMax > 0 {
        pidUsedPct := float64(info.PIDCount) / float64(info.KernelPIDMax) * 100
        if pidUsedPct > 90 {
            issues = append(issues, fmt.Sprintf(
                "PID exhaustion: %d/%d (%.0f%%) — fork() will start failing",
                info.PIDCount, info.KernelPIDMax, pidUsedPct))
        } else if pidUsedPct > 70 {
            issues = append(issues, fmt.Sprintf(
                "PID count elevated: %d/%d (%.0f%%)",
                info.PIDCount, info.KernelPIDMax, pidUsedPct))
        }
    }

    if len(issues) > 0 {
        info.Status = "WARN"
        info.StatusReason = strings.Join(issues, "; ")
    } else {
        info.Status = "OK"
    }

    return info, nil
}

// readSysctlInt reads a kernel parameter from /proc/sys/.
// key uses "/" not "." — e.g. "vm/swappiness" → /proc/sys/vm/swappiness
func readSysctlInt(key string) int {
    data, err := os.ReadFile("/proc/sys/" + key)
    if err != nil {
        return 0
    }
    v, _ := strconv.Atoi(strings.TrimSpace(string(data)))
    return v
}
```

**`internal/collectors/kernel_security.go` — SELinux and AppArmor status:**

```go
package collectors

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)

type KernelSecurityCollector struct{}

func (c *KernelSecurityCollector) Name()    string        { return "KernelSecurity" }
func (c *KernelSecurityCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *KernelSecurityCollector) Collect(ctx context.Context) (interface{}, error) {
    info := models.KernelSecurityInfo{}

    // ── SELinux ──────────────────────────────────────────────────────────────
    if out, err := exec.CommandContext(ctx, "getenforce").Output(); err == nil {
        info.SELinuxPresent = true
        info.SELinuxMode = strings.TrimSpace(strings.ToLower(string(out)))
    }

    // Count AVC denials in last hour — only useful when enforcing
    if info.SELinuxPresent && info.SELinuxMode == "enforcing" {
        out, err := exec.CommandContext(ctx,
            "journalctl", "-k", "--since", "1 hour ago",
            "--no-pager", "-o", "cat",
            "--grep", "avc:.*denied").Output()
        if err == nil {
            text := strings.TrimSpace(string(out))
            if text != "" {
                info.SELinuxDenials = len(strings.Split(text, "\n"))
            }
        }
    }

    // ── AppArmor ─────────────────────────────────────────────────────────────
    // /sys/module/apparmor exists when the module is loaded
    if _, err := os.Stat("/sys/module/apparmor"); err == nil {
        info.AppArmorPresent = true
        if data, err := os.ReadFile("/sys/module/apparmor/parameters/mode"); err == nil {
            info.AppArmorMode = strings.TrimSpace(string(data))
        } else {
            info.AppArmorMode = "enabled" // loaded but mode not readable
        }
    }

    // ── Status ───────────────────────────────────────────────────────────────
    switch {
    case info.SELinuxDenials > 10:
        info.Status = "CRIT"
        info.StatusReason = fmt.Sprintf(
            "SELinux: %d AVC denials in last hour — run: ausearch -m avc -ts recent",
            info.SELinuxDenials)
    case info.SELinuxDenials > 0:
        info.Status = "WARN"
        info.StatusReason = fmt.Sprintf(
            "SELinux: %d AVC denial(s) in last hour — run: ausearch -m avc -ts recent",
            info.SELinuxDenials)
    default:
        info.Status = "OK"
    }

    return info, nil
}
```

**Memory collector — add Slab and CommitLimit reading from `/proc/meminfo`:**

```go
// Add to MemoryCollector.Collect() after reading VirtualMemory:

// Read extended fields from /proc/meminfo
// These are not exposed by gopsutil and must be read directly
extFields := readMemInfoFields([]string{
    "Slab",
    "CommitLimit",
    "Committed_AS",
})
slabKB        := extFields["Slab"]
commitLimitKB := extFields["CommitLimit"]
committedAsKB := extFields["Committed_AS"]

info.SlabMB        = float64(slabKB) / 1024
info.CommitLimitMB = float64(commitLimitKB) / 1024
info.CommittedAsMB = float64(committedAsKB) / 1024
if commitLimitKB > 0 {
    info.OverCommitted = committedAsKB > commitLimitKB
}

// Add to analysis layer thresholds:
totalMB := info.TotalGB * 1024
if info.SlabMB > totalMB*0.20 {
    // Slab > 20% of RAM — likely inode/dentry cache leak or many small files
    info.Status = "WARN"
    info.StatusReason = fmt.Sprintf(
        "kernel slab cache %.0fMB (%.0f%% of RAM) — possible inode/dentry leak",
        info.SlabMB, info.SlabMB/totalMB*100)
}
if info.OverCommitted {
    info.Status = "WARN"
    info.StatusReason = fmt.Sprintf(
        "memory overcommitted: %.0fMB committed / %.0fMB limit — OOM risk",
        info.CommittedAsMB, info.CommitLimitMB)
}

// readMemInfoFields parses selected fields from /proc/meminfo.
// Returns map of field name → value in kB.
func readMemInfoFields(fields []string) map[string]uint64 {
    want := make(map[string]bool, len(fields))
    for _, f := range fields { want[f] = true }
    result := make(map[string]uint64, len(fields))

    data, err := os.ReadFile("/proc/meminfo")
    if err != nil { return result }

    for _, line := range strings.Split(string(data), "\n") {
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 { continue }
        key := strings.TrimSpace(parts[0])
        if !want[key] { continue }
        valStr := strings.Fields(strings.TrimSpace(parts[1]))
        if len(valStr) == 0 { continue }
        v, _ := strconv.ParseUint(valStr[0], 10, 64)
        result[key] = v
    }
    return result
}
```

**Logs collector — add journal size check:**

```go
// Add to LogsCollector.Collect() before the status decision:

// Journal disk usage
info.JournalSizeGB = readJournalSize(ctx)

// Add to status decision:
if info.JournalSizeGB > 2.0 && info.Status == "OK" {
    info.Status = "WARN"
    info.StatusReason = fmt.Sprintf(
        "journal disk usage %.1fGB — consider: journalctl --vacuum-size=500M",
        info.JournalSizeGB)
}

// readJournalSize runs 'journalctl --disk-usage' and parses the size.
func readJournalSize(ctx context.Context) float64 {
    out, err := exec.CommandContext(ctx,
        "journalctl", "--disk-usage").Output()
    if err != nil { return 0 }
    // Output: "Archived and active journals take up 1.2G in the filesystem."
    text := string(out)
    for _, line := range strings.Split(text, "\n") {
        if !strings.Contains(line, "take up") { continue }
        fields := strings.Fields(line)
        for i, f := range fields {
            if f == "up" && i+1 < len(fields) {
                sizeStr := fields[i+1]
                return parseSizeToGB(sizeStr)
            }
        }
    }
    return 0
}

// parseSizeToGB converts "1.2G", "450M", "3.1G" → float64 GB
func parseSizeToGB(s string) float64 {
    s = strings.TrimRight(s, ".")
    if len(s) == 0 { return 0 }
    suffix := s[len(s)-1]
    num, err := strconv.ParseFloat(s[:len(s)-1], 64)
    if err != nil { return 0 }
    switch suffix {
    case 'G': return num
    case 'M': return num / 1024
    case 'K': return num / 1024 / 1024
    }
    return 0
}
```

---

**AI prompts for new collectors:**

```
Prompt — systemd.go:
"Write internal/collectors/systemd.go with SystemdCollector.
Timeout: 3 seconds.
Run: systemctl list-units --state=failed,activating --no-legend --no-pager --plain
Parse each line: unit name (field 0), load state (field 1), active state (field 2), sub state (field 3).
Collect failed units (substate=failed) and stuck units (activestate=activating).
If systemctl not found or exits non-zero → return SystemdInfo{Available: false, Status: INFO}.
Thresholds: CRIT if any failed units; WARN if any stuck/activating units.
Show at most 3 unit names in StatusReason, append '(+N more)' if truncated."
```

```
Prompt — sysctl.go:
"Write internal/collectors/sysctl.go with SysctlCollector.
Timeout: 1 second. No exec calls — read only from /proc/sys/.
Read:
  vm/swappiness      → VMSwappiness
  net/core/somaxconn → NetSomaxconn
  fs/file-max        → FSFileMax
  kernel/pid_max     → KernelPIDMax
Count PIDCount via len(filepath.Glob('/proc/[0-9]*')).
Thresholds:
  NetSomaxconn < 512:  WARN (connections dropped under load)
  NetSomaxconn < 1024: WARN (recommended ≥ 1024)
  PIDCount > 90% of pid_max: CRIT
  PIDCount > 70% of pid_max: WARN
Return models.SysctlInfo. No errors — missing files return 0."
```

```
Prompt — kernel_security.go:
"Write internal/collectors/kernel_security.go with KernelSecurityCollector.
Timeout: 5 seconds.
SELinux:
  1. exec 'getenforce' → SELinuxMode (enforcing/permissive/disabled)
     If not found: SELinuxPresent=false
  2. If enforcing: exec 'journalctl -k --since \"1 hour ago\" --no-pager -o cat --grep avc:.*denied'
     Count non-empty output lines as SELinuxDenials
AppArmor:
  1. os.Stat('/sys/module/apparmor') → AppArmorPresent
  2. Read /sys/module/apparmor/parameters/mode → AppArmorMode
Thresholds:
  SELinuxDenials > 10: CRIT with ausearch hint
  SELinuxDenials > 0:  WARN with ausearch hint
  No MAC framework detected: OK (many systems have neither)
All exec calls use exec.CommandContext. Permission errors → INFO."
```

```
Prompt — memory slab and overcommit (add to memory collector):
"Extend internal/collectors/memory.go to read Slab, CommitLimit, CommittedAS from /proc/meminfo.
Add readMemInfoFields(fields []string) map[string]uint64 helper.
It parses /proc/meminfo line by line, splits on ':', trims whitespace, returns kB values.
Add to MemoryInfo: SlabMB float64, CommitLimitMB float64, CommittedAsMB float64, OverCommitted bool.
Add to analysis thresholds in analysis/thresholds.go:
  WARN if SlabMB > totalMB * 0.20 (kernel cache possibly leaking)
  WARN if OverCommitted = true (CommittedAS > CommitLimit, OOM possible despite free RAM)"
```

```
Prompt — journal size (add to logs collector):
"Extend internal/collectors/logs.go to check journal disk usage.
Add to LogsInfo: JournalSizeGB float64.
After collecting errors, run: journalctl --disk-usage
Parse the output line containing 'take up' — extract the size token after 'up'.
Implement parseSizeToGB(s string) float64 that handles G/M/K suffixes.
Add to status decision: WARN if JournalSizeGB > 2.0, CRIT if > 5.0.
Hint message: 'journalctl --vacuum-size=500M' or '--vacuum-time=4weeks'."
```

**Target output — `dsd health` with systemd, sysctl, and SELinux issues:**

```
[Systemd]
❌ Failed units: 2  (nginx.service, redis.service)
   → systemctl status nginx.service
   → journalctl -u nginx.service -n 50 -xe

[Kernel Parameters]
⚠️  net.core.somaxconn=128 — low, connections may be dropped under load
   → sysctl -w net.core.somaxconn=4096
   → echo 'net.core.somaxconn=4096' >> /etc/sysctl.d/99-dsd.conf

[KernelSecurity]
⚠️  SELinux enforcing: 23 AVC denials in last hour
   → ausearch -m avc -ts recent
   → sealert -l "*" (if setroubleshoot installed)

[Memory]
⚠️  Slab cache: 3.2GB (20% of RAM) — possible inode/dentry leak
   → echo 3 > /proc/sys/vm/drop_caches  (temporary relief only)
   → slabtop  (identify which cache is growing)

[Logs]
⚠️  Journal disk usage: 4.8GB
   → journalctl --vacuum-size=500M
```

---

---

### Step 2: `dsd net` — Full Network Diagnostics Module

`dsd net` is the deep-diagnostic command. It runs when something is wrong or when you need quality data before a deployment. It has four layers: interface health, latency + quality, DNS, and conditional traceroute.

**Architecture — what runs when:**

```
dsd quick  →  network_quick.go  →  3 pings each, 5s timeout, pass/fail only
dsd net    →  network_deep.go   →  20 pings, jitter, DNS timing,
                                   conditional traceroute, interface errors
```

Traceroute **never runs automatically** on a healthy connection. The trigger:
```go
if !internetReachable || avgRTT > 200*time.Millisecond || packetLoss > 5.0 {
    runTraceroute(gateway, "8.8.8.8")
}
```

**Data models — `internal/models/network.go`:**

```go
package models

import "time"

type PingStats struct {
    Host       string
    Reachable  bool
    SentCount  int
    RecvCount  int
    PacketLoss float64       // percentage 0-100
    MinRTT     time.Duration
    MaxRTT     time.Duration
    AvgRTT     time.Duration
    Jitter     time.Duration // stddev of RTT samples
    Samples    []time.Duration
}

type TracerouteHop struct {
    Number  int
    IP      string
    RTT     time.Duration
    Host    string
    Timeout bool
}

type InterfaceHealth struct {
    Name      string
    State     string  // UP / DOWN
    IPv4      string
    IPv6      string
    Errors    uint64  // RX + TX errors
    Drops     uint64  // RX + TX drops
    IsVirtual bool
}

type DNSResult struct {
    Server    string
    Reachable bool
    LatencyMS int64
    Resolved  string // resolved IP for test hostname
}

// ConnectionStates holds TCP connection state counts.
// High TIME_WAIT = connection churn; high CLOSE_WAIT = likely application bug.
type ConnectionStates struct {
    TimeWait     int
    CloseWait    int
    Established  int
    Listen       int
    Status       string
    StatusReason string
}

// BondInfo holds bonded interface (bond0, bond1) health.
// Parsed from /proc/net/bonding/<interface>.
type BondInfo struct {
    Name         string
    Mode         string     // "active-backup", "802.3ad", "balance-rr", etc.
    TotalSlaves  int
    UpSlaves     int
    ActiveSlave  string
    Slaves       []BondSlave
    Status       string
    StatusReason string
}

type BondSlave struct {
    Name   string
    State  string // "up" / "down"
    Speed  int    // Mbps
    Active bool
}

// LinkInfo holds physical link quality from ethtool + wireless detection.
// Only populated for physical non-virtual interfaces.
type LinkInfo struct {
    Interface    string
    SpeedMbps    int    // 0 = unknown (ethtool unavailable or no CAP_NET_ADMIN)
    Duplex       string // "Full" / "Half" / "Unknown"
    IsWireless   bool
    SignaldBm    int    // 0 if wired or signal unavailable
    Status       string
    StatusReason string
}

// NATInfo describes whether the system sits behind NAT.
// Detected when public IP != any interface IP.
type NATInfo struct {
    Detected   bool
    InternalIP string
    PublicIP   string
}

type DeepNetworkInfo struct {
    Interfaces        []InterfaceHealth
    PingResults       map[string]*PingStats
    DNS               []DNSResult
    Connections       ConnectionStates
    Bonds             []BondInfo       // nil if no bonded interfaces
    Links             []LinkInfo       // speed/duplex per physical interface
    NAT               NATInfo
    PublicIP          string
    Gateway           string
    DefaultRouteExist bool
    Traceroute        []TracerouteHop  // nil if not triggered
    TracerouteTo      string
}
```

**Jitter calculation — `internal/analysis/jitter.go`:**

```go
package analysis

import (
    "math"
    "time"
)

// Jitter returns the standard deviation of RTT samples.
func Jitter(samples []time.Duration) time.Duration {
    if len(samples) < 2 {
        return 0
    }
    var sum float64
    for _, s := range samples {
        sum += float64(s)
    }
    mean := sum / float64(len(samples))
    var variance float64
    for _, s := range samples {
        diff := float64(s) - mean
        variance += diff * diff
    }
    variance /= float64(len(samples) - 1)
    return time.Duration(math.Sqrt(variance))
}

type JitterRating string
const (
    RatingExcellent JitterRating = "Excellent"
    RatingGood      JitterRating = "Good"
    RatingHigh      JitterRating = "High"     // WARN
    RatingCritical  JitterRating = "Critical" // CRIT
)

func GatewayJitterLevel(j time.Duration) JitterRating {
    switch {
    case j < 5*time.Millisecond:  return RatingExcellent
    case j < 20*time.Millisecond: return RatingGood
    case j < 50*time.Millisecond: return RatingHigh
    default:                       return RatingCritical
    }
}

func InternetJitterLevel(j time.Duration) JitterRating {
    switch {
    case j < 10*time.Millisecond: return RatingExcellent
    case j < 30*time.Millisecond: return RatingGood
    case j < 60*time.Millisecond: return RatingHigh
    default:                       return RatingCritical
    }
}
```

**Deep ping with individual sample collection:**

```go
// Collect individual RTT samples for proper jitter calculation.
// go-ping Statistics() only gives min/max/avg — we need per-packet RTTs.
func pingWithSamples(host string, count int, timeout time.Duration) (*models.PingStats, error) {
    pinger, err := ping.NewPinger(host)
    if err != nil {
        return nil, err
    }
    var samples []time.Duration
    pinger.Count   = count
    pinger.Timeout = timeout
    pinger.OnRecv = func(pkt *ping.Packet) {
        samples = append(samples, pkt.Rtt)
    }
    if err := pinger.Run(); err != nil {
        return nil, err
    }
    stats := pinger.Statistics()
    return &models.PingStats{
        Host:       host,
        Reachable:  stats.PacketsRecv > 0,
        SentCount:  stats.PacketsSent,
        RecvCount:  stats.PacketsRecv,
        PacketLoss: stats.PacketLoss,
        MinRTT:     stats.MinRtt,
        MaxRTT:     stats.MaxRtt,
        AvgRTT:     stats.AvgRtt,
        Jitter:     analysis.Jitter(samples),
        Samples:    samples,
    }, nil
}
```

**Complete deep network collector prompt:**

```
Prompt:
"Write internal/collectors/network_deep.go implementing DeepNetworkCollector.

Collect concurrently with sync.WaitGroup — all groups run simultaneously:

GROUP A — Connectivity (run concurrently):
1. Interface health via gopsutil/v3/net IOCounters(true):
   - Skip: loopback, docker0, virbr*, veth*, br-* interfaces
   - Flag WARN if Errin+Errout > 0 or Dropin+Dropout > 0

2. Deep ping to: default gateway, 1.1.1.1, 8.8.8.8
   - 20 samples each via go-ping OnRecv callback (collect individual RTTs)
   - Jitter = stddev via analysis.Jitter()
   - Thresholds:
     Gateway:  jitter WARN > 20ms CRIT > 50ms; loss WARN > 1% CRIT > 5%
     Internet: jitter WARN > 30ms CRIT > 60ms; loss WARN > 2% CRIT > 10%

3. DNS check via gns:
   - Time resolution of 'google.com' against each configured DNS server
   - WARN if any server latency > 100ms; CRIT if all DNS servers fail

4. TCP connection states via gopsutil/v3/net Connections('tcp'):
   - Count TIME_WAIT, CLOSE_WAIT, ESTABLISHED, LISTEN states
   - Thresholds: TIME_WAIT WARN > 500 CRIT > 2000
   - Thresholds: CLOSE_WAIT WARN > 10 CRIT > 100 (likely application bug)

GROUP B — Physical layer (run concurrently, best-effort):
5. Interface bonding — scan /proc/net/bonding/* for each bond* interface:
   - Parse: bonding mode, slave list, slave states, active slave
   - WARN if any slave is DOWN; CRIT if all slaves are DOWN
   - Skip gracefully if /proc/net/bonding/ does not exist

6. Link speed/duplex — run ethtool <iface> for each physical interface:
   - Parse: 'Speed: NNNMb/s' and 'Duplex: Full/Half'
   - Skip if ethtool not installed or CAP_NET_ADMIN not available (return INFO)
   - WARN if speed < 1000 Mbps on a GbE+ NIC (configurable threshold)
   - WARN if duplex is Half (negotiation failure)
   - Detect wireless: check /sys/class/net/<iface>/wireless/ exists
   - If wireless: run 'iw dev <iface> link' to get signal dBm
   - Wireless signal: OK > -65dBm, WARN -65 to -80dBm, CRIT < -80dBm

GROUP C — Routing context (fast, sequential):
7. Default route check:
   - gns.GetGateways() — CRIT if empty AND at least one interface is UP
   - NAT detection: if PublicIP != all interface IPs, set NATInfo.Detected = true

8. Public IP via gns (best effort, 3s timeout, skip if fails)

GROUP D — Conditional (only if triggered):
9. Traceroute via nexttrace:
   - ONLY if: internetUnreachable OR avgRTT > 200ms OR packetLoss > 5%
   - Max 15 hops, 3s per-hop timeout
   - Identify last responding hop before consecutive timeouts
   - Add interpretation: 'Path fails at hop N — ISP routing issue'

Total collector timeout: 35 seconds.
All calls respect context cancellation.
ethtool and iw calls use exec.CommandContext with 2s timeout each.
If ethtool returns permission error: set LinkInfo.Status = INFO, continue."
```

**Threshold reference table — complete network checks:**

| Metric | OK | WARN | CRIT |
|---|---|---|---|
| Gateway packet loss | 0% | 1–5% | > 5% |
| Internet packet loss | 0–1% | 2–10% | > 10% |
| Gateway jitter | < 20ms | 20–50ms | > 50ms |
| Internet jitter | < 30ms | 30–60ms | > 60ms |
| Gateway avg RTT | < 5ms | 5–50ms | > 50ms |
| Internet avg RTT | < 50ms | 50–200ms | > 200ms |
| DNS resolution latency | < 50ms | 50–200ms | > 200ms or fail |
| Interface errors | 0 | any non-zero | — |
| Interface drops | 0 | any non-zero | — |
| TCP TIME_WAIT | < 500 | 500–2000 | > 2000 |
| TCP CLOSE_WAIT | < 10 | 10–100 | > 100 |
| Bond slave health | all UP | 1+ slave DOWN | all slaves DOWN |
| Link speed (1GbE NIC) | 1000 Mbps | 100 Mbps | 10 Mbps |
| Link duplex | Full | — | Half |
| Wireless signal | > -65 dBm | -65 to -80 dBm | < -80 dBm |
| Default route | exists | — | missing + interfaces UP |

**Target output — `dsd net` healthy (with bonding and link info):**

```
🌐 Network diagnostics… (20 samples per target)

[Interfaces]
✅ bond0  UP   10.0.0.5        errors: 0   drops: 0   (active-backup: 2/2 slaves UP)
  ✅ eth0  slave  UP   1000Mbps  Full  [active]
  ✅ eth1  slave  UP   1000Mbps  Full  [standby]
✅ en0    UP   192.168.1.131   errors: 0   drops: 0   1000Mbps Full
ℹ️  wlan0  UP   10.0.0.8        signal: -58dBm  (WiFi, channel 6)
❌ en1    DOWN  —
✅ lo0    UP   127.0.0.1       (loopback, skipped)

[Latency & Quality]
Target         Reachable  Avg RTT  Jitter  Loss  Rating
192.168.1.1    ✅         2.1ms    0.4ms   0%    Excellent
1.1.1.1        ✅         14.2ms   2.1ms   0%    Good
8.8.8.8        ✅         18.7ms   1.8ms   0%    Good

[DNS]
✅ 192.168.1.1   reachable   12ms   google.com → 142.250.184.14
✅ 8.8.8.8       reachable   18ms

[Connections]
✅ TCP: 842 ESTABLISHED  |  TIME_WAIT: 124  |  CLOSE_WAIT: 2

[Routing]
✅ Default route: 192.168.1.1
ℹ️  NAT: internal 192.168.1.131 → public 82.45.112.33

[Summary]
Connectivity: ✅ Full  |  Quality: ✅ Good
Jitter: 0.4ms (gateway) / 1.9ms (internet)  |  Loss: 0%
```

**Target output — `dsd net` with multiple problems:**

```
🌐 Network diagnostics…

[Interfaces]
⚠️  bond0  UP   10.0.0.5   errors: 0  drops: 0  (active-backup: 1/2 slaves UP)
  ✅ eth0  slave  UP   1000Mbps  Full  [active]
  ❌ eth1  slave  DOWN               [standby — FAILED]
⚠️  en0   UP   192.168.1.131   errors: 142  drops: 17  ← hardware errors
⚠️  eth2  UP   10.0.0.6        100Mbps  Half  ← speed/duplex mismatch

[Latency & Quality]
Target         Reachable  Avg RTT  Jitter  Loss    Rating
192.168.1.1    ✅         2.1ms    0.3ms   0%      Excellent
1.1.1.1        ❌         —        —       100%    —
8.8.8.8        ❌         —        —       100%    —

[Traceroute → 8.8.8.8]  (triggered: internet unreachable)
Hop  IP               RTT     Host
1    192.168.1.1      1.2ms   gateway.local
2    10.0.0.1         8.4ms   isp-edge.provider.net
3    *                timeout
4    *                timeout
→ Path fails at hop 3 — ISP routing issue (local network OK)

[DNS]
✅ 192.168.1.1  reachable  9ms
❌ Resolution failed: DNS server reachable but internet routing broken

[Connections]
⚠️  TCP CLOSE_WAIT: 847  ← application not closing connections (likely bug)
✅  TCP TIME_WAIT:   312
✅  ESTABLISHED:     421

[Summary]
Connectivity: ❌ Internet unreachable  |  Local: ✅ OK
⚠️  bond0: eth1 slave down — single point of failure until repaired
⚠️  en0: hardware errors (142 errors, 17 drops) — check cable/switch
⚠️  eth2: link at 100Mbps Half-duplex — check cable or switch port config
⚠️  CLOSE_WAIT: 847 — application not releasing connections, check app logs
→ ISP routing issue at hop 3 confirmed by traceroute
→ Next steps: ip link show eth1 | ethtool eth2 | lsof -i | grep CLOSE_WAIT
```

**Renderer prompt:**

```
Prompt:
"Write internal/render/network.go that renders DeepNetworkInfo.
Accept a Formatter that carries plain bool (from output.IsPlain()).

COLLAPSE RULE (applies to all renderers):
- If all checks in a section are OK: print one collapsed line, not a table
  e.g. 'Network ✅' or '[Network] ✅ all OK'
- Only expand a section when it contains WARN or CRIT results
- If ALL sections are OK: print 'All systems normal (N checks passed)' and skip all sections

Rendering rules:
- If plain=false: use lipgloss colors — green OK, yellow WARN, red CRIT
- If plain=true:  use ASCII only — [OK], [WARN], [CRIT] tags, no ANSI, no borders

Section: Interfaces
- Physical interfaces: show state, IPs, errors, drops, speed, duplex
- Bond interfaces: show mode, slave count (UP/total), indent slaves beneath
  e.g. '⚠️  bond0  active-backup  1/2 slaves UP' then indented slave lines
- Wireless interfaces: show signal dBm and rating alongside other fields
- Skip loopback unless --verbose

Section: Latency & Quality
- Table: Target / Reachable / Avg RTT / Jitter / Loss / Rating
- Color each column independently by its threshold

Section: Connections
- Only show if any state has WARN/CRIT, or if --verbose
- Show TIME_WAIT, CLOSE_WAIT, ESTABLISHED counts
- Annotate: CLOSE_WAIT > 100 gets '← application bug likely'

Section: Traceroute (only if populated)
- Indent successful hops, bold/mark '>>>' last responding hop
- Show interpretation line below the table

Section: Summary
- One plain-English sentence per problem detected
- Final 'Next steps' line listing 2-3 commands relevant to problems found
- --json flag: output raw DeepNetworkInfo as JSON, skip all rendering"
```

---

### Network Checks — Scope Boundary

**In scope for DashDiag** (diagnostic snapshot):

| Tool replaced | DashDiag equivalent | Where |
|---|---|---|
| `ss -s` (connection summary) | `gopsutil net.Connections()` — TIME_WAIT/CLOSE_WAIT counts | `dsd net` |
| `netstat -rn` (routes) | `gns.GetGateways()` — default route exists | `dsd health` + `dsd net` |
| `ip link show` (interface state) | `gopsutil net.Interfaces()` | `dsd health` + `dsd net` |
| `cat /proc/net/bonding/*` | `detectBonding()` — slave states | `dsd net` |
| `ethtool <iface>` (speed/duplex) | `exec.Command("ethtool", iface)` — parsed | `dsd net` |
| `iw dev <iface> link` (WiFi signal) | `exec.Command("iw", ...)` — signal dBm | `dsd net` |
| NAT detection | `gns.PublicIP != interface IPs` | `dsd net` |

**Out of scope — recommend as next-step hints only:**

| Tool | Why out of scope | Hint text |
|---|---|---|
| `tcpdump` | Packet capture — interactive, requires root, not a snapshot | `tcpdump -i eth0 -c 100 -w cap.pcap` |
| `iftop` | Real-time bandwidth monitor — interactive, requires root | `iftop -i eth0` |
| `iptables -L` | Firewall rules — management, not diagnostics | `iptables -L -n -v \| head -40` |
| `iptables -t nat -L` | NAT rule inspection — management, not diagnostics | `iptables -t nat -L -n -v` |
| `nmap` | Port scanner — active probing, not passive diagnostics | `nmap -sV localhost` |
| `wireshark` | Packet analysis — not CLI snapshot | Use `tcpdump` for capture first |
| `mtr` | Interactive path quality tool | `mtr --report 8.8.8.8` |

The rule: DashDiag reads state passively. Tools that actively probe, modify, or require interactive sessions are not DashDiag's job. DashDiag tells you **what commands to run next**, not run them for you.

---

### Step 3: Container Runtime Module

The container runtime collector has a clear priority order. Docker and Podman share the same API — one client handles both. containerd and CRI-O are only reported as detected runtime names inside `dsd k8s`, never queried directly.

**Runtime Priority Matrix:**

| Runtime | Context | Socket Path | How to Query | Priority |
|---|---|---|---|---|
| Docker | Dev, CI/CD, non-enterprise Linux | `/var/run/docker.sock` | Docker SDK for Go | 1st |
| Podman | RHEL 8+, Fedora, rootless prod | `/run/podman/podman.sock` or `$XDG_RUNTIME_DIR/podman/podman.sock` | Docker SDK for Go (API-compatible) | 2nd |
| containerd | K8s nodes (EKS, GKE, kubeadm) | `/run/containerd/containerd.sock` | Detect only — report version, don't query | 3rd (K8s only) |
| CRI-O | OpenShift, some kubeadm | `/var/run/crio/crio.sock` | Detect only — report version, don't query | 4th (K8s only) |

**Key insight:** Podman deliberately implements the Docker REST API. The Docker SDK for Go works against Podman's socket with zero code changes — just a different socket path. You get two runtimes for the price of one client.

**Runtime detection logic — `internal/collectors/runtime.go`:**

```go
package collectors

import (
    "fmt"
    "os"

    "github.com/docker/docker/client"
)

var ErrNoRuntimeFound = fmt.Errorf("no container runtime detected")

type RuntimeClient struct {
    Client  *client.Client
    Runtime string // "docker" | "podman"
    Socket  string
}

func DetectRuntime() (*RuntimeClient, error) {
    candidates := []struct {
        socket  string
        runtime string
    }{
        {"/var/run/docker.sock", "docker"},
        {"/run/podman/podman.sock", "podman"},
        {podmanUserSocket(), "podman"},
    }

    for _, c := range candidates {
        if c.socket == "" {
            continue
        }
        if _, err := os.Stat(c.socket); err != nil {
            continue
        }
        cli, err := client.NewClientWithOpts(
            client.WithHost("unix://" + c.socket),
            client.WithAPIVersionNegotiation(),
        )
        if err != nil {
            continue
        }
        return &RuntimeClient{
            Client:  cli,
            Runtime: c.runtime,
            Socket:  c.socket,
        }, nil
    }

    return nil, ErrNoRuntimeFound
}

func podmanUserSocket() string {
    xdg := os.Getenv("XDG_RUNTIME_DIR")
    if xdg == "" {
        return ""
    }
    return xdg + "/podman/podman.sock"
}
```

**Container collector — `internal/collectors/docker.go`:**

```go
package collectors

import (
    "context"
    "fmt"
    "time"

    "github.com/docker/docker/api/types"
    "github.com/yourusername/dashdiag/internal/models"
)

type ContainerCollector struct{}

func (c *ContainerCollector) Name() string { return "Containers" }

func (c *ContainerCollector) Collect() (interface{}, error) {
    rt, err := DetectRuntime()
    if err == ErrNoRuntimeFound {
        // Not an error — just not installed
        return models.ContainerInfo{
            RuntimeDetected: false,
            Message:         "No container runtime detected (Docker/Podman not installed)",
        }, nil
    }
    if err != nil {
        return nil, err
    }
    defer rt.Client.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    containers, err := rt.Client.ContainerList(ctx, types.ContainerListOptions{All: true})
    if err != nil {
        return nil, fmt.Errorf("container list failed: %w", err)
    }

    var info models.ContainerInfo
    info.RuntimeDetected = true
    info.RuntimeName     = rt.Runtime
    info.SocketPath      = rt.Socket

    for _, ctr := range containers {
        inspect, _ := rt.Client.ContainerInspect(ctx, ctr.ID)
        restarts := 0
        if inspect.ContainerJSONBase != nil {
            restarts = inspect.ContainerJSONBase.RestartCount
        }

        status := "OK"
        if restarts > 20 {
            status = "CRIT"
        } else if restarts > 5 {
            status = "WARN"
        }
        if ctr.State == "exited" || ctr.State == "dead" {
            status = "WARN"
        }
        if inspect.State != nil && inspect.State.Health != nil &&
            inspect.State.Health.Status == "unhealthy" {
            status = "CRIT"
        }

        info.Containers = append(info.Containers, models.ContainerSummary{
            Name:       ctr.Names[0],
            State:      ctr.State,
            Status:     status,
            Image:      ctr.Image,
            Restarts:   restarts,
            CreatedAgo: time.Since(time.Unix(ctr.Created, 0)).Round(time.Minute).String(),
        })
    }

    return info, nil
}
```

**AI prompt for this module:**
```
Prompt:
"Using the DetectRuntime() function in internal/collectors/runtime.go,
write internal/collectors/docker.go that collects container info.
For each container return: name, state (running/exited/paused/dead),
restart count, image name, created time ago, health check status if present.
Flags: WARN if restarts > 5 or state == exited, CRIT if restarts > 20 or health == unhealthy.
If no runtime found → return ContainerInfo{RuntimeDetected: false}, not an error.
Timeout all Docker API calls at 5 seconds."
```

**Example output — `dsd docker`:**
```
🐳 Container runtime check… (podman @ /run/podman/podman.sock)

Name               State     Restarts  Image                    Age
nginx-proxy        running   0         nginx:1.25               3 days
api-service        running   2         myapp:v1.4.2             1 hour
worker-crashed     exited    23 ⚠️      myapp-worker:v1.4.1      45 mins  ← CRIT
db-postgres        running   0         postgres:15              7 days

— Summary —
Runtime: Podman | Containers: 4 | Running: 3 | Exited: 1
⚠️  1 container needs attention: worker-crashed (23 restarts)
```

---

### Step 4: Platform Abstraction

```
Prompt:
"Create internal/platform/ with linux.go and darwin.go using //go:build tags.

Expose: GetDefaultGateway() string
  - Linux: parse /proc/net/route (skip loopback/default entries without gateway)
  - macOS: parse 'netstat -rn | grep default' output

Expose: GetDNSServers() []string
  - Linux: parse /etc/resolv.conf
  - macOS: parse 'scutil --dns' output

Expose: IsLinux() bool, IsMacOS() bool
  - Used by collectors to select the right data source

Note: ClockCollector, SwapCollector, and CPUDetailCollector all use build tags
or runtime OS detection to pick the right platform path. See collector files
for the full platform-specific implementation."
```

---

### Step 5: Testing

```
Prompt:
"Write table-driven unit tests for internal/collectors/cpu.go.
Define a SystemMetrics interface that wraps gopsutil calls.
Inject a mock implementation in tests.
Test cases: normal (OK), >80% load (WARN), >95% load (CRIT),
and gopsutil returns error (error propagated correctly)."
```

---

### Step 6: CI/CD Pipeline

**Three separate workflows — keep them focused:**

**`.github/workflows/ci.yml` — runs on every PR and push to main:**
```
Prompt:
"Write .github/workflows/ci.yml with these jobs:

1. lint: runs go vet ./... and staticcheck ./... and golangci-lint run
   Install: go install honnef.co/go/tools/cmd/staticcheck@latest
   golangci-lint checks: errcheck, gosec, ineffassign, misspell

2. test (matrix):
   strategy.matrix.os: [ubuntu-22.04, ubuntu-20.04, macos-13]
   Also run in containers: alpine:3.18, redhat/ubi8
   Steps: go test ./... -race -coverprofile=coverage.out
   Upload coverage to codecov

3. build-check: go build ./... on all matrix targets to catch cross-platform issues

All jobs must pass before PR can merge."
```

**`.github/workflows/release.yml` — runs on tags `v*`:**
```
Prompt:
"Write .github/workflows/release.yml that:
1. Triggers on git tags matching v*
2. Injects version via ldflags:
   VERSION=$(git describe --tags)
   COMMIT=$(git rev-parse --short HEAD)
   BUILT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   -ldflags="-X dsd/internal/version.Version=$VERSION
              -X dsd/internal/version.Commit=$COMMIT
              -X dsd/internal/version.Built=$BUILT"
3. Cross-compiles: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
4. Generates sha256 checksums for each binary
5. Creates GitHub Release with all 4 binaries + checksums.txt attached
6. Uses GoReleaser if available (.goreleaser.yml in repo), else manual go build loop"
```

**Golden file tests — add to test suite:**
```
Prompt:
"Write internal/render/golden_test.go implementing golden file tests.
Use testscript or a simple golden helper:
  1. Create testdata/golden/ directory
  2. For each render function, call with mock snapshot data
  3. Compare output to testdata/golden/<name>.txt
  4. Flag -update regenerates golden files: go test ./... -update
Test cases needed:
  - quick_healthy.txt   (all checks OK)
  - quick_warn.txt      (CPU + swap warnings)
  - quick_crit.txt      (disk full + swap thrashing)
  - quick_container.txt (running inside Docker, shows container banner)
  - net_healthy.txt     (full connectivity)
  - net_no_internet.txt (gateway OK, internet unreachable + traceroute)
  - plain_mode.txt      (same as quick_healthy but --plain, no emoji/ANSI)"
```

---

### Step 6b: --report flag and --out file saving

`--report` is a format flag, not a command. It is handled by `internal/output/tty.go`
`DetectMode()` which already has `ModeReport`. No separate `cmd/report.go` needed.

The `--out <file>` flag is a global persistent flag on rootCmd:

```go
rootCmd.PersistentFlags().StringVar(&outFile, "out", "",
    "save output to file (works with --report, --json, --plain)")
```

If `--out` is set, the renderer writes to the file instead of stdout.
Exit codes remain 0/1/2 regardless of output destination.

**Example usage:**
```bash
dsd health --report --out health-$(date +%Y%m%d-%H%M).md
dsd k8s --report --out k8s-check.md
dsd net deep --report | pbcopy   # pipe to clipboard on macOS
```

---

### Step 7: Install Script & README

```
Prompt:
"Write install.sh for DashDiag that:
1. Detects OS (linux/darwin) and arch (amd64/arm64) via uname
2. Downloads correct binary from GitHub releases (latest tag via GitHub API)
3. Installs to /usr/local/bin/dsd with chmod +x
4. Verifies download with sha256 checksum if .sha256 file exists
5. Prints success with 'Try it: dsd health'
Safe: checks for curl/wget, handles download failure, requires no root if ~/bin exists"
```

```
Prompt:
"Write README.md for DashDiag. Requirements:
- First 3 lines: name, one-line description, install command — make someone want to star it
- Animated demo GIF placeholder with [demo.gif] alt text
- Install section: curl one-liner, Homebrew, manual binary download
- Command reference table: dsd health / dsd health deep / dsd net / dsd net deep / dsd docker / dsd k8s
- Example output block (emoji + color described in ASCII)
- 'Why DashDiag?' section: 3 bullet points max
- Contributing + License sections
Optimize for GitHub: badges, clean headings, no walls of text."
```

---

### Step 8: Kubernetes Module (Phase 4)

```
Prompt — k8s.go (full implementation):
"Write internal/collectors/k8s.go using k8s.io/client-go.
See §6 for the complete data model (models.K8sInfo) and failure modes table.

Setup:
  clientset, err := buildClientFromKubeconfig()
  if err: return K8sInfo{Status: "INFO", StatusReason: "K8s not configured"}
  All API calls: context.WithTimeout(ctx, 10*time.Second)

Run all checks concurrently with errgroup or sync.WaitGroup:

1. API server latency: time GET /healthz

2. Nodes: list all, for each check conditions array:
   Ready=False → CRIT; MemoryPressure/DiskPressure/PIDPressure=True → WARN

3. Pods: list all namespaces once, iterate once for ALL pod checks:
   (single list call — avoid N+1 API calls)

   a. OOMKilled: LastTerminationState.Terminated.Reason == 'OOMKilled'
      → K8sPodOOM{exit code, memory limit, restart count}

   b. Evicted: Phase==Failed AND Reason==Evicted AND Message contains 'memory'
      → K8sEviction{node name, message}

   c. CrashLoopBackOff: State.Waiting.Reason == 'CrashLoopBackOff'
      → K8sCrashLoop{container name, restart count, last exit code}

   d. ImagePullBackOff / ErrImagePull: State.Waiting.Reason in those values
      → K8sImagePullError{container name, image, message}

   e. Pending scheduling: Phase==Pending, find PodScheduled condition with Status=False
      → K8sPendingPod{reason from condition.Message}

4. PVCs: list all namespaces, flag Status.Phase != 'Bound'
   → K8sPVC{namespace, name, storage class, phase, message from conditions}

5. CoreDNS: list pods in kube-system with LabelSelector k8s-app=kube-dns
   Count total vs ContainersReady
   → K8sCoreDNS{TotalPods, ReadyPods}

6. Deployments: availableReplicas == 0 → CRIT; < desired → WARN

7. Events: list Warning events, filter last 15 min by creationTimestamp

Status aggregation (highest severity wins):
  CRIT: any OOMKilled, CrashLoop, ImagePull, CoreDNS=0, node NotReady
  WARN: evictions, pending pods, unbound PVCs, degraded CoreDNS, node pressure

RBAC: get/list nodes, pods, deployments, events, persistentvolumeclaims
Return models.K8sInfo."
```

**K8s RBAC minimum — ClusterRole for `dsd k8s`:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dsd-k8s-reader
rules:
- apiGroups: [""]
  resources: ["nodes", "pods", "events", "persistentvolumeclaims",
              "namespaces", "limitranges", "resourcequotas"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
- apiGroups: ["metrics.k8s.io"]
  resources: ["pods"]
  verbs: ["get", "list"]
  # ^ optional — dsd k8s gracefully skips throttling check if metrics-server absent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dsd-k8s-reader-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: dsd-k8s-reader
  apiGroup: rbac.authorization.k8s.io
```

**K8s OOM heuristics — `internal/analysis/heuristics.go`:**

```go
// Container OOMKill — hard memory limit hit
for _, pod := range snapshot.K8s.OOMKilledPods {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf(
            "K8s OOMKill: %s/%s container %s killed (exit 137) — limit: %.0fMB",
            pod.Namespace, pod.PodName, pod.ContainerName, pod.MemLimitMB),
        Hints: []string{
            fmt.Sprintf("kubectl describe pod %s -n %s", pod.PodName, pod.Namespace),
            fmt.Sprintf("kubectl logs %s -n %s --previous", pod.PodName, pod.Namespace),
            "increase memory limit in pod spec or fix memory leak",
        },
    })
}

// Pod evictions — node memory pressure, preventive eviction
for _, eviction := range snapshot.K8s.EvictedPods {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s eviction: %s/%s evicted from %s — %s",
            eviction.Namespace, eviction.PodName, eviction.NodeName, eviction.Message),
        Hints: []string{
            fmt.Sprintf("kubectl describe node %s", eviction.NodeName),
            "kubectl get events --field-selector reason=Evicted",
            "check node memory headroom: kubectl top nodes",
        },
    })
}

// Node MemoryPressure — kubelet is evicting pods to reclaim memory
for _, node := range snapshot.K8s.Nodes {
    if node.MemoryPressure {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: fmt.Sprintf(
                "K8s node %s has MemoryPressure — kubelet is evicting pods",
                node.Name),
            Hints: []string{
                fmt.Sprintf("kubectl describe node %s", node.Name),
                "kubectl get events --field-selector involvedObject.name=" + node.Name,
                "kubectl drain --ignore-daemonsets " + node.Name + "  (if node needs relief)",
            },
        })
    }
}

// CrashLoopBackOff — pod will never self-recover
for _, pod := range snapshot.K8s.CrashLoopPods {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf(
            "K8s CrashLoopBackOff: %s/%s container %s (exit %d, restarts: %d) — will not self-recover",
            pod.Namespace, pod.PodName, pod.ContainerName,
            pod.LastExitCode, pod.RestartCount),
        Hints: []string{
            fmt.Sprintf("kubectl logs %s -n %s --previous", pod.PodName, pod.Namespace),
            fmt.Sprintf("kubectl describe pod %s -n %s", pod.PodName, pod.Namespace),
            fmt.Sprintf("kubectl get pod %s -n %s -o yaml  (check command/entrypoint/env)",
                pod.PodName, pod.Namespace),
        },
    })
}

// ImagePullBackOff / ErrImagePull — pod cannot start
for _, img := range snapshot.K8s.ImagePullErrors {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: fmt.Sprintf(
            "K8s %s: %s/%s cannot pull image %s",
            img.Reason, img.Namespace, img.PodName, img.Image),
        Hints: []string{
            fmt.Sprintf("kubectl describe pod %s -n %s  (see Events for registry error)",
                img.PodName, img.Namespace),
            fmt.Sprintf("kubectl get secret -n %s  (check imagePullSecrets)",
                img.Namespace),
            // Direct pull test — confirms whether auth or image name is the issue
            fmt.Sprintf("docker pull %s  (test pull with local Docker credentials)",
                img.Image),
        },
    })
}

// Pending pods — scheduling blocked
for _, p := range snapshot.K8s.PendingPods {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s pod %s/%s stuck Pending: %s",
            p.Namespace, p.PodName, p.Reason),
        Hints: []string{
            fmt.Sprintf("kubectl describe pod %s -n %s", p.PodName, p.Namespace),
            "kubectl get nodes  (check node capacity)",
            "kubectl describe node <node>  (check allocatable vs requested)",
        },
    })
}

// Unbound PVCs — pods will stay in ContainerCreating
for _, pvc := range snapshot.K8s.UnboundPVCs {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s PVC %s/%s is %s — pods mounting it will stay in ContainerCreating",
            pvc.Namespace, pvc.Name, pvc.Phase),
        Hints: []string{
            fmt.Sprintf("kubectl describe pvc %s -n %s", pvc.Name, pvc.Namespace),
            fmt.Sprintf("kubectl get storageclass  (check provisioner is running)"),
            fmt.Sprintf("kubectl get events -n %s --field-selector involvedObject.name=%s",
                pvc.Namespace, pvc.Name),
        },
    })
}

// CoreDNS down — all in-cluster service DNS fails
if snapshot.K8s.CoreDNS.ReadyPods == 0 && snapshot.K8s.CoreDNS.TotalPods > 0 {
    insights = append(insights, models.Insight{
        Level:   "CRIT",
        Message: "K8s CoreDNS: 0 pods Ready — ALL in-cluster DNS resolution failing",
        Hints: []string{
            "kubectl get pods -n kube-system -l k8s-app=kube-dns",
            "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50",
            "kubectl rollout restart deployment/coredns -n kube-system",
        },
    })
} else if snapshot.K8s.CoreDNS.ReadyPods < snapshot.K8s.CoreDNS.TotalPods {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s CoreDNS: %d/%d pods Ready — degraded DNS capacity",
            snapshot.K8s.CoreDNS.ReadyPods, snapshot.K8s.CoreDNS.TotalPods),
        Hints: []string{
            "kubectl get pods -n kube-system -l k8s-app=kube-dns",
            "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50",
        },
    })
}

// BestEffort pods — first evicted under node memory pressure
if len(snapshot.K8s.BestEffortPods) > 0 {
    // Only WARN if BestEffort pods share a namespace with Guaranteed/Burstable pods
    // (pure BestEffort namespaces are less concerning — often test/batch workloads)
    names := make([]string, 0, min(3, len(snapshot.K8s.BestEffortPods)))
    for _, p := range snapshot.K8s.BestEffortPods[:min(3, len(snapshot.K8s.BestEffortPods))] {
        names = append(names, p.Namespace+"/"+p.PodName)
    }
    suffix := ""
    if len(snapshot.K8s.BestEffortPods) > 3 {
        suffix = fmt.Sprintf(" (+%d more)", len(snapshot.K8s.BestEffortPods)-3)
    }
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s BestEffort QoS: %d pod(s) have no resource limits — first evicted under pressure: %s%s",
            len(snapshot.K8s.BestEffortPods), strings.Join(names, ", "), suffix),
        Hints: []string{
            "kubectl get pods -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.status.qosClass}{"\n"}{end}' --all-namespaces | grep BestEffort",
            "add resources.limits to pod specs or deploy a LimitRange with defaults",
        },
    })
}

// CPU throttling — pod slowed by CPU limit despite node having capacity
for _, p := range snapshot.K8s.ThrottledPods {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s CPU throttled: %s/%s container %s at %.0f%% of %dm limit — add latency from throttling",
            p.Namespace, p.PodName, p.ContainerName, p.UsagePct, p.CPULimitMillis),
        Hints: []string{
            fmt.Sprintf("kubectl top pod %s -n %s --containers", p.PodName, p.Namespace),
            fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[*].resources}'",
                p.PodName, p.Namespace),
            "raise CPU limit or remove it for bursty/latency-sensitive workloads",
        },
    })
}

// Namespaces without enforcement — pods get BestEffort QoS by default
for _, ns := range snapshot.K8s.UnenforcedNamespaces {
    insights = append(insights, models.Insight{
        Level:   "WARN",
        Message: fmt.Sprintf(
            "K8s namespace %s has %d running pod(s) but no LimitRange or ResourceQuota — pods default to BestEffort QoS",
            ns.Namespace, ns.RunningPods),
        Hints: []string{
            fmt.Sprintf("kubectl get limitrange -n %s", ns.Namespace),
            fmt.Sprintf("kubectl get resourcequota -n %s", ns.Namespace),
            "deploy a LimitRange with default requests/limits to this namespace",
        },
    })
}
```

**Target output — `dsd k8s` with multiple failure types:**

```
⚡ Kubernetes cluster check… (api latency: 14ms)

[Nodes]
✅ 7/8 Ready
❌ node-3: MemoryPressure=True ← kubelet actively evicting pods

[Pod Failures]
❌ CrashLoopBackOff (will not self-recover):
   default/payment-svc-9x4k (container: app) — exit 1, restarts: 47
   → kubectl logs payment-svc-9x4k -n default --previous

❌ ImagePullBackOff:
   staging/frontend-v2-8b2m (container: frontend) — image: registry.io/app:v2.1.0
   → kubectl describe pod frontend-v2-8b2m -n staging  (see Events for registry error)
   → kubectl get secret -n staging  (check imagePullSecrets)

❌ OOMKilled (last restart cycle):
   default/api-worker-7f9b (container: worker) — limit: 512MB, restarts: 14

⚠️  Evicted (memory-driven):
   default/cache-6d4c (node-3): "node low on memory. Threshold: 100Mi"

⚠️  Pending (scheduling blocked):
   default/batch-job-5z9p: "0/3 nodes: 3 Insufficient memory"
   → kubectl describe node  (check allocatable vs requested)

[Storage]
⚠️  Unbound PVC: default/postgres-data (Pending, standard StorageClass)
   → kubectl describe pvc postgres-data -n default
   → kubectl get storageclass

[CoreDNS]
✅ CoreDNS: 2/2 pods Ready

[Workloads]
⚠️  deployment/api-worker: 2/3 available
✅ Pods: 87 Running / 3 Pending / 5 Failed

[Events]
⚠️  8 Warning events in last 15 minutes
   → "Evicting pod default/cache-6d4c due to node memory pressure"

[Resource Hygiene]
⚠️  BestEffort pods: 4  (default/worker-pool-x2k, staging/test-job +2 more)
   → add resources.limits to pod specs or deploy LimitRange defaults

⚠️  Unenforced namespaces: staging (12 pods, no LimitRange, no ResourceQuota)
   → kubectl apply -f limitrange.yaml -n staging

⚠️  CPU throttled: default/api-gateway (container: proxy) at 94% of 200m limit
   → raise CPU limit or remove it for this latency-sensitive container

ℹ️  metrics-server: available (throttling data current)

— Summary —
Status: ❌ CRIT | CrashLoop: 1 | ImagePull: 1 | OOMKill: 1 | Evictions: 1 | Pending: 1 | PVC: 1 | BestEffort: 4 | Throttled: 1
```

---

## 18. AI Prompting Best Practices for This Project

### Do
- Give AI one module at a time with explicit struct/interface contracts
- Specify which libraries to use — prevents AI choosing random alternatives
- Ask AI to handle failure modes explicitly: Docker not running, no network, no gateway
- Ask for table-driven tests alongside every implementation
- After each module: `go build ./... && go test ./...` before moving on

### Don't
- Ask AI to build the entire project in one prompt
- Accept AI output without compiling and running it immediately
- Let AI parse command output — always specify a library instead
- Skip `--json` — it's what makes the tool scriptable and CI-friendly
- Skip `--debug` — it's what makes the tool supportable when users file bugs
- Add Kubernetes before the core is used daily
- Forget to handle permission errors gracefully — "permission denied" must never crash

### Useful Review Prompts
```
"Review this Go function for: error handling gaps, platform assumptions (Linux vs macOS),
and goroutine safety if called concurrently."

"Review this /proc file parser for: panic conditions on malformed input,
integer overflow on large values, missing nil checks. Suggest fuzz test seeds."

"Audit this file for gosec findings: unsafe file permissions, path traversal risk,
unchecked errors on os.ReadFile calls, predictable temp file names."

"Refactor this collector to use an interface so gopsutil calls can be mocked in tests."

"What edge cases am I missing in this network check on a machine inside a Docker
container with no default gateway?"

"Generate a Makefile with targets: build, test, lint, release-local, install."

"Write a demo script that runs dsd health and captures the ASCII output
formatted as a README code block, suitable for a GitHub README."
```

---

## 19. Business Model & Monetization Path

DashDiag starts as a free open-source utility. That is not a compromise — it is the strategy. The tool builds trust, installs, and community. Paid features layer on top of a fully functional free CLI — never on top of a crippled one.

**The core rule: never put diagnostic features behind a paywall.** Every `dsd` command — including `dsd health deep`, `dsd net deep`, and `dsd k8s deep` — is free forever. Money comes from what happens after the CLI runs: storage, collaboration, policy enforcement, and fleet management. This is the pattern of every successful CLI tool that monetised (ngrok, Tailscale, 1Password CLI, Datadog agent).

---

### Monetization Sequence — Fastest Path to Revenue

The original tiers were correct in direction but wrong in sequence. The revised sequence is ordered by time-to-first-paying-customer:

**Month 1–2: Ship Phase 1. Build user base. Do not touch paid features yet.**
No SaaS, no policy engine, no fleet mode. Just `dsd health` and `dsd net` in the hands of real engineers. Add one waitlist link to the README: "⭐ Using DashDiag at work? [Join the team waitlist] — launching Q3 2026."

**Month 2–3: `--share` flag (snapshot hosting)**
```bash
dsd health --share
# → https://snap.dashdiag.sh/s/abc123  (expires 24h, free)
```
An engineer shares a snapshot URL in a Slack incident. A colleague clicks it, sees the value, installs dsd. Free tier: 24h expiry. Paid tier: persistent snapshots, team workspace, diff between runs. This is the virality-to-revenue path — collect emails from snapshot viewers from day one.

**Contextual upsell — shown after `--share` URL, once per day max:**
```
$ dsd health --share
→ https://snap.dashdiag.sh/s/abc123

ℹ️  Free tier: snapshot expires in 24 hours.
    Team plan keeps snapshots for 90 days + adds team diff history.
    → dashdiag.sh/teams  ($29/month, 14-day free trial)
```
Never shown in `--json`, `--plain`, or non-TTY. Shown after the URL — not before.
The engineer already received the value before seeing the upgrade option.


**Month 3–4: Team workspace (first paid product)**
- Persistent snapshot history
- Team sharing and commenting
- Diff reports: "what changed since yesterday's check?"
- Price: $29/month per team (up to 10 engineers)
- Target: the engineer who shared the snapshot and wants their team to have it

**Month 4–6: `dsd policy` — CI/CD gate (second paid product)**
```bash
dsd health --json | dsd policy check --policy .dsd-policy.yaml
```
```yaml
# .dsd-policy.yaml (free, local)
require:
  cpu_load_max: 0.7
  disk_free_min_pct: 20
  required_services: [nginx, postgres]
  network_reachable: [10.0.0.1, api.stripe.com]
```

**`--recheck` — context preservation for CI failures:**

When `dsd policy check` fails a CI deploy, the failing checks are saved to
`~/.dsd/state.json` as `last_policy_failure`. After fixing, re-verify fast:

```bash
# First run fails in CI — saves failure state
$ dsd health --json | dsd policy check --policy .dsd-policy.yaml
❌ Policy failed: memory_free_pct 8% < required 20%
   Run after fixing: dsd policy check --recheck

# After fix — no need to re-run full pipeline
$ dsd policy check --recheck
⚡ Re-checking last failed checks (memory_free_pct)...
✅ memory_free_pct: 24%  (was 8%, required ≥ 20%)
✅ All previously failed checks now passing. Safe to re-run deploy.
```

The YAML policy file is free. The paid product is centralised policy management: org-wide policies, audit log, SSO, Slack alerting on policy violations. This is Tier 2 from the original model — moved earlier because it has clear ROI for engineering teams.

**Month 6+: `dsd fleet` — multi-server checks (enterprise)**
```bash
dsd fleet --hosts servers.txt health
dsd fleet --hosts web-tier health --report --out fleet-$(date).md
```
Run `dsd health` across N servers concurrently via SSH, aggregate into one report. No agent, no daemon. Enterprise buyers understand this immediately: "I have 200 servers, I want one command to see which ones are unhealthy." Highest contract value. Requires user base to validate demand — do not build before month 6.

---

### Why NOT to split deep checks to paid

The engineer who runs `dsd health`, wants more detail, hits a paywall, and falls back to `htop` manually — that engineer never becomes a paying customer AND never recommends DashDiag to a colleague. You lose the conversion and the referral simultaneously. Deep checks are a diagnostic capability, not a commercial feature. Keep them free.

---

### Tier Structure (updated)

### Tier 0 — Free CLI (always, forever)
All `dsd` commands including all `deep` variants. MIT licensed. This is the distribution mechanism and must never be crippled.

### Tier 1 — Team Snapshots ($29/month)
Hosted snapshot history, team workspace, diff reports, commenting. The `--share` flag is the on-ramp. No server required on the engineer's side.

### Tier 2 — Policy & CI Gates ($99/month per team)
Centralised `dsd policy` management: org-wide policies, CI/CD integration, audit log, Slack/PagerDuty alerting on policy violations. Local YAML policy file always free.

### Tier 3 — Fleet Mode (enterprise, annual contract)
`dsd fleet` across N servers via SSH. Aggregated reports, scheduled runs, CSV export, role-based access. This is the product that replaces ad-hoc SSH loops and manual runbooks at scale.

### Tier 4 — AI Diagnostic Copilot (deferred)
Deferred — see §25 Possible Future Development. DashDiag's deterministic heuristics (§21) already provide actionable next steps without LLM dependency.

---

### Monetization Summary

| Path | When | Model | Est. first customer |
|---|---|---|---|
| Open source CLI | Now | Free forever | — |
| Snapshot sharing (`--share`) | Month 2–3 | Freemium | Month 3 |
| Team workspace | Month 3–4 | $29/month/team | Month 4 |
| Policy engine (`dsd policy`) | Month 4–6 | $99/month/team | Month 6 |
| Fleet mode (`dsd fleet`) | Month 6+ | Annual contract | Month 8 |
| GitHub Sponsors | Month 2+ | Open Collective | Month 3 |
| AI copilot | Deferred | TBD | Post-UnpackOps |

### The One Thing to Do Right Now

Add this to the README before launch day:

```markdown
#### 💼 Using DashDiag at work?

We're building team features: persistent snapshot history, shared dashboards,
pre-deploy policy gates, and fleet health checks across multiple servers.

[Join the early access waitlist →](https://dashdiag.sh/teams)
```

Collect emails from day one. When you build the paid features, you already have
a warm list of people who self-identified as team users. That list is worth more
than any feature you could build in the same time.

---

## 19b. Viral Features — Adoption & Monetization Accelerators

These six features are designed around proven CLI virality mechanics: screenshot sharing,
paste-into-Slack sharing, comparison sharing, and social proof. They require no new
collectors — only new renderers and one new command. Prioritised by implementation cost
vs revenue impact.

---

### Priority 1 — `--diff` : What changed since last run
**Build in:** Phase 1 (renderer only, 1 day)
**Viral mechanic:** Comparison virality — engineers share diffs in incident Slack threads
**Revenue path:** Local diff is free → cloud baseline history is paid (Team tier)

```bash
# Baseline saved automatically after every run to ~/.dsd/baselines/<hostname>-latest.json
dsd health --diff

# Output:
⚡ Changes since last run (2h 14m ago) — web-prod-01

  Memory:   82% → 94%   ⚠️  +12% and growing
  Systemd:  0 failed → 1 failed  ❌  nginx.service added
  FD count: 4,821 → 48,210  ⚠️  10x spike

  Unchanged (9 checks): CPU ✅  Disk ✅  Network ✅  Clock ✅  ...

→ Something changed 2 hours ago — run dsd health deep for full picture
```

**Implementation:**
```go
// internal/baseline/baseline.go
// Save after every run:
//   ~/.dsd/baselines/<hostname>-latest.json   ← current run
//   ~/.dsd/baselines/<hostname>-prev.json     ← previous run (rotated)
// --diff loads prev.json, compares field by field, renders only changed fields
// Fields that changed WARN→CRIT render red; OK→WARN render yellow; CRIT→OK render green
// Unchanged fields collapsed to one summary line

// stdin piping — accept baseline from stdin with:
//   dsd health --diff -          (dash = read from stdin)
//   cat yesterday.json | dsd health --diff -
//   aws s3 cp s3://my-bucket/baseline.json - | dsd health --diff -
//
// This makes --diff scriptable: engineers can store baselines in S3, git,
// or any remote store and compare against them without manual file management.
//
// Detection:
func loadBaseline(path string) (*models.Snapshot, error) {
    if path == "-" {
        // Read from stdin
        data, err := io.ReadAll(os.Stdin)
        if err != nil { return nil, err }
        return parseSnapshot(data)
    }
    if path != "" {
        // Explicit file path
        data, err := os.ReadFile(path)
        if err != nil { return nil, err }
        return parseSnapshot(data)
    }
    // Default: load from ~/.dsd/baselines/<hostname>-prev.json
    return loadPrevBaseline()
}
```

**Why this is Priority 1:** One day to build. No backend. Direct conversion question:
"Can I see last week's baseline?" = paying customer asking to hand over money.

---

### Priority 1b — `--since-deploy` : What changed since the last deploy (half a day)
**Build in:** Phase 1 alongside `--diff` (shares all baseline infrastructure)
**Viral mechanic:** Comparison virality — the post-deploy check engineers run every time
**Revenue path:** Same as `--diff` — local baselines free, cloud history paid

Zero engineer effort after one week of use. No config, no pipeline changes.
dsd auto-detects the last deploy time from service restart signals and finds
the nearest saved baseline from before that restart.

```bash
$ dsd health --since-deploy

⚡ Changes since last deploy (nginx restarted 47 min ago) — web-prod-01

  Memory:   61% → 78%   ⚠️  +17% since restart
  FD count: 4,821 → 12,440  ⚠️  growing after deploy
  IO util:  8% → 62%   ⚠️  elevated

  Unchanged (9 checks): CPU ✅  Disk ✅  Network ✅  Clock ✅  ...

→ Something changed when nginx restarted 47 min ago
```

**Implementation:**
```go
// internal/baseline/since_deploy.go

// DetectLastDeployTime finds the most recent service restart time.
// Checks multiple signals in order — uses whichever returns fastest.
func DetectLastDeployTime() (time.Time, string, error) {
    // Signal 1: systemd service ActiveEnterTimestamp (most accurate)
    // Check the most common services — first one found wins
    for _, svc := range []string{"nginx", "apache2", "caddy", "postgres",
        "mysql", "redis", "docker", "containerd"} {
        if t, err := systemdActiveEnter(svc); err == nil {
            return t, "systemd: " + svc + ".service restarted", nil
        }
    }

    // Signal 2: newest process start time from /proc/<pid>/stat
    // Finds the most recently started long-running process (uptime < 2h)
    if t, svc, err := newestProcessStart(2 * time.Hour); err == nil {
        return t, svc + " process started", nil
    }

    // Signal 3: newest Docker/container restart
    if t, name, err := newestContainerRestart(); err == nil {
        return t, "container " + name + " restarted", nil
    }

    // Signal 4: git log -1 (code deploy signal on dev/staging)
    if t, err := gitLastCommitTime(); err == nil {
        return t, "git: last commit pushed", nil
    }

    return time.Time{}, "", fmt.Errorf("no deploy signal detected")
}

// FindBaselineBeforeTime finds the newest baseline snapshot saved
// before the given time. Falls back to previous baseline if none found.
func FindBaselineBeforeTime(t time.Time, hostname string) (*models.Snapshot, error) {
    dir := filepath.Join(os.Getenv("HOME"), ".dsd", "baselines")
    entries, err := os.ReadDir(dir)
    if err != nil { return nil, err }

    var best *models.Snapshot
    var bestTime time.Time

    for _, e := range entries {
        if !strings.HasPrefix(e.Name(), hostname) { continue }
        info, _ := e.Info()
        if info.ModTime().Before(t) && info.ModTime().After(bestTime) {
            if snap, err := loadSnapshot(filepath.Join(dir, e.Name())); err == nil {
                best = snap
                bestTime = info.ModTime()
            }
        }
    }
    if best == nil {
        return nil, fmt.Errorf("no baseline found before %s", t.Format(time.RFC3339))
    }
    return best, nil
}

// Entry point — called when --since-deploy flag is set
func RunSinceDeployDiff(mode output.OutputMode) error {
    deployTime, signal, err := DetectLastDeployTime()
    if err != nil {
        // Graceful fallback — teach the engineer the habit
        fmt.Printf("ℹ️  No deploy signal detected.
")
        fmt.Printf("    Run dsd health before your next deploy to enable this check.
")
        fmt.Printf("    Or: dsd health --diff  to compare against your last run.
")
        return nil
    }

    hostname, _ := os.Hostname()
    baseline, err := FindBaselineBeforeTime(deployTime, hostname)
    if err != nil {
        // No pre-deploy baseline exists yet
        mins := int(time.Since(deployTime).Minutes())
        fmt.Printf("ℹ️  No pre-deploy baseline found (%s %d min ago).
", signal, mins)
        fmt.Printf("    Run dsd health before your next deploy to enable this check.
")
        fmt.Printf("    Or: dsd health --diff  to compare against your last run.
")
        return nil
    }

    // Run current health check and diff against pre-deploy baseline
    curr := runHealthSnapshot()
    mins := int(time.Since(deployTime).Minutes())
    fmt.Printf("⚡ Changes since last deploy (%s, %d min ago)

", signal, mins)
    return render.PrintDiff(baseline, curr, mode)
}
```

**Key design decisions:**
- Service restart detection uses systemd first (most accurate), falls back to
  `/proc` process start times (works everywhere), then container restarts, then git.
- Baseline matching uses file modification time on `~/.dsd/baselines/` —
  the baseline saved just before the deploy is automatically the right one.
- Both failure modes (no signal, no baseline) produce actionable messages that
  teach the habit. Neither produces an error exit — `--since-deploy` never blocks.
- After one week of running `dsd health` before deploys: works perfectly every time.
- Day 1 with no prior baselines: graceful message, no noise.

**Upgrade path:** "Can I see what changed across deploys this month?"
→ Team plan: 90-day baseline history, deploy timeline, trend charts.

---

### Priority 2 — `--story` : Human-readable system narrative
**Build in:** Phase 1 (renderer only, 2 days)
**Viral mechanic:** Paste virality — engineers paste narratives into post-mortems and Slack
**Revenue path:** Free forever — drives installs through post-mortem sharing

```bash
dsd health --story

# Output:
📋 System narrative — web-prod-01 — 2026-04-15 14:32 UTC

The server is under memory pressure. Available RAM has dropped to 312MB (98% used)
and swap is actively thrashing at 142 pages/sec in, 89 pages/sec out — a pattern
that typically precedes OOM kills within minutes.

Disk IO on sda is saturated at 97% utilization with 180ms await — 9x above the
healthy SSD threshold. Three processes are in uninterruptible D-state sleep,
consistent with IO blocking caused by the disk saturation.

Network, clock, and systemd units are healthy. 9 of 12 checks passed.

Most likely sequence: memory consumer → swap thrashing → IO saturation → hung processes.
Immediate action: ps aux --sort=-%mem | head -10
```

**Implementation:**
```go
// internal/render/story.go
// Pure deterministic template rendering — no LLM, no API call.
// Input: []models.Insight from heuristics engine
// Templates:
//   "memory_pressure" → paragraph about RAM + swap + OOM risk
//   "io_saturation"   → paragraph about disk util + await + D-state correlation
//   "cpu_saturated"   → paragraph about load + cores + process count
//   "network_fault"   → paragraph about interface + gateway + routing
// Severity ordering: CRIT items appear first, WARN items second
// All-healthy template: one sentence — "All 12 checks passed. System healthy."
// --story does NOT use AI — this distinction must be clear in docs and output footer
```

**Note on UnpackOps boundary:** `--story` is deterministic template rendering.
UnpackOps/`--ai` does probabilistic root cause inference. They are different products.
`--story` says "memory is high and swap is thrashing." UnpackOps says "this is probably
a Node.js heap leak in your request handler." Keep that line clear.

---

### Priority 3 — `--post-mortem` : Populated incident template
**Build in:** Phase 1 (renderer only, 1 day)
**Viral mechanic:** Team virality — post-mortems reviewed by entire engineering teams
**Revenue path:** Free template → paid history ("show all incidents last 90 days")

```bash
dsd health --post-mortem "API latency spike 14:30-15:15"

# Output (markdown, paste into Notion/Confluence/GitHub/Linear):
#### Incident: API latency spike 14:30-15:15
**Server:** web-prod-01  |  **Captured:** 2026-04-15 15:22 UTC  |  **By:** dsd v1.2.3

#### System State at Time of Capture
| Check | Status | Value | Threshold |
|---|---|---|---|
| CPU | ⚠️ WARN | load 3.8/4 cores (95%) | > 70% |
| Memory | ❌ CRIT | 312MB free / 16GB (98%) | > 95% |
| Disk IO | ❌ CRIT | sda 97% util, 180ms await | > 85% |
| Systemd | ✅ OK | 0 failed units | — |
| Network | ✅ OK | gateway 2ms, DNS 12ms | — |

#### Heuristic Analysis
- Memory pressure (98%) + active swap thrashing (si=142, so=89/sec) → OOM risk
- IO saturation on sda (97%, 180ms) → 3 processes in D-state
- Likely sequence: memory consumer → swap → IO saturation → hung processes

#### Recommended Investigation Steps
1. `ps aux --sort=-%mem | head -10` — identify top memory consumers
2. `iostat -x 1 5` — confirm IO device and utilization
3. `lsof +L1` — check for deleted-but-open files consuming disk
4. `journalctl -p err --since "2 hours ago"` — check for error patterns

#### Timeline
<!-- Paste: dsd health --diff output here -->

#### Resolution
<!-- Fill in -->

---
*Generated by DashDiag v1.2.3 — https://dashdiag.sh*
```

**Implementation:**
```go
// internal/render/postmortem.go
// --post-mortem "title" activates ModePostMortem in DetectMode()
// Renders full markdown document with:
//   - timestamped header
//   - check results table (all checks, not just failing)
//   - heuristics analysis section (from insights engine)
//   - investigation steps (from hints in each insight)
//   - empty resolution section for engineer to fill
// Automatically uses --out if specified, else stdout
// Footer: "Generated by DashDiag" — brand impression on every post-mortem
```

---

### Priority 4 — `--badge` : GitHub README status badge
**Build in:** Phase 2 (requires dashdiag.sh backend, 3 days + infra)
**Viral mechanic:** Passive virality — badge on popular repos = thousands of impressions
**Revenue path:** Badge account (free) → team dashboard (paid)

```bash
dsd health --badge
# → Badge URL generated: https://img.shields.io/endpoint?url=https://snap.dashdiag.sh/badge/abc123
# → Add to README.md:
#   ![Server Health](https://img.shields.io/endpoint?url=https://snap.dashdiag.sh/badge/abc123)
# → Update badge: add to cron:
#   */5 * * * * dsd health --json | curl -sX POST https://snap.dashdiag.sh/badge/abc123/update -d @-
```

Badge states:
```
[dsd: healthy]     — green   — all checks passed
[dsd: 2 warnings]  — yellow  — WARN checks present
[dsd: 1 critical]  — red     — CRIT checks present
[dsd: stale]       — grey    — not updated in > 10 minutes
```

**Implementation:** shields.io custom endpoint format — DashDiag serves a JSON endpoint
that shields.io polls. Engineer registers a badge token (free dashdiag.sh account),
pushes updates via `--badge`. Backend is a simple key-value store (Redis + tiny API).

---

### Priority 5b — `--report --weekly` / `--report --monthly` : Usage Summary Report (1 day)

Reads entirely from `~/.dsd/state.json` — no collectors, no network, no backend.
Available after one week of runs. Surfaces value the engineer already created but
cannot see. The upgrade prompt is the natural conversion moment.

```bash
$ dsd report --weekly

╔═══════════════════════════════════════════╗
║   DashDiag Weekly Report — web-prod-01    ║
║   Week of Apr 14–20, 2026                 ║
╠═══════════════════════════════════════════╣
║ Checks run:       47   (6.7 / day avg)    ║
║ Issues detected:  12   (8 WARN, 4 CRIT)   ║
║ Most frequent:    Memory WARN  × 8        ║
║ Cleanest day:     Tuesday — all clear     ║
║ Commands used:    health × 40, net × 7   ║
║ Time saved:       ~47 minutes             ║
╚═══════════════════════════════════════════╝

💡 Memory is your most common issue — try: dsd health --diff
   See 90-day history + trends: dashdiag.sh/teams  (Team plan)
```

```bash
$ dsd report --monthly --out april-2026.md
# Saves markdown version for runbooks / retrospectives
```

**Implementation:**
```go
// internal/render/weekly.go
// WeeklyReport reads state.json fields:
//   - total_runs, command_counts   → activity summary
//   - error_exits, shown_milestones → issue frequency
//   - current_streak, last_run_date → consistency
//   - piped_runs                   → scripting usage
// Filters to the last 7 days (--weekly) or 30 days (--monthly)
// by comparing timestamps stored per-run in state.json
//
// No collectors run. No network calls. Reads local state only.
// --out <file> saves as markdown. Default: pretty terminal box.

type WeeklyReport struct {
    Period        string   // "Week of Apr 14–20" or "April 2026"
    ChecksRun     int
    DailyAvg      float64
    IssuesTotal   int
    WarnCount     int
    CritCount     int
    MostFrequent  string   // check name that failed most often
    CleanestDay   string   // day with all OK
    CommandCounts map[string]int
    TimeSavedMin  int      // ChecksRun * 1 (60s per manual check)
    StreakDays    int
}
```

**Why it accelerates conversion:** An engineer who sees "8 Memory WARN this week"
wants to know "what about last month — is this getting worse?" That question is
the Team plan selling itself. The free version shows 7 or 30 days from local state.
The paid version shows unlimited history from dashdiag.sh. Clear, non-coercive
upgrade path at the exact moment of highest perceived value.

**Build trigger:** Available after state.json accumulates 7+ days of data.
If run too early: "Not enough data yet. Run dsd health for 7 days to generate a weekly report."

---

### Priority 5 — `dsd compare` : Side-by-side server comparison
**Build in:** Phase 3 (SSH coordination, 3 days)
**Viral mechanic:** Cluster virality — "which node is the odd one out" shared in every cluster incident
**Revenue path:** Manual compare (free) → automated drift detection (paid fleet tier)

```bash
dsd compare web-prod-01 web-prod-02 web-prod-03

# Output:
⚡ Comparing 3 servers… (SSH, concurrent)

Check            web-prod-01    web-prod-02    web-prod-03
─────────────────────────────────────────────────────────────
CPU load         12%  ✅         89%  ❌         14%  ✅
Memory           62%  ✅         94%  ❌         61%  ✅
Disk /           52%  ✅         52%  ✅         81%  ⚠️
Systemd          ✅ OK           ❌ 1 failed     ✅ OK
Network RTT      2ms  ✅         2ms  ✅         180ms ⚠️
─────────────────────────────────────────────────────────────
Outlier:  web-prod-02 differs on 2/3 critical checks → investigate first
          web-prod-03 differs on 2/3 non-critical checks → lower priority
```

**Implementation:**
```go
// cmd/compare.go
// SSH to each host concurrently, run `dsd health --json`, collect results
// No agent required — dsd binary must be installed on remote hosts
// OR: copy binary temporarily via scp (--no-install flag auto-copies)
// Outlier detection: a host is an outlier if it differs from the majority (>50%)
//   on CRIT/WARN checks. Simple majority vote per check.
// Uses existing SSH key from agent — never prompts for password
```

**Fleet upgrade path:** "I ran `dsd compare` across 3 servers and it was amazing.
Can I schedule this to run every hour and alert me when a server drifts?" = paying customer.

---

### Priority 6 — `--qr` : QR code for mobile/sharing
**Build in:** Phase 1 alongside `--share` (2 hours)
**Viral mechanic:** Surprise virality — unexpected terminal output drives social sharing
**Revenue path:** Indirect — awareness and installs

```bash
dsd health --share --qr

# Terminal output:
⚡ System health (read-only) …
[... health output ...]

📱 Scan to view on mobile or share:
█▀▀▀▀▀█ ▄▀▄ ▄  █▀▀▀▀▀█
█ ███ █ ▄▀█▀▀▄ █ ███ █
█ ▀▀▀ █ ▀▄▄▄▄ █ ▀▀▀ █
▀▀▀▀▀▀▀ ▀ █ ▀ ▀▀▀▀▀▀▀
[QR encodes: https://snap.dashdiag.sh/s/abc123]
```

**Implementation:** Pure Go QR generation — `github.com/skip2/go-qrcode` renders
to terminal using Unicode block characters. No external dependency beyond the library.
Automatically activates when `--share` generates a URL. Can also encode `--report` output.

---

### Viral Features — Summary Table

| Priority | Feature | Phase | Build time | Viral mechanic | Revenue path |
|---|---|---|---|---|---|
| 1 | `--diff` | 1 | 1 day | Comparison — incident diffs in Slack | Local→cloud baseline history |
| 1b | `--since-deploy` | 1 | 0.5 days | Post-deploy habit — zero effort after week 1 | Pre/post deploy history → paid |
| 2 | `--story` | 1 | 2 days | Paste — narrative in post-mortems | Brand/installs |
| 3 | `--post-mortem` | 1 | 1 day | Team — reviewed by whole eng team | History→paid tier |
| 4 | `--badge` | 2 | 3 days + infra | Passive — README impressions | Account→team tier |
| 5 | `dsd compare` | 3 | 3 days | Cluster — "odd one out" sharing | Manual→fleet paid |
| 6 | `--qr` | 1 | 2 hours | Surprise — social screenshot sharing | Awareness/installs |

**Combined Phase 1 viral surface (Priorities 1, 2, 3, 6):** 4 days of renderer work,
no new collectors, no backend. Engineers get `--diff`, `--story`, `--post-mortem`, and
`--qr` from day one. These four features alone give DashDiag a meaningfully different
shareability profile from any existing CLI diagnostic tool.

---

## 19c. Sticky Features — Retention & Habit Formation

Six features that increase daily active usage, build habit, and create natural
upgrade conversations. Ordered by priority: build time vs retention impact.

---

### Priority 1 — Tip of the Day (1 day)

One feature discovery tip, shown after results, once per day maximum.
Rotates through all 12 tips over 12 days then repeats. Never shown on
`--json`, `--plain` piped output, or `--report` mode.

```
$ dsd health

[... health output ...]

💡 Tip: Run `dsd health --diff` to see only what changed since your last check.
   Tip 3 of 12  |  dsd tips (see all)  |  dsd config set tips off (disable)
```

**Tip rotation — 12 tips, one per day:**
```
1.  --diff        "See only what changed since your last check"
2.  --story       "Get a human-readable narrative of system state"
3.  --share       "Share a snapshot URL in Slack — no install needed"
4.  --post-mortem "Generate a pre-filled post-mortem template"
5.  dsd net deep  "Deep network analysis: jitter, bonds, traceroute"
6.  --report      "Markdown output for GitHub issues and Jira tickets"
7.  dsd compare   "Compare health across multiple servers side-by-side"
8.  dsd hook      "Auto-run dsd on SSH login or before deploys"
9.  --watch       "Monitor for changes — refreshes every 60 seconds"
10. --badge       "Embed a live health badge in your README"
11. ~/.dsd.yaml   "Custom thresholds and service checks"
12. dsd full      "Run all checks — the complete picture"
```

**Implementation:**
```go
// internal/tips/tips.go
// State stored in ~/.dsd/state.json:
//   {"last_tip_date": "2026-04-15", "tip_index": 3, "tips_enabled": true}
// Rules:
//   - Only show if tips_enabled == true (default: true)
//   - Only show if today != last_tip_date
//   - Only show in ModeHuman (not --json, --plain, --report)
//   - Show AFTER results output — never before
//   - Update last_tip_date and tip_index after showing
//   - dsd config set tips off → sets tips_enabled = false

func MaybePrintTip(mode output.OutputMode, state *State) {
    if !state.TipsEnabled { return }
    if mode != output.ModeHuman { return }
    if state.LastTipDate == today() { return }

    tip := tips[state.TipIndex % len(tips)]
    fmt.Printf("
💡 Tip: %s
", tip.Message)
    fmt.Printf("   Tip %d of %d  |  dsd tips (see all)  |  dsd config set tips off
",
        state.TipIndex+1, len(tips))

    state.LastTipDate = today()
    state.TipIndex++
    state.Save()
}

// MaybeShowReengagement shows a welcome-back message when an engineer returns
// after 7+ days away. Shown BEFORE health output — a greeting, not an afterthought.
// Only in ModeHuman. Only once per re-engagement gap of 7+ days.
func MaybeShowReengagement(mode output.OutputMode, state *State, version string) {
    if mode != output.ModeHuman { return }
    if state.LastRunDate == "" { return } // first run handled by dsd init

    last, err := time.Parse("2006-01-02", state.LastRunDate)
    if err != nil { return }
    daysSince := int(time.Since(last).Hours() / 24)

    if daysSince < 7 { return }

    fmt.Printf("\n👋 Welcome back! %d days since your last check.\n", daysSince)
    fmt.Println("   → dsd --changelog  to see what is new")
    fmt.Println()
}


``

**Why tips accelerate monetisation:** Tips 3 (`--share`), 8 (`dsd hook`), and 10 (`--badge`)
directly surface paid-tier features. An engineer who discovers `--share` through a tip
and shares their first snapshot is on the conversion path.

---

### Priority 2 — `dsd hook install` — Habit Formation (1 day)

Installs DashDiag into the engineer's existing workflows so it runs without
deliberate intent. The single highest-impact retention feature because it creates
daily active usage automatically.

```bash
$ dsd hook install

Where would you like to install DashDiag?
(↑↓ to move, space to select, enter to confirm)

  ◉  SSH login — show health summary on SSH login        ~/.zshrc
  ○  Pre-deploy script — health check before deploys     check-health.sh
  ○  Git pre-push hook — health check before git push    .git/hooks/pre-push
  ○  systemd timer — run every hour, log results         /etc/systemd/system/
  ○  GitHub Actions — add to CI/CD workflow              .github/workflows/
  ○  Show me the commands (manual setup)
```

**Interactive multi-select using `bubbletea`:**
```go
// cmd/hook.go
// Uses bubbletea multi-select model — the only TUI component in DashDiag.
// Rationale: multi-select with spacebar is standard terminal UX that engineers
// already know from fzf, lazygit, k9s. A numbered prompt requires them to
// re-read options; arrow-key selection is faster and error-free.
//
// Falls back to numbered prompt when:
//   - stdout/stderr is not a TTY (CI, pipes, SSH without terminal allocation)
//   - TERM=dumb or NO_COLOR is set
//   - --plain flag is active
//
// The bubbletea model is only active for the duration of the selection prompt.
// Once the engineer confirms, the model exits and normal output resumes.
// No persistent TUI state — DashDiag remains a snapshot tool.

import "github.com/charmbracelet/bubbletea"

type hookSelectModel struct {
    options  []hookOption
    cursor   int
    selected map[int]bool
    done     bool
}

func (m hookSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "up",   "k": m.cursor = max(0, m.cursor-1)
        case "down", "j": m.cursor = min(len(m.options)-1, m.cursor+1)
        case " ":         m.selected[m.cursor] = !m.selected[m.cursor]
        case "enter":     m.done = true; return m, tea.Quit
        case "ctrl+c":    return m, tea.Quit
        }
    }
    return m, nil
}
```

**Generated outputs:**

```bash
# Option 1 — SSH login (.zshrc snippet):
# DashDiag health check (remove line to disable)
which dsd &>/dev/null && dsd health --plain --compact 2>/dev/null || true

# Option 2 — pre-deploy script:
#!/bin/bash
echo "=== Pre-deploy health check ==="
dsd health --json | dsd policy check --policy .dsd-policy.yaml
[ $? -eq 0 ] && echo "✅ Health check passed" || { echo "❌ Health check failed"; exit 1; }

# Option 5 — GitHub Actions:
- name: Server health check
  run: dsd health --json --out health-${{ github.sha }}.json
  continue-on-error: true
```

**`--dry-run` flag — shows exactly what files would be written, without writing them:**

```bash
$ dsd hook install --dry-run
DRY RUN — no files will be written

Would modify ~/.zshrc:
  + # DashDiag health check on login (remove to disable)
  + which dsd &>/dev/null && dsd health --plain --compact 2>/dev/null || true

Run without --dry-run to apply.
```

```bash
$ dsd init --dry-run
DRY RUN — no files will be written

Would create ~/.dsd.yaml:
  + thresholds:
  +   io_util_warn_pct: 60
  +   io_await_warn_ms_ssd: 1
  + services:
  +   - name: nginx
  +     host: localhost
  +     port: 80

Run without --dry-run to apply.
```

`--dry-run` applies to every operation that writes files: `dsd hook install`,
`dsd init`, and `dsd policy check --policy` (shows which checks would fail
without blocking the deploy). DashDiag's diagnostic commands have no side effects
and do not need `--dry-run` — they are already read-only by design.


**`--dry-run` flag — shows exactly what would be written without writing it:**

```bash
$ dsd hook install --dry-run
DRY RUN — no files will be written

Would modify ~/.zshrc:
  + # DashDiag health check on login (remove to disable)
  + which dsd &>/dev/null && dsd health --plain --compact 2>/dev/null || true

$ dsd init --dry-run
DRY RUN — no files will be written

Would create ~/.dsd.yaml:
  + thresholds:
  +   io_util_warn_pct: 60
  + services:
  +   - name: nginx
  +     host: localhost
  +     port: 80
```

`--dry-run` applies to every file-writing operation: `dsd hook install`,
`dsd init`, and `dsd policy check` (shows which checks would fail without
blocking). Diagnostic commands need no `--dry-run` — they are read-only.

**Why this is the fastest path to paying customers:** The CI hook (option 2) puts
DashDiag in every deploy pipeline. When the team sees the health check in CI they
ask "can we enforce policies?" — that question is Tier 2 (paid policy engine).
The SSH login hook (option 1) creates the daily habit that drives word-of-mouth.

---

### Priority 3 — Usage Milestones (2 hours)

At usage milestones, show a one-time message quantifying value delivered.
Never shown more than once per milestone. Never shown in `--json`/`--plain`/`--report`.

```
$ dsd health

[... health output ...]

🎯 Milestone: 50 checks run across 3 servers.
   Estimated time saved: ~50 minutes of manual checking.
   → Share with your team: dsd health --share
   → Never miss a change: dsd hook install
```

**Milestone triggers:**
```
Run 10:   NPS survey (one-time only, interactive):
           "You've run dsd 10 times. Quick question: how likely are you to
            recommend DashDiag to a colleague? (0-10, Enter to skip)"
           If score given → "Thanks! What would make it a 10? (Enter to skip)"
           Stores result in ~/.dsd/state.json for future product decisions.
           After survey: "💡 Try: dsd health --diff to see what changed"
Run 50:   "50 checks run. ~50 minutes saved. Share with your team: dsd health --share"
Run 100:  "100 checks! DashDiag has become part of your workflow."
           "→ Automate it: dsd hook install"
Run 500:  "500 checks across your infrastructure."
           "→ Ready for your whole team? dashdiag.sh/teams"

Streak 7:  "7-day streak ⚡ — dsd has become part of your daily workflow."
           (shown once when current_streak first hits 7, not every day)
Streak 30: "30-day streak 🔥 — you're a DashDiag power user."
           "→ Try dsd health --diff to track changes over time"

Pro trial trigger: when total_runs >= 10 AND current_streak >= 5 AND trial_offered == false:
   "You've run dsd 10+ times this week. Want a 14-day Team plan trial? (free, no card needed)"
   "→ dsd trial start  |  Enter to skip"
   Sets trial_offered = true. Only offered once.

Streak 7:  "7-day streak ⚡ — dsd is now part of your daily workflow."
           (shown once when current_streak first hits 7, never repeated)
Streak 30: "30-day streak 🔥 — you are a DashDiag power user."
           "→ Try: dsd health --diff  |  dsd health --story"

Pro trial auto-trigger:
  When: total_runs >= 10 AND current_streak >= 5 AND trial_offered == false
  Show: "You've run dsd 10+ times this week. Want a free 14-day Team plan trial?"
        "→ dsd trial start  |  Enter to skip"
  Sets: trial_offered = true (only offered once ever)

```

**Implementation:**
```go
// internal/tips/milestones.go
// Stored in ~/.dsd/state.json:
//   {
//     "total_runs": 51,
//     "shown_milestones": [10, 50],
//     "last_tip_date": "2026-04-15",
//     "tip_index": 3,
//     "tips_enabled": true,
//     "nps_done": false,
//     "nps_score": "",
//     "nps_reason": "",
//     "hook_installed": false,
//     "current_streak": 7,         // consecutive days with at least one run
//     "longest_streak": 12,        // all-time longest streak
//     "last_run_date": "2026-04-15",
//     "trial_offered": false,      // 14-day pro trial offered flag
//     "piped_runs": 8,             // runs where stdout was non-TTY (scripting signal)
//     "last_policy_failure": {},   // stored last policy check failure for --recheck
//     "last_version": "v1.2.0",   // version at last run — for re-engagement "what's new" message
//     "command_counts": {}        // per-command run counts: {"health": 40, "net": 8, "k8s": 3}
//     "error_exits": 3,            // count of exit-code-2 (CRIT/error) runs
//     "total_commands": 51         // per-command counters: {"health": 40, "net": 8, "k8s": 3}
//   }
// Minutes saved = total_runs * 1 (average 60s of manual checking per run)

var milestones = []int{10, 50, 100, 500, 1000}

// NPS survey — shown once at run 10, stored in state.json
// Only in ModeHuman (never --json, --plain, --report, non-TTY)
func MaybeRunNPS(state *State, mode output.OutputMode) {
    if state.NPSDone { return }
    if state.TotalRuns != 10 { return }
    if mode != output.ModeHuman { return }
    if !isaTTY() { return }

    fmt.Println("
📊 Quick question (takes 10 seconds):")
    fmt.Println("   How likely are you to recommend DashDiag to a colleague?")
    fmt.Print("   Score 0-10 (Enter to skip): ")

    var score string
    fmt.Scanln(&score)

    if score != "" {
        fmt.Print("   Thanks! What would make it a 10? (Enter to skip): ")
        var reason string
        fmt.Scanln(&reason)
        // Store locally — optionally POST to dashdiag.sh/nps if --share account exists
        state.NPSScore  = score
        state.NPSReason = reason
    }

    state.NPSDone = true
    state.Save()
    fmt.Println() // spacing before tip
}

func MaybePrintMilestone(state *State, mode output.OutputMode) {
    if mode != output.ModeHuman { return }
    state.TotalRuns++

    // Update streak: if last run was yesterday or today, increment; else reset
    today := time.Now().Format("2006-01-02")
    yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")

    // Re-engagement message: welcome back after 7+ days away
    // Shown BEFORE health output — it is a greeting, not an afterthought
    if state.LastRunDate != "" && state.LastRunDate != today && state.LastRunDate != yesterday {
        lastRun, _ := time.Parse("2006-01-02", state.LastRunDate)
        daysSince := int(time.Since(lastRun).Hours() / 24)
        if daysSince >= 7 && mode == output.ModeHuman {
            fmt.Printf("
👋 Welcome back! %d days since your last check.
", daysSince)
            // Show what is new if version changed since last run
            if state.LastVersion != "" && state.LastVersion != version.Version {
                fmt.Printf("   New in %s: see `dsd --changelog`
", version.Version)
            }
            fmt.Println()
        }
    }

    switch state.LastRunDate {
    case today:
        // Already ran today — no streak change
    case yesterday:
        state.CurrentStreak++
        if state.CurrentStreak > state.LongestStreak {
            state.LongestStreak = state.CurrentStreak
        }
    default:
        state.CurrentStreak = 1 // streak broken or first run
    }
    state.LastRunDate = today

    // Streak milestones — shown once when streak first hits threshold
    for _, threshold := range []int{7, 30} {
        if state.CurrentStreak == threshold && !state.HasShownStreak(threshold) {
            printStreakMilestone(threshold)
            state.MarkStreak(threshold)
        }
    }

    // Pro trial auto-trigger: power-user pattern detected
    if state.TotalRuns >= 10 && state.CurrentStreak >= 5 && !state.TrialOffered {
        printTrialOffer()
        state.TrialOffered = true
    }

    // Run count milestones
    for _, m := range milestones {
        if state.TotalRuns == m && !state.HasShownMilestone(m) {
            printMilestone(m, state.TotalRuns)
            state.MarkMilestone(m)
            break // only one milestone per run
        }
    }
    state.Save()
}

func printStreakMilestone(days int) {
    switch days {
    case 7:
        fmt.Println("
⚡ 7-day streak — dsd is part of your daily workflow.")
        fmt.Println("   → Try: dsd health --diff  to track what changes day to day")
    case 30:
        fmt.Println("
🔥 30-day streak — you are a DashDiag power user.")
        fmt.Println("   → Try: dsd health --story  for a narrative of today's state")
    }
}

func printTrialOffer() {
    fmt.Println("
🎁 You've run dsd 10+ times this week.")
    fmt.Println("   Want a free 14-day Team plan trial? No card needed.")
    fmt.Print("   → dsd trial start  |  Enter to skip: ")
    var input string
    fmt.Scanln(&input)
    if strings.TrimSpace(input) == "" { return }
    fmt.Println("   → Run: dsd trial start")
}
```

**The run-500 milestone message** ("Ready for your whole team? dashdiag.sh/teams")
is the natural upgrade prompt. An engineer at 500 runs is a habitual user — the exact
person who becomes a team-tier paying customer.

---

### Priority 4 — `dsd init` — First-Run Wizard (2 days)

Runs automatically on first invocation only. Detects server type from running
processes and suggests a matching config profile. Then runs the first health check
immediately — value from the first minute, not after configuration.

```bash
$ dsd  # first run on new server

👋 First run on this server. Quick setup — ~30 seconds.

Detected processes: nginx, postgres
Suggested profile: Web + Database server

Apply this profile?
  ✅ IO thresholds tuned for SSD (your /dev/nvme0n1)
  ✅ Services check: nginx:80, nginx:443, postgres:5432
  ✅ Disk warn at 80%, crit at 90% (standard)

(↑↓ to move, enter to confirm)
❯ Yes, apply suggested profile
  No, use generic defaults
  Customise thresholds manually

✅ Profile saved to ~/.dsd.yaml
⚡ Running first health check…
[health output follows immediately]
```

**Interactive single-select using `bubbletea` — the profile confirmation step:**
```go
// internal/init/firstrun.go
// Uses bubbletea for the profile selection prompt.
// Three choices rendered as an arrow-key menu — no typing, no mis-keying.
// Falls back to Y/N/C prompt when not a TTY (non-interactive SSH, CI).
//
// The wizard has two bubbletea prompts:
//   1. Profile confirmation (single-select: apply / defaults / customise)
//   2. Customise mode: multi-value threshold editor (only if engineer chose C)
//
// Both prompts use the same bubbletea instance as dsd hook install.
// Extract to internal/tui/select.go as a reusable component — both the
// init wizard and the hook installer use the same arrow-key selection model.

// internal/tui/select.go — shared reusable component
type SingleSelect struct {
    Title   string
    Options []string
    cursor  int
    chosen  int
    done    bool
}

func (s SingleSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "up",   "k": s.cursor = max(0, s.cursor-1)
        case "down", "j": s.cursor = min(len(s.Options)-1, s.cursor+1)
        case "enter":     s.chosen = s.cursor; s.done = true; return s, tea.Quit
        case "ctrl+c":    return s, tea.Quit
        }
    }
    return s, nil
}

func (s SingleSelect) View() string {
    var b strings.Builder
    for i, opt := range s.Options {
        if i == s.cursor {
            b.WriteString("❯ " + opt + "
")
        } else {
            b.WriteString("  " + opt + "
")
        }
    }
    return b.String()
}
```

**`internal/tui/select.go` — shared component used by both wizards:**

Both `dsd init` and `dsd hook install` import the same `tui.SingleSelect` and
`tui.MultiSelect` components. This is the only TUI code in the entire project.
It lives in `internal/tui/` and is used nowhere else — DashDiag remains a
snapshot tool. The bubbletea dependency is already in `go.mod` (lipgloss requires it).

**Auto-detection logic:**
```go
// internal/init/detector.go
// CloudEnvironment identifies the hosting environment for threshold adjustment.
// Detection is file-read-only (< 5ms) unless all file methods fail,
// in which case a single metadata endpoint call is made (150ms timeout).
type CloudEnvironment int
const (
    EnvUnknown      CloudEnvironment = iota
    EnvBareMetal                     // on-prem, no cloud signatures
    EnvAWSEBS                        // AWS with network-attached EBS storage
    EnvAWSNVMe                       // AWS instance with local NVMe (c5d, m5d, etc.)
    EnvGCP                           // Google Cloud Platform
    EnvAzure                         // Microsoft Azure
    EnvDigitalOcean                  // DigitalOcean Droplet
)

// DetectCloudEnvironment reads DMI/hypervisor files first (< 1ms each),
// falls back to metadata endpoint only if all file reads are inconclusive.
func DetectCloudEnvironment() CloudEnvironment {
    // Method 1: DMI product name (most reliable, no network)
    if b, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
        name := strings.ToLower(string(b))
        switch {
        case strings.Contains(name, "google compute"):
            return EnvGCP
        case strings.Contains(name, "microsoft azure"):
            return EnvAzure
        case strings.Contains(name, "amazon ec2"):
            return detectAWSStorageType()
        case strings.Contains(name, "droplet"):
            return EnvDigitalOcean
        }
    }
    // Method 2: BIOS vendor
    if b, err := os.ReadFile("/sys/class/dmi/id/bios_vendor"); err == nil {
        if strings.Contains(strings.ToLower(string(b)), "amazon") {
            return detectAWSStorageType()
        }
    }
    // Method 3: Xen hypervisor UUID (older AWS)
    if b, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil {
        if strings.HasPrefix(string(b), "ec2") {
            return detectAWSStorageType()
        }
    }
    // Method 4: cloud-init instance data
    if _, err := os.Stat("/run/cloud-init/instance-data.json"); err == nil {
        return EnvUnknown // cloud-init present but provider unclear — conservative
    }
    // Method 5: metadata endpoint (last resort, 150ms timeout)
    // Only reached on servers where no file evidence was found
    ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
    defer cancel()
    req, _ := http.NewRequestWithContext(ctx, "GET",
        "http://169.254.169.254/latest/meta-data/", nil)
    if resp, err := http.DefaultClient.Do(req); err == nil {
        resp.Body.Close()
        return detectAWSStorageType() // metadata endpoint responded
    }
    return EnvBareMetal
}

// detectAWSStorageType distinguishes EBS from local NVMe by checking block devices.
// Instance store NVMe devices appear as /dev/nvme*n1 with model "Amazon EC2 NVMe".
func detectAWSStorageType() CloudEnvironment {
    entries, err := os.ReadDir("/sys/block")
    if err != nil { return EnvAWSEBS }
    for _, e := range entries {
        if !strings.HasPrefix(e.Name(), "nvme") { continue }
        model, err := os.ReadFile("/sys/block/" + e.Name() + "/device/model")
        if err != nil { continue }
        if strings.Contains(string(model), "Instance Storage") {
            return EnvAWSNVMe
        }
    }
    return EnvAWSEBS
}

func DetectServerProfile() Profile {
    procs := runningProcessNames() // parse /proc/[0-9]*/comm
    cloud := DetectCloudEnvironment()

    switch {
    case contains(procs, "nginx", "apache2", "caddy"):
        return WebServerProfile.WithCloud(cloud)
    case contains(procs, "postgres", "mysqld", "redis-server"):
        return DatabaseProfile.WithCloud(cloud)
    case contains(procs, "kubelet"):
        return KubernetesNodeProfile.WithCloud(cloud)
    case contains(procs, "pvecheckd", "pvedaemon"):
        return ProxmoxProfile.WithCloud(cloud)
    default:
        return GeneralProfile.WithCloud(cloud)
    }
}
```

**First-run gate:**
```go
// internal/init/firstrun.go
func IsFirstRun() bool {
    _, err := os.Stat(os.ExpandEnv("$HOME/.dsd/state.json"))
    return os.IsNotExist(err)
}
// After wizard: create ~/.dsd/state.json with initial state
// Wizard never runs again on this machine
```

---

### Priority 5 — `dsd health --watch` — Incident Monitoring Mode (1 day)

Repeating health check that shows only changes from run to run.
Designed for use during active incidents — "keep this open while you work."

```bash
$ dsd health --watch
# Default: refresh every 60s. Override: --watch=30s

⚡ System health — watching (read-only, Ctrl+C to exit)
   Refresh: every 60s  |  Started: 14:32:11

   ✅ All 12 checks passing — watching for changes…

   14:33:45  ⚠️  Memory: 82% → 94%  (+12% in 60s)
             → ps aux --sort=-%mem | head -10

   14:34:45  ❌  Memory: 94% → 98%  (still growing — OOM imminent)
             ❌  Systemd: nginx.service → failed
             → dsd health deep  (full picture)
             → journalctl -u nginx -n 50 -xe
```

**Implementation:**
```go
// cmd/health.go — --watch flag
var watchInterval time.Duration

func runWatch(cmd *cobra.Command, args []string) {
    ticker := time.NewTicker(watchInterval)
    defer ticker.Stop()

    var prev models.Snapshot
    first := true

    for {
        curr := runHealthSnapshot(ctx, cols)

        if first {
            renderer.PrintFull(curr)   // first run: show everything
            first = false
        } else {
            changes := diff.Compute(prev, curr)
            if len(changes) == 0 {
                renderer.PrintWatchIdle(curr.Timestamp)
            } else {
                renderer.PrintWatchDiff(curr.Timestamp, changes)
            }
        }
        prev = curr
        <-ticker.C
    }
}
```

**--watch vs monitoring tools:** `--watch` is a snapshot repeated, not a monitoring
agent. It has no persistent storage, no alerting, no daemon. It is the "stare at the
terminal during an incident" mode. Engineers who use `--watch` during incidents and
find it useful become internal advocates who push for team adoption.

---

### Priority 6 — `dsd examples` — Real-World Workflow Discovery (4 hours)

Engineers who see concrete workflows convert faster than engineers who see feature lists.
`dsd examples` shows 6 real-world usage patterns with actual commands — not docs, not flags,
but the exact sequence an experienced engineer would run in each scenario.

```bash
$ dsd examples

⚡ DashDiag — Real-World Workflows

1) Incident triage — "something is wrong, what's happening?"
   $ dsd health                          # start here
   $ dsd health --diff                   # what changed?
   $ dsd health --story                  # explain it to me
   $ dsd health --post-mortem "title"    # document it

2) Pre-deployment checklist
   $ dsd health deep                     # thorough check
   $ dsd health --json | dsd policy check --policy .dsd-policy.yaml

3) Network investigation
   $ dsd net                             # is it working?
   $ dsd net deep                        # why is it slow?

4) Share with team during incident
   $ dsd health --share                  # URL for Slack
   $ dsd health --report                 # markdown for GitHub

5) Kubernetes cluster check
   $ dsd k8s                             # snapshot
   $ dsd k8s deep                        # full audit

6) Set up daily automation
   $ dsd hook install                    # SSH login / CI / git hook

Run any command with --help for full options.
→ dsd examples --scenario incident  (show only scenario 1)
```

**Implementation:**
```go
// cmd/examples.go — 50 lines, pure output, no collectors
// --scenario flag filters to one workflow
// dsd examples is the marketing page inside the tool
// Engineers who run dsd examples and see scenario 2 (pre-deploy policy gate)
// ask "how do I set up the policy file?" — that question leads to paid tier
```

---

### Sticky Features — Summary Table

| Priority | Feature | Build time | Retention mechanic | Conversion path |
|---|---|---|---|---|
| 1 | Tip of the day | 1 day | Feature discovery | Tips surface paid features (--share, --badge, hook) |
| 2 | `dsd hook install` | 1 day | Daily habit automation | CI hook → policy gate → Tier 2 paid |
| 3 | Usage milestones | 2 hours | Identity + value proof | Run-500 message → team upgrade |
| 4 | `dsd init` wizard | 2 days | First-run retention | Configured tool → higher daily engagement |
| 5 | `--watch` mode | 1 day | Incident habit | Incident use → team advocacy → adoption |

**Combined impact:** Priorities 1–3 take ~2.5 days total to build and together
address the three biggest retention levers: feature discovery (tips), daily habit
(hook), and upgrade trigger (milestones). Build these before `dsd init` and `--watch`.

---

## 20. Plugin Architecture

The plugin model enables community extension without bloating core. Pattern: `dsd-<module>` executables on `$PATH`.

### How It Works
```bash
# Core discovers plugins automatically
$ which dsd-postgres   # → /usr/local/bin/dsd-postgres
$ dsd postgres check   # → core calls dsd-postgres with standard args

# Community plugin example
$ dsd redis check      # → calls dsd-redis if installed
$ dsd kafka status     # → calls dsd-kafka if installed
```

### Plugin Contract
Every plugin must:
1. Accept `--json` flag and output a valid `[]CheckResult` JSON array
2. Accept `--plain` flag and suppress all emoji/color/ANSI output
3. Accept `--report` flag and output markdown-table format
4. Auto-detect TTY: activate plain mode automatically when stdout is not a terminal
5. Accept `--help` and print usage
6. Exit `0` (all pass), `1` (warnings), `2` (critical)
7. Be a static binary or self-contained script
8. Status values must be one of: `OK` / `WARN` / `CRIT` / `INFO` / `PENDING`

### Plugin Development Prompt
```
Prompt:
"Write a DashDiag plugin binary called 'dsd-postgres' in Go.
It must implement the standard plugin contract:
  - Connect to PostgreSQL using connection string from env var DSN or --dsn flag
  - Check: connection reachability, active connections vs max_connections,
    replication lag (if replica), long-running queries > 30s
  - Output []CheckResult as JSON when --json flag is set
  - Output human-readable colored table by default
  - Exit 0/1/2 based on severity
Use the same models.CheckResult struct from DashDiag core."
```

### Future Plugin Registry
Once 10+ community plugins exist, create `dsd registry`:
```
dsd plugin list           # show available plugins
dsd plugin install redis  # download dsd-redis binary
dsd plugin update --all   # update all installed plugins
```

---

## 21. Deterministic Heuristics — Smart Without AI

These deterministic rules make DashDiag feel smart without any AI dependency. They ship in MVP and are the correct level of intelligence for a fast, offline, read-only CLI tool.

```go
// internal/analysis/heuristics.go

func Analyze(snapshot models.Snapshot) []models.Insight {
    var insights []models.Insight

    // IO-bound detection
    if snapshot.IO.WaitPercent > 40 && snapshot.CPU.UsagePercent < 30 {
        insights = append(insights, models.Insight{
            Level:   "WARN",
            Message: "High IO wait with low CPU — likely IO-bound workload",
            Hints:   []string{"iostat -x 1 5", "iotop -ao", "lsof +D /"},
        })
    }

    // Memory pressure
    if snapshot.Memory.FreePercent < 5 && snapshot.Memory.SwapUsedPercent > 50 {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: "Memory pressure — swap in use, risk of OOM",
            Hints:   []string{"ps aux --sort=-%mem | head -10", "dmesg | grep -i oom"},
        })
    }

    // CPU saturation
    if snapshot.CPU.LoadAvg1 > float64(snapshot.CPU.Cores)*0.9 {
        insights = append(insights, models.Insight{
            Level:   "WARN",
            Message: fmt.Sprintf("CPU saturated: load %.1f on %d cores",
                snapshot.CPU.LoadAvg1, snapshot.CPU.Cores),
            Hints:   []string{"top -bn1 | head -20", "pidstat 1 5"},
        })
    }

    // Network isolation
    if !snapshot.Network.GatewayReachable && snapshot.Network.InterfacesUp > 0 {
        insights = append(insights, models.Insight{
            Level:   "CRIT",
            Message: "Interfaces UP but gateway unreachable — routing issue",
            Hints:   []string{"ip route show", "cat /proc/net/route"},
        })
    }

    return insights
}
```

**AI prompt for heuristics expansion:**
```
Prompt:
"Extend internal/analysis/heuristics.go with 10 more detection rules for:
- Disk inode exhaustion (inodes_used > 90% without disk_space issue)
- High network errors/drops on any interface
- Too many TIME_WAIT connections (> 1000)  
- Swap in active use on a machine with > 50% free RAM (memory leak signal)
- Clock skew detection (system time vs NTP drift > 5 seconds)
- Load spike (load_avg_1 >> load_avg_15 by 3x — sudden spike vs sustained)
Each rule returns a Hint with 2-3 suggested next commands."
```

---

## 22. MVP Launch Validation Checklist

Run this after shipping v0.1. Do NOT expand to Phase 2 until 3+ of these are true.

```
✅ Validation signals — check weekly after launch:

[ ] I use dsd health myself every day without thinking about it
[ ] Someone shared a dsd output screenshot in Slack/Discord/LinkedIn
[ ] A GitHub issue requests a feature I didn't plan (signal: real users with real needs)
[ ] Someone opened a PR to fix something (signal: community trust)
[ ] An SRE/DevOps engineer pasted dsd output into an incident ticket
[ ] r/devops or r/sysadmin post generated >50 upvotes
[ ] Someone asked to add it to their team's onboarding runbook
[ ] A company's internal wiki links to dsd install instructions
```

### Phase Gate Checklist

Before building any `deep` variant or next phase, answer these:

```
Before dsd health deep:
  [ ] dsd health used daily by at least one engineer (including me)
  [ ] At least one real incident where dsd health output was shared in Slack
  [ ] Engineers asking "can I see per-core CPU / more memory detail?"

Before dsd net deep:
  [ ] dsd net used during at least one real network investigation
  [ ] Engineers asking for jitter data or traceroute

Before dsd docker:
  [ ] dsd health in daily use
  [ ] Engineers asking "can it check my containers?"

Before dsd k8s:
  [ ] dsd docker in use
  [ ] Engineers asking about Kubernetes support

Before dsd k8s deep:
  [ ] dsd k8s used in at least 3 real K8s incidents
  [ ] Engineers asking about BestEffort pods / throttling / namespace enforcement

Rule: a GitHub issue requesting the feature counts as permission to build it.
Silence means the feature is not needed yet.
```



### Success Pattern References
These tools all followed the same adoption arc you're targeting:

| Tool | What it replaced | Stars | Time to traction |
|---|---|---|---|
| `bat` | `cat` | 50k+ | 6 months after launch |
| `eza` / `exa` | `ls` | 12k+ | ~1 year |
| `fd` | `find` | 35k+ | 6 months |
| `ripgrep` | `grep` | 50k+ | 3 months (Rust perf angle) |
| `lazydocker` | `docker ps` + TUI | 40k+ | Fast — novelty of Docker TUI |
| `k9s` | `kubectl` TUI | 28k+ | 1 year |
| `fastfetch` | `neofetch` | 12k+ | 6 months |
| `zoxide` | `cd` | 25k+ | 1 year |

**Common pattern:** single focused problem → beautiful output → one-liner install → GitHub trending → community plugins/extensions. DashDiag follows the same path.

---

## 23. Success Metrics

### Awareness & Growth

| Metric | 3 months | 6 months | 12 months |
|---|---|---|---|
| GitHub Stars | 500 | 1,000–2,000 | 5,000–10,000 |
| Monthly active installs | 500 | 5,000 | 20,000+ |
| Community plugins | — | 5 | 20+ |
| Contributors | 2 | 8 | 25+ |
| Integrations | Homebrew tap | GitHub Action | Prometheus exporter |
| Press | — | Dev.to / Hashnode | The New Stack / DevOps.com |
| Business | — | Sponsorships | First paying team tier |

### Retention & Conversion (freemium-specific)

These are the metrics that predict revenue, not just awareness. Track from day one.

| Metric | Definition | Target | How to measure |
|---|---|---|---|
| Activation rate | First `dsd health` completes < 5 min from install | > 70% | install timestamp vs first run in state.json |
| D7 retention | Engineer runs dsd again within 7 days of first run | > 40% | state.json total_runs + last_run_date |
| D30 retention | Still running dsd 30 days after install | > 20% | same |
| NPS | Survey score at run-10 | > 40 | state.json nps_score, optional POST to dashdiag.sh |
| Free → paid conversion | Free users who upgrade to Team tier | 5–8% | dashdiag.sh backend |
| Hook install rate | % of users who run `dsd hook install` | > 15% | state.json hook_installed flag |
| `--share` usage rate | % of runs that use `--share` | > 5% | dashdiag.sh endpoint logs |
| `--since-deploy` usage | % of runs after a detected deploy | > 20% | detect in state.json |
| Snapshot click-through | % of shared URLs opened by others | > 60% | dashdiag.sh analytics |
| `--json` pipe rate | % of runs where stdout is piped (non-TTY) | > 10% | detect non-TTY stdout in state.json |
| Tab completion rate | % of invocations via shell completion | > 30% | detect `COMP_LINE` env var set |
| Command success rate | % of runs exiting 0 or 1 (not error/crash) | > 95% | `error_exits` counter in state.json |
| Feature stickiness | DAU/MAU ratio per command | > 10% for `dsd health` | `command_counts` in state.json |
| `--json` pipe rate | % of runs where stdout is piped (non-TTY) | > 10% | detect in state.json: `os.Stdout` is non-TTY |
| Tab completion rate | % of invocations via shell completion | > 30% | detect `COMP_LINE` env var set at invocation |

**D7 retention is the most important single metric.** A user who does not return within 7
days almost certainly never will. If D7 < 30%, the first-run experience needs work before
anything else is built. Fix onboarding first, then invest in later-stage retention.

**`--json` pipe rate > 10%** means engineers are scripting DashDiag into their workflows.
Scripting users are highest-LTV customers — they build automation around the tool,
hit usage limits faster, and upgrade teams rather than individuals.
Detect by checking whether `os.Stdout` is a TTY at invocation time and incrementing
a `piped_runs` counter in `state.json`.

**Tab completion rate > 30%** means engineers have installed shell completions and
are using the tool as a native shell citizen. This is a strong power-user signal.
Detect by checking if `COMP_LINE` or `COMP_POINT` env vars are set at invocation
(these are always set by bash/zsh during tab-completion expansion).


**`--json` pipe rate > 10%** means engineers are scripting DashDiag.
Scripting users are highest-LTV — they build automation, hit limits, and upgrade teams.
Detect: check if `os.Stdout` is non-TTY at invocation, increment `piped_runs` in state.json.

**Tab completion rate > 30%** indicates power-user shell integration.
Detect: check if `COMP_LINE` env var is set at invocation time.

**Command success rate < 95%** is a warning sign — either the tool is confusing
(engineers run it wrong repeatedly) or every server it checks is genuinely unhealthy
(which means the tool is working but the environment needs attention). Either way,
a drop below 95% is worth investigating. Track `error_exits` in state.json.

**Feature stickiness (DAU/MAU per command)** tells you which commands are habits vs
one-off investigations. `dsd health` should have high DAU/MAU (daily habit). `dsd security`
and `dsd logs` will have lower DAU/MAU — that is expected and correct for investigation
tools. If `dsd net` has low stickiness, the output may not be compelling enough.
Track via `command_counts` in state.json: `{"health": 40, "net": 8, "k8s": 3}`.


**Command success rate < 95%** is a warning sign — either the tool is confusing
(engineers run it wrong repeatedly) or every server checked is genuinely unhealthy.
Either way, a drop below 95% is worth investigating. Track `error_exits` in state.json.

**Feature stickiness (DAU/MAU per command)** tells you which commands are daily habits
vs one-off investigations. `dsd health` should have high DAU/MAU. `dsd security` and
`dsd logs` will have lower DAU/MAU — expected for investigation tools.
Track via `command_counts` in state.json: `{"health": 40, "net": 8, "k8s": 3}`.

**NPS at run-10 tells you if you have a word-of-mouth problem** before it becomes a
growth problem. Score < 30: engineers will not recommend it — find out why immediately.
Score > 50: engineers are enthusiastic — double down on shareability and referral mechanics.

**The leading indicator to watch:** Engineers sharing `dsd` output screenshots in Slack
incidents or GitHub issues. When that starts happening, double down on output aesthetics
and shareability before adding more checks.

---

## 24. Quick Reference — Complete Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Go 1.22+ | Static binary, fast, strong stdlib, DevOps ecosystem |
| CLI framework | `cobra` + `viper` | Industry standard (kubectl, helm, gh); viper for config |
| Terminal UI | `lipgloss` + `bubbletea` | Best-in-class Charm ecosystem |
| TUI scope | `internal/tui/select.go` only | Arrow-key menus for `dsd init` + `dsd hook` wizards only — nowhere else |
| System metrics | `gopsutil/v3` | Cross-platform CPU/mem/disk/net, battle-tested |
| ICMP Ping | `go-ping` | Privileged + unprivileged modes, RTT statistics |
| Network suite | `gns` | Gateway, DNS, public IP — no shelling out |
| Traceroute | `nexttrace` | Multi-protocol, ASN whois, 6k+ stars |
| Container | Docker SDK for Go | One client handles Docker + Podman (same API); containerd/CRI-O detected-only |
| Kubernetes | `client-go` + `metrics.k8s.io` | Node conditions, OOMKill, evictions, CrashLoop, ImagePull, Pending, PVC binding, CoreDNS, deployments, events |
| Tables | `tablewriter` | Clean terminal table rendering |
| Color | `lipgloss` or `fatih/color` | lipgloss for full UI, fatih/color for quick coloring |
| Output modes | `internal/output/tty.go` | `DetectMode()` resolves human/plain/report/json; `StatusIcon()` returns correct symbol per mode |
| Heuristics | `internal/analysis` | Deterministic pre-AI insights, ships in v1 |
| AI analysis | deferred | See §25 Possible Future Development |
| Plugins | `dsd-<module>` on PATH | Community extensibility without core coupling |
| Releases | GoReleaser + GitHub Actions | One config, all platforms, checksums auto-generated |
| Distribution | curl install script + Homebrew + apt/yum | DevOps-standard multi-path install |
| Config | `~/.dsd.yaml` via viper | User-configurable thresholds without recompiling |
| Version | `internal/version` + ldflags | Build-time injection of version/commit/date |
| Container ctx | `internal/platform/container.go` | cgroup v1/v2 memory+CPU limits, container detection |
| Permissions | `pingWithFallback()` | CAP_NET_RAW → UDP ICMP → skip gracefully |
| NTP check | `timedatectl` / `chronyc` / systemd | Clock sync and offset — one of top prod failure causes |
| FD limits | `/proc/sys/fs/file-nr` + `/proc/[PID]/limits` + `/proc/[PID]/fd` | System-wide + per-process FD exhaustion + deleted-but-open files |
| Linting | `staticcheck` + `golangci-lint` | `go vet`, `gosec`, `errcheck`, `ineffassign` in CI |
| Testing | golden files + `-race` flag | Renderer regression tests + race condition detection |
| Fuzzing | `go test -fuzz` | Parser panic prevention on malformed `/proc`+`/sys` input |
| E2E | `testcontainers-go` | Real binary in real containers (ubuntu/alpine/ubi8) |
| Contract | JSON Schema + `jsonschema` | `--json` output schema stability across versions |
| Security CI | `govulncheck`+`gosec`+`semgrep`+`gitleaks` | Vuln DB + SAST + secret scanning |
| SBOM | `syft` + `grype` | Supply chain visibility + vulnerability scan on release |
| Signing | `cosign` (Sigstore) | Binary signature verification for end users |
| QR codes | `github.com/skip2/go-qrcode` | Terminal QR output for `--qr` flag |
| Tips engine | `internal/tips` | Feature discovery, milestone messages, streak tracking, pro trial trigger |
| Init wizard | `internal/init` | First-run server detection + profile setup |
| Cloud detect | `internal/platform/cloud.go` | AWS/GCP/Azure/bare-metal via DMI files + metadata fallback |
| Hook installer | `cmd/hook.go` | CI/SSH/git/systemd integration wizard |
| Baseline diff | `internal/baseline` | Save/compare snapshots for `--diff` flag |
| YAML output | `gopkg.in/yaml.v3` | `--yaml` flag — marshal same structs as `--json` |
| Licenses | `go-licenses` | GPL/AGPL incompatibility detection before publish |
| Proxmox | `pvesh`, `zpool`, `qm`, `pct`, `corosync-quorumtool` | Host checks via exec + /sys/block; graceful fallback for each |
| Per-core CPU | `/sys/bus/platform/drivers/coretemp/` + `/sys/devices/system/cpu/` | Temperature + frequency + throttle detection |
| SMART | `smartctl` (smartmontools) | Disk health: overall + reallocated sectors; graceful if missing |
| Services | `net.Dialer` + `http.Client` | TCP connect + HTTP GET; concurrent; configurable via ~/.dsd.yaml |
| Progress bar | `internal/models.ProgressBar()` | Locked 16-char spec: `[████████--------] 50%` |
| Log analysis | `journalctl` + grep fallback | Error aggregation, top-3 recurring messages, 60m window |
| Security posture | `ss`, `/etc/ssh/sshd_config`, `/etc/sudoers`, `find /etc` | Read-only config checks; never scans or probes |
| Process health | `/proc/[0-9]*/stat` | Zombie (Z) and hung (D-state) detection |
| Systemd units | `systemctl list-units --state=failed,activating` | Failed and stuck service detection |
| Kernel params | `/proc/sys/` (no exec) | somaxconn, pid_max, swappiness — read-only |
| kernel security | `getenforce` + `/sys/module/apparmor` | SELinux/AppArmor mode + recent AVC denials |
| Memory slab | `/proc/meminfo` Slab/CommitLimit | Kernel cache growth and overcommit detection |
| Journal size | `journalctl --disk-usage` | Journal disk consumption |

---

## 25. Possible Future Development

This section preserves ideas that were deliberately removed from the current scope. They are not rejected — they are deferred until DashDiag has an established user base and a clear product strategy. Nothing here should be built until the core tool (Phases 1–3) is complete and used daily.

---

### F1 — AI-Assisted Diagnostic Analysis (`--ai` flag)

**What it would do:** Feed the structured `--json` snapshot to an LLM and return natural-language root-cause analysis and suggested remediation steps.

**Example of what it would produce:**
```
⚠️  AI Analysis:
    Node has high disk IO wait (68%), low CPU (12%), and 47 blocked processes.
    Likely cause: DB contention or slow NFS mount.
    Suggested next steps:
      → iostat -x 1 5       (identify the slow device)
      → lsof | grep /data   (find processes blocking on /data)
      → dmesg | tail -20    (check for storage errors)
```

**Why deferred:**
- Adds runtime dependency on an external API (cost, latency, privacy concerns on prod servers)
- Requires API key management in a tool designed to be zero-config
- The deterministic heuristics in §21 already produce actionable next-step hints without LLM
- Risk of diluting a future dedicated AI diagnostic product if one is built

**When to revisit:** When DashDiag has 5k+ monthly active users and there is validated demand for "explain this to me" beyond what heuristics provide.

**Architecture note:** The `--json` output is already structured correctly to feed an LLM. The model types, threshold values, and status fields are all present. Implementation would be adding a `cmd/analyze.go` that pipes JSON to an API endpoint. No collector changes needed.

**Possible implementation when ready:**
```go
// cmd/analyze.go
// dsd analyze --from <snapshot.json>  OR  dsd health --json | dsd analyze
// Uses Anthropic Claude API or configurable endpoint
// Opt-in only — never runs automatically
// Rate-limited — never runs on every dsd health invocation
```

---

### F2 — UnpackOps / External AI Platform Integration (`--unpackops` flag)

**What it would do:** Export the DashDiag snapshot in a format compatible with an external AI DevOps platform, and provide a handoff link or auto-pipe.

```bash
dsd health --unpackops
# Saves: /tmp/dsd-snapshot-20260320-143211.json
# Prints: → unpackops analyze --snapshot /tmp/dsd-snapshot-20260320-143211.json
```

**Why deferred:** The target platform does not exist yet. Building a handoff mechanism to a non-existent product adds dead code and confuses users.

**When to revisit:** When the external platform exists and has a defined API contract.

---

### F3 — Prometheus Exporter Mode

**What it would do:** `dsd export metrics` runs as a long-lived process exposing a `/metrics` endpoint in Prometheus text format. Enables integration with existing Grafana/Prometheus stacks.

```
# HELP dsd_cpu_load_avg_1 CPU load average (1 minute)
# TYPE dsd_cpu_load_avg_1 gauge
dsd_cpu_load_avg_1 1.24

# HELP dsd_disk_used_pct Disk usage percentage per mount
# TYPE dsd_disk_used_pct gauge
dsd_disk_used_pct{mount="/"} 82.4
```

**Why deferred:** DashDiag is a snapshot tool, not a long-running agent. Running as a daemon changes the operational model significantly (init scripts, health monitoring, resource usage). This belongs in Phase 5 only after the snapshot use case is validated.

**When to revisit:** When enterprise users request it in GitHub issues.

---

### F4 — Log Pattern Analysis and Cross-Service Correlation

**What it would do:** Beyond counting errors (which `dsd logs` does), detect recurring patterns, correlate errors across services by timestamp, and identify cascading failure chains.

**Example:**
```
🔗 Correlated event chain (14:32–14:33):
  14:32:01  nginx:      upstream timeout (backend-api)
  14:32:02  backend-api: database connection pool exhausted
  14:32:03  postgres:   too many connections (max 100)
  Root pattern: DB connection saturation → API timeout → HTTP 502
```

**Why deferred:** Requires maintaining state across multiple log sources and time windows. Significantly increases collector complexity. This is closer to an observability platform feature than a CLI snapshot tool.

**When to revisit:** Phase 5, after `dsd logs` basic error counting is validated in production.

---

### F5 — perf / eBPF Profiling Integration

**What it would do:** Run `perf stat` for a 5-second window and surface the top CPU hotspots and syscall bottlenecks.

**Why deferred:** Requires kernel headers, elevated privileges (CAP_SYS_PERF or root), and 5+ seconds of sampling time. Fundamentally incompatible with DashDiag's design constraints (fast, safe on prod, no special privileges).

**When to revisit:** Never as a core feature. Could be a community plugin (`dsd-perf`) for users who need it.

---

### F6 — Package / Software CVE Checking

**What it would do:** Run `apt list --upgradable` / `dnf check-update` and cross-reference against a CVE database.

**Why deferred:** Network-dependent (CVE database lookup), slow, and outside the "is my system healthy right now" scope. Belongs in a security scanning tool, not a system snapshot.

**When to revisit:** Never in core. Possible as an optional plugin.

---

### F7 — GPU Health Snapshot (`dsd gpu`)

**Priority: Low.** Specialist workload — ML training clusters and inference servers. Engineers running those environments typically already have NVIDIA DCGM, Prometheus GPU exporters, or vendor dashboards. DashDiag adds most value as a quick sanity check for a generalist engineer who happens to SSH into a GPU node. Better implemented as a community plugin (`dsd-gpu`) than as core.

**What it would do:** Detect GPU presence first via `lspci`. If no GPU: skip with INFO. If GPU present, run a single query to the vendor tool and surface the key health signals:

```
NVIDIA (nvidia-smi):
  nvidia-smi --query-gpu=name,temperature.gpu,power.draw,utilization.gpu,
    memory.used,memory.total,performance_state,ecc_errors.active --format=csv
  Single call, < 1 second, read-only.

AMD (rocm-smi):
  rocm-smi --showtemp --showmemuse --showid

Intel (intel_gpu_top):
  intel_gpu_top -J -s 500ms  (requires root — skip with INFO if unavailable)
```

**Key signals worth surfacing:**

| Signal | Threshold | Meaning |
|---|---|---|
| Temperature | WARN > 85°C, CRIT > 90°C | Thermal throttling risk |
| ECC errors | WARN if > 0 | Memory hardware fault — replace GPU |
| P-state stuck at P8 during utilization > 50% | WARN | Driver/CUDA issue — restart persistence daemon |
| Xid errors in dmesg (NVIDIA) | CRIT | Driver crash signatures |
| VRAM used vs total | WARN > 90% | Out-of-memory risk for next job |
| `nvidia-device-plugin` pods in K8s | CRIT if not running | Already in `dsd k8s` |

**Target output:**
```
🖥️  GPU health… (1 NVIDIA GPU detected)

Name:          NVIDIA A100 80GB PCIe
Temperature:   72°C     ✅
Power:         312W / 400W limit  ✅
Utilization:   94%  ✅
VRAM:          68GB / 80GB  (85%)  ✅
P-State:       P0 (max performance)  ✅
ECC errors:    0  ✅

— Summary —
Status: ✅ Healthy
```

**Why deferred:**
- Vendor tooling (`nvidia-smi`, `rocm-smi`) is not a standard Linux utility — absent on 95%+ of servers
- Specialist audience: ML/inference cluster engineers likely have better GPU monitoring already
- Does not block any Phase 1–4 work
- Plugin architecture (Phase 3) makes this a natural community contribution

**When to revisit:** After plugin architecture ships (Phase 3) and community interest is validated. Implement as `dsd-gpu` plugin first — if adoption is high, consider pulling into core.

**Out of scope even as a plugin:** Driver installation, CUDA version management, clock locking, fan control, X11/Wayland rendering, multi-GPU topology optimization, NVML programmatic monitoring.

---

### Design Constraints That Gate All Future Items

Any future feature added to DashDiag must satisfy all of these:

| Constraint | Rationale |
|---|---|
| Works offline | Engineers run this on air-gapped prod servers |
| No external API calls by default | No latency, no cost, no privacy concerns |
| Completes in < 35 seconds | Users expect a fast snapshot, not a long analysis |
| Read-only | No side effects on the system being checked |
| Zero-config for basic use | First run must work without editing any config file |
| Single static binary | No runtime deps, no venv, no node_modules |

If a proposed feature cannot satisfy all six constraints, it belongs in a different product, not in DashDiag.

---

## 26. UnpackOps Platform Vision — DashDiag's Place in the Portfolio

### The Company Philosophy

UnpackOps was conceived as ExplainOps — bringing clarity and comprehension to
operations. The name evolved but the philosophy did not:

> **Making infrastructure legible, controllable, and predictable.**

Every UnpackOps product answers one question engineers ask every day about
their infrastructure. Together they answer the complete picture.

---

### The Four-Product Portfolio

```
UnpackOps (company)
"Your infrastructure, made legible."

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   Keyorix        "Who has access?"                          │
│   Secrets & credentials management                         │
│   Layer: Security & Access                                  │
│                                                             │
│   DashDiag       "What state is it in right now?"          │
│   Server health diagnostics CLI                             │
│   Layer: Observability & Health                             │
│                                                             │
│   UnpackOps      "Why did it break?"                        │
│   AI-assisted root cause analysis platform                  │
│   Layer: Intelligence & Explanation                         │
│                                                             │
│   FinOps product "What is it costing and why?"             │
│   Infrastructure cost transparency & prediction             │
│   Layer: Financial Visibility                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

These are not four separate products. They are four lenses on the same
infrastructure. An engineer managing a Kubernetes cluster needs all four:

```
Temporal sequence of infrastructure awareness:
────────────────────────────────────────────────────────────────
Before deploy    → DashDiag    "is everything healthy?"
During incident  → DashDiag    "what changed, what is wrong?"
After incident   → UnpackOps   "why did it break?"
Ongoing          → Keyorix     "do the right people have access?"
Monthly review   → FinOps      "what is this costing and why?"
```

---

### The Platform Architecture

DashDiag and Keyorix are the **data collection layer** — lightweight CLI tools
that run everywhere, trusted by engineers, free at the core. UnpackOps (RCA)
and FinOps are the **intelligence layer** — cloud-hosted, subscription-based,
where the business model lives. The free CLI tools drive adoption and feed
structured data into the paid platform.

```
                      Infrastructure
                           │
             ┌─────────────┴──────────────┐
             │                            │
        DashDiag                     Keyorix
        (health telemetry)           (access data)
        dsd health --json            API / webhooks
             │                            │
    ┌────────┴──────────┐                 │
    │                   │                 │
 UnpackOps          FinOps product   ────┘
 RCA platform       Cost platform
 (why it broke)     (what it costs)
    │                   │
    └─────────┬──────────┘
              │
    UnpackOps Dashboard
    (unified platform view)
```

**DashDiag's `--json` output is the API surface between products** — not just
a convenience flag for CI pipelines. The JSON schema in `schema/dsd-output.json`
must be designed for three audiences simultaneously:
1. CI/CD gates (`dsd health --json | dsd policy check`)
2. UnpackOps RCA ingestion (structured incident telemetry)
3. FinOps utilization ingestion (CPU/memory/IO as cost signals)

This is why the JSON schema is a public contract. Breaking it breaks the
entire platform data pipeline.

---

### DashDiag's Role in the Platform — Explicit Statement

DashDiag is the **"what state is it in?"** product. It is useful standalone
and more powerful as part of the platform. Its position in the portfolio:

- **Standalone value:** instant health snapshot for any engineer with a terminal
- **Platform value:** structured telemetry feed into UnpackOps and FinOps
- **Growth engine:** free CLI drives installs → installs generate data →
  data makes the paid platform more valuable → teams upgrade

The `--share` flag and dashdiag.sh backend are the conversion bridge —
engineers share snapshots, colleagues see the value, teams upgrade.
This is not just a monetisation feature — it is the adoption mechanism
for the entire UnpackOps platform.

---

## 26b. FinOps Product — Concept Specification

**Status:** Future product. Not being built now. Specified here to ensure
DashDiag's architecture does not accidentally foreclose this path.

### Core concept

Infrastructure cost is invisible until the AWS bill arrives. By then the
overspend has already happened. The FinOps product makes cost visible
in real time — not as a billing dashboard but as operational intelligence
integrated into the engineering workflow.

**The key insight:** Cost and health are the same data viewed differently.

```
DashDiag sees:     CPU at 4% utilization → health check: OK (not overloaded)
FinOps sees:       CPU at 4% utilization → cost signal: overprovisioned by 25×
                   This instance costs $340/month and delivers $13 of compute
```

```
DashDiag sees:     Memory at 94% → WARN (approaching OOM)
FinOps sees:       Memory at 94% → cost signal: correctly sized, do not downsize
                   AND reliability risk: OOM kill probability rising
```

The FinOps product does not require new data collection infrastructure.
DashDiag already collects the utilization telemetry. FinOps adds the
cost dimension to data that already exists.

### What FinOps answers that nothing else does

```
"Why is our AWS bill $40k this month when it was $28k last month?"
→ DashDiag showed memory pressure on web-prod-03 for 3 weeks
  Engineers never fixed it, added more instances to compensate
  Cost: +$12k/month in redundant capacity masking the real problem

"Which of our 47 EC2 instances can we downsize?"
→ DashDiag has been showing 4-8% CPU utilization on 12 instances for 60 days
  Rightsizing those 12 to the next smaller instance type: -$8k/month

"Is this Kubernetes cluster costing more than it would on VMs?"
→ Cross-reference DashDiag k8s utilization data with cloud pricing APIs
  Answer: yes, by $2,200/month — the overhead is node-level wasted capacity
```

### Data sources for FinOps product

**From DashDiag (already collected, requires `--share` or agent mode):**
```
CPU utilization per server/container (from cpu.go collector)
Memory used vs total (from memory.go collector)
Disk IO utilization (from io.go collector)
Cloud environment detection (from platform/cloud.go)
Container resource limits vs actual usage (from container.go)
K8s node utilization and pod resource requests (from k8s.go)
```

**From cloud provider APIs (new data sources for FinOps product):**
```
AWS Cost Explorer API     → line-item billing data
AWS EC2 pricing API       → current instance prices by type/region
GCP Cloud Billing API     → GCP equivalent
Azure Cost Management API → Azure equivalent
Reserved instance coverage → are you using what you paid for?
```

**From infrastructure as code (future, Phase 2 of FinOps product):**
```
Terraform state files     → what is provisioned
Kubernetes manifests      → what is requested vs what is used
```

### Product naming candidates

Following the UnpackOps portfolio naming conventions:

| Name | Rationale | Fit |
|---|---|---|
| **Gauge** | Extends DashDiag car dashboard metaphor — a gauge measures cost like a fuel gauge | ⭐⭐⭐⭐⭐ |
| Ledger | Clear, financial, trusted — but generic | ⭐⭐⭐ |
| Costr | Invented, modern SaaS feel | ⭐⭐⭐ |
| Drift | "Cost drift" is a strong concept | ⭐⭐⭐ |
| Forecast | Predictive emphasis — too generic | ⭐⭐ |
| Unspend | Verb-based, memorable | ⭐⭐⭐ |

**`Gauge` is the strongest candidate** — it explicitly extends the DashDiag
car dashboard metaphor. A dashboard has gauges. DashDiag is the dashboard.
Gauge measures one specific dimension: cost.

Portfolio reads naturally:
```
DashDiag → the dashboard (overall health at a glance)
Gauge    → the fuel gauge (cost visibility, running out of budget)
```

### What DashDiag must NOT do to keep the FinOps path open

1. **Do not discard utilization data** — keep raw CPU%, memory%, IO% in the
   JSON output even when status is OK. FinOps needs the numbers, not just
   the WARN/CRIT signal.

2. **Do not collapse per-instance data** — keep per-container and per-pod
   metrics separate in K8s output. FinOps needs granularity to identify
   which specific workloads are expensive.

3. **Do not omit cloud environment from JSON output** — `cloud_environment`
   field must appear in every `dsd health --json` response. FinOps uses it
   to look up pricing for the detected instance type.

4. **Keep `--json` schema stable** — adding fields is safe, removing or
   renaming breaks the FinOps data pipeline before it is built.

### Build sequence

```
Now:        DashDiag (health telemetry — collecting the data)
6 months:   UnpackOps RCA (consuming DashDiag data for incident analysis)
12 months:  FinOps product (consuming DashDiag data + cloud billing APIs)
18 months:  Unified dashboard (all four products in one view)
```

The FinOps product should not be started until:
- DashDiag has real daily users with `--share` accounts (the data pipeline exists)
- UnpackOps RCA is shipping (proves the platform model works)
- At least one customer has asked "can you also show me the cost angle?" (demand validated)

---

### The Company Positioning Statement

```
UnpackOps

"Your infrastructure, made legible."

Four questions. One platform.

  Keyorix      Who has access?              (Security & Access)
  DashDiag     What state is it in?         (Observability & Health)
  UnpackOps    Why did it break?            (Intelligence & Explanation)
  Gauge        What is it costing?          (Financial Visibility)

For engineering teams who are tired of being surprised by their infrastructure.
```

This positioning works because each product is independently valuable but
they compound. A team using all four has complete operational intelligence.
No surprises. No black boxes. No unexplained AWS bills.

**The original ExplainOps instinct — bringing clarity and comprehension to
operations — is exactly what this portfolio delivers. The name evolved.
The vision did not.**

---

---

*DashDiag Project Bible — Version 48.0 — Consolidated from fifty planning sessions*

## 27. Multi-Distro Validation Testbed

### Hardware

**Lenovo Legion 5 15ACH6H (82JU)**
- CPU: AMD Ryzen 7 5800H (8 cores / 16 threads)
- GPU: NVIDIA RTX 3070 Laptop (8GB VRAM)
- RAM: 16GB DDR4
- Storage: 2x NVMe (nvme0n1 = Windows, nvme1n1 = Linux multi-boot)
- Network: 192.168.1.145 (rotates across OS boots)

### Multi-Boot Partition Map (nvme1n1, 1TB)

| Partition | Size | OS | Status |
|---|---|---|---|
| p1-p5 | ~280GB | RHEL 10.1 | ✅ Validated |
| p6 | 977MB | Shared ESP | All distros use this |
| p7-p10 | 185GB | Debian 13.4 | ✅ Validated |
| p11-p12 | 76GB | Ubuntu 26.04 | ✅ Installed, stress pending |
| p13 | 74GB | Fedora 44 | ✅ Validated (GPU, DNF5) |
| p14 | 2GB | Fedora swap | |
| p15-p16 | 56GB | openSUSE Tumbleweed | ✅ Validated |
| p17-p18 | 56GB | SLES 16 | ⏳ Installing |
| p19-p20 | 80GB | Reserved (Gentoo TBD) | |
| p21 | 1GB | Rocky /boot (LVM) | |
| p22 | 184GB | Rocky Linux 10.1 LVM | ✅ Validated |

Note: Rocky installer ignored pre-created p13/p14 and used the reserve space (p21/p22).
Pre-created partitions p13-p20 are intact and available for other distros.

### Validated Distros

| OS | Kernel | Baselines | Stress | GPU | Key Findings |
|---|---|---|---|---|---|
| macOS arm64 | — | — | — | — | ✅ Full support |
| RHEL 10.1 | 6.12.0 | Separate | ✅ | No | SELinux, subscription |
| Debian 13.4 | 6.12.73 | 144 | ✅ | No | Overnight 9h, soft lockups |
| Ubuntu 26.04 | 7.0.0 | — | Pending | No | |
| Rocky Linux 10.1 | 6.12.0 | 197 | ✅ | ✅ 83°C peak | LVM, Podman, FIPS, AIDE |
| Fedora 44 | 6.19.10 | Collecting | ✅ | ✅ Driver 595 | DNF5, gpu_burn fails GCC16 |
| openSUSE Tumbleweed | 7.0.5 | Collecting | ✅ | ✅ Driver 580 | zypper, SELinux (not AppArmor!) |
| SLES 16 | TBD | Pending | Pending | TBD | AppArmor, SUSEConnect, supportconfig |

### Features Discovered/Built Per Distro

**Rocky Linux 10.1 (2026-05-13)**
- Cockpit port awareness + socket-activation service name resolution
- BUG-009 SELinux AVC blind spot fix (non-root ausearch fallback)
- dnf `has_security_repo` validation
- Podman rootless socket (`/run/user/<uid>/podman/podman.sock`)
- LVM disk collector validation (`/dev/mapper/rl-root`)
- firewalld detection (zone, allowed services, SSH lockout CRIT)
- `dsd health --firmware` via fwupd (UEFI dbx WARN — real finding)
- FIPS mode, crypto-policies, auditd rules, AIDE, USBGuard

**Fedora 44 (2026-05-13)**
- DNF5 advisory command syntax (`dnf advisory list --security`)
- LLMNR port 5355 added to expected ports (systemd-resolved)
- gpu_burn incompatible with GCC 16 + CUDA 12.6

**openSUSE Tumbleweed (2026-05-13)**
- zypper security patch parser (fixed `not needed` bug)
- FDLimits sshd-auth false positive fixed (socket-activated transient units)
- postfix port 25 → `wellKnownPort` resolution
- nvidia-persistenced /dev/nvidia* permission fix (dsd caught crash loop)
- Stress every 10 minutes via stress-ng (no `stress` package on Tumbleweed)
- SELinux enforcing on Tumbleweed (expected AppArmor — surprise!)

**SLES 16 (2026-05-13) — Built, awaiting validation:**
- AppArmor profiles + complain mode + denials in `dsd security`
- SUSEConnect registration check in zypper repo detection
- supportconfig detection (last run date, archive path)
- SUMA competitive analysis added to project bible

### Stress Test Infrastructure

Each distro runs:
```
*/10 * * * * stress/stress-ng --cpu 8 --vm 2 --vm-bytes 2G --timeout 60s
*/10 * * * * nvidia-smi snapshot after stress (GPU distros)
* * * * * dsd health --json && dsd baseline collect
```

Data stored in `marketing-assets/<distro>-data/` per distro.

### Key Multi-Distro Learnings

1. **Port 9090 (Cockpit)** — shows as `systemd` due to socket activation. Fixed globally.
2. **Port 5355 (LLMNR)** — standard on Fedora/Ubuntu, add to expected ports.
3. **Port 25 (postfix)** — default on openSUSE/SLES server, show as `postfix` not `master`.
4. **SELinux on Tumbleweed** — openSUSE moved from AppArmor to SELinux in Tumbleweed.
5. **DNF5 syntax break** — `dnf updateinfo list security` → `dnf advisory list --security`.
6. **zypper `not needed` bug** — `strings.Contains("not needed", "needed")` is true. Fixed to parse pipe-separated columns.
7. **FDLimits sshd-auth** — systemd socket-activated transient processes have soft limit=1 by design. Not a real FD exhaustion.
8. **Rocky installer grabs free space** — Anaconda ignores pre-created partitions and creates its own LVM layout using the reserve space. Use Expert Partitioner and name partitions explicitly.
9. **gpu_burn + GCC 16** — CUDA 12.6 doesn't support GCC 16 (Fedora 44). Use nvidia-smi for GPU monitoring instead.
10. **auditd 0 rules** — Rocky ships with auditd running but zero rules. Fedora and openSUSE ship 1 default rule. Surfaced as WARN.


## 28. Session Log — 2026-05-13 (Multi-Distro Validation Day)

### Summary

Full-day development session focused on hardware validation across 6 Linux distros
plus major new features built during install/download wait times.

**Commits today:** 30+  
**Distros validated:** Rocky Linux 10.1, Fedora 44, openSUSE Tumbleweed  
**Distros in progress:** SLES 16 (installing from GM ISO)  
**Legal milestone:** Keyorix SL escritura signed, CIF provisional obtained

---

### Morning — Rocky Linux 10.1 Validation

| Commit | Feature |
|---|---|
| 2f12f90 | Cockpit port 9090 socket-activation service name resolution |
| c5390cd | BUG-009 SELinux AVC blind spot fix (non-root ausearch fallback) |
| f208e67 | Podman rootless socket + LVM disk collector validated |
| 1ac8542 | firewalld detection (zone, allowed services, SSH lockout CRIT) |
| 7329131 | `dsd health --firmware` via fwupd (UEFI dbx WARN — real finding) |
| 64a5bd1 | FIPS, crypto-policies, auditd rules, AIDE, USBGuard |
| 2592e34 | Rocky 10.1 final dataset — 197 baselines committed |

### Afternoon — Fedora 44 + openSUSE Tumbleweed Validation

| Commit | Feature |
|---|---|
| b2f974c | DNF5 advisory command syntax fix |
| 98ff59c | LLMNR port 5355 added to expected ports |
| 907c9f0 | zypper security patch parser fix (`not needed` bug) |
| a578009 | FDLimits sshd-auth false positive fix |
| d0c39f7 | Port display improvements (postfix/master, wellKnownPort) |
| 1c2b514 | AppArmor deep inspection (profiles, complain mode, denials) |
| 9194b5b | AppArmor in `dsd security` output |
| 8b5afb7 | SUSE supportconfig detection (last run date, archive path) |
| 8d6c05c | SUSEConnect registration check in zypper repo detection |

### Evening — Hardware Features + New Commands

| Commit | Feature |
|---|---|
| 0b164cf | Network link speed + 100Mbps WARN (real finding: machine at 100Mbps) |
| 95cd3d6 | USB-Ethernet detection on Linux (sysfs /usb/ path) |
| 19880b8 | macOS USB-Ethernet via networksetup (en7 RTL8156 detected) |
| 44fe858 | NVMe unsafe shutdowns + power-on hours heuristics + NIC rx_errors |
| 762ae59 | `dsd health --report` — shareable markdown health report |

### CVE Feature (built during SLES download)

| Commit | Feature |
|---|---|
| d942a16 | `dsd cve CVE-XXXX` — cross-distro CVE vulnerability checker |
| 043dfac | `dsd cve --all` — scan all pending security advisories |
| ded658d | Air-gapped OVAL import + embedded snapshot (initial) |
| 55f3704 | OVAL parser fixed — 26,349 CVEs generated from SUSE OVAL |
| 9d58d1e | **Removed embed** — sidecar file pattern (stable binary hash) |
| 78b5836 | `dsd cve info` + snapshot fallback chain |

### Key Architecture Decision: CVE Sidecar Files

**Problem identified:** Embedding CVE data in binary changes its hash on every update.
In air-gapped enterprise environments, binary hashes are verified before deployment.
A binary that changes hash without a code change breaks change control.

**Solution:** Sidecar file pattern (like antivirus):
```
/usr/local/bin/dsd                    ← stable binary, predictable hash
/var/lib/dsd/oval/sles16.xml.bz2     ← OVAL data, updated separately
```

**CVE check priority chain:**
1. `zypper lp --cve CVE-XXXX` (live, requires updated repos)
2. OVAL sidecar file auto-discovery (`/var/lib/dsd/oval/`)
3. Pre-converted snapshot (`/var/lib/dsd/cvedata.json.gz`)

**Air-gapped workflow:**
```bash
# Internet machine
curl -O https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.16.xml.bz2
# USB transfer
mkdir -p /var/lib/dsd/oval && cp sles16.xml.bz2 /var/lib/dsd/oval/
# Air-gapped query (no flags needed)
dsd cve CVE-2025-32462
```

### SLES 16 GM ISO Strategy

Intentionally installing from GM ISO (May 2025 packages, not QU1):
- Every CVE discovered after May 2025 will be VULNERABLE on first boot
- `dsd cve --all` on fresh install → expect 20-50 CRITICAL/IMPORTANT findings
- This is the marketing screenshot — shows dsd catching what went unfixed

First boot validation plan:
```bash
sudo dsd health --plain --terse
sudo dsd security --plain        # AppArmor, supportconfig, SUSEConnect
sudo dsd health --packages       # zypper + SUSEConnect registration
sudo dsd cve --all               # THE MONEY SHOT
sudo dsd cve CVE-2025-32462 CVE-2025-32463 CVE-2024-3094
sudo dsd health --report         # Generate shareable report
```

### Hardware Findings (real, from testbed)

- Machine connected at **100Mbps not 1Gbps** — dsd caught it, we didn't notice manually
- USB-Ethernet (en7, RTL8156) detected as primary interface on macOS — WARN fires
- NVMe1 at **7094 power-on hours** (295 days), 0 unsafe shutdowns — healthy
- Battery health at **84.5%** (50.71Wh / 60Wh design, 150 cycles) — normal wear
- SELinux enforcing on openSUSE Tumbleweed (expected AppArmor — surprise!)



## 29. Session Log — 2026-05-14 (SLES 16 Hardware Validation + New Features)

### Summary

Hardware validation session on Lenovo Legion 5 (192.168.1.145) running SLES 16.
Stress cron running throughout — Thermal CRITs captured in baselines overnight.
Keyorix SL legally incorporated 2026-05-13, CIF provisional obtained.

**Commits this session:** 5
**Hardware validated:** SLES 16, dual NVMe, RTX 3070 GPU, AMD k10temp

---

### Features Shipped

| Commit | Feature |
|---|---|
| `f710c02` | Snapper/Btrfs heuristic in `dsd health` — CRIT/WARN on stale/missing snapshots |
| `257eec3` | SUSEConnect subscription status in `dsd health` as dedicated Subscription check |
| `6c338d4` | `dsd hardware` — SMART via smartctl, hwmon thermals, EDAC memory errors |
| `dc9df89` | nolint cyclop fix on checkHardware + printHardwareReport |

---

### Bugs Fixed

- **Snapper date timezone bug**: `time.Parse` defaults to UTC; snapper dates are local wall-clock time. On CEST (UTC+2) machines, `time.Since(lastTime)` returned ~-1.7h, cast to int gave -1 which is the "unknown" sentinel. Fixed with `time.ParseInLocation(layout, s, time.Local)`.
- **SUSEConnect orphaned insight**: insight with check name "Subscription" was silently dropped because `insightForResult` matches by runner result name — no collector named "Subscription" existed. Fixed by creating `SUSEConnectCollector` returning `*models.SUSEConnectInfo` (new thin type to avoid type-switch collision with SecurityInfo/checkSecurity).

---

### Hardware Validated

| Check | Result |
|---|---|
| Dual NVMe IO collector | Both drives visible — nvme0n1 idle, nvme1n1 active. No bugs. |
| OVAL air-gap path | Two outcomes: NOT AFFECTED + NOT IN OVAL both correct |
| SUSEConnect in health | `Subscription OK SUSEConnect ACTIVE — expires in 60 day(s)` |
| GPU VRAM WARN | 7314 MB / 8192 MB (89%) — WARN fires correctly at >85% threshold |
| Snapper heuristic | `Snapshots OK 11 Btrfs snapshot(s) — last < 1h ago` |
| dsd hardware NVMe | SKHynix 49/54°C, 7081/7100h, 0 media errors, SMART PASSED |
| k10temp | 71°C post-stress, 100°C during stress-ng (CRIT fires correctly) |
| EDAC | `/sys/devices/system/edac/mc` empty on AMD Zen 3 SLES 16 — correctly reports unavailable |

---

### Pending (Hardware Required)

- **Marketing screenshots**: Thermal CRIT during stress + combined health output with multiple WARNs — tomorrow
- **SATA validation**: `dsd hardware` SATA path built but untested — needs Proxmox HP ProDesk G2 (mix of SATA + NVMe). Validate `ata_smart_attributes` parsing (attrs 5, 197, 198, 173/177/231/233).
- **Multi-distro smoke tests**: RHEL 10.1, Debian 13.4, Fedora 44, Rocky 10.1, openSUSE Tumbleweed all bootable on nvme1n1 — blocked by stress cron, reboot needed.
- **Old MacBook Ubuntu**: aged Intel SSD — good `dsd hardware` wear % validation target.

---

### Architecture Decisions

**SUSEConnectInfo separate from SecurityInfo**: When two different collectors both return `SecurityInfo`, the heuristics type switch can only route to one function. Solution: create a thin wrapper type `SUSEConnectInfo{Registered, ExpiresDays, Status}` so the type switch routes independently. Pattern to follow for any future "sub-check" extracted from an existing collector.

---

### Backlog Items Added (from 2026-05-14 session)

**Distro-aware health checks** (sprint 3, collector layer discipline):
Collectors should detect the running distro and adjust checks accordingly rather than
being retrofitted later. Already largely done (zypper vs apt vs dnf, RHEL vs Debian
log paths). What's missing is a formal discipline: every new collector should document
which distro variants it handles and have a fallback for unknown distros.
Implementation: add a `platform.Distro()` call at the top of each collector's
`Collect()` function where behaviour differs, rather than scattered `if` checks.
Not a sprint 2 item — add to collector review checklist for v0.3 quality pass.

**Log surfacing in `dsd health deep`** (sprint 3):
When a service or check is unhealthy, `dsd health deep` should surface the 3-5 most
relevant log lines inline rather than just reporting the failed state. Keeps users in
one tool instead of jumping to `journalctl`. Example: `systemd unit postgres.service
failed` should show the last 3 journal lines for that unit inline.
Prerequisite: `dsd health deep` fast variant must be in production use first
(build-order rule). Implementation sketch: after each collector result, if status is
WARN/CRIT and the check has an associated systemd unit or log source, call
`journalctl -u <unit> -n 5 --no-pager` and attach output to the insight's Details
field. Already have the Details rendering infrastructure.
Sprint 3 target.



## 30. Pricing Strategy, TAM/SAM/SOM & 3-Year Projection

*Written 2026-05-14 post hardware validation sweep across 7 distros.*

---

### Positioning

DashDiag sits **below full APM, above nothing** — the gap between "no monitoring" and "Datadog at $18/host/month". Target buyer is a sysadmin or DevOps engineer managing 5-500 Linux hosts who wants instant actionable health data without deploying an agent, configuring a SaaS, or learning a complex platform.

**Closest comparables:**
| Product | Price | Why DashDiag wins |
|---|---|---|
| Datadog Agent | $18-23/host/month | No agent, no cloud dependency, instant CLI |
| New Relic | $16/host/month | Zero config, works air-gapped |
| Checkmk | €600/year/10 hosts | Better UX, multi-distro, CVE-aware |
| Site24x7 | $9/host/month | Local-first, no data leaves the machine |
| Netdata | Free/OSS | Actionable output, not just metrics |

---

### Pricing Tiers

| Tier | Price | Hosts | Target |
|---|---|---|---|
| **Free** | €0 | 1 | Individual devs, OSS projects, viral acquisition |
| **Pro** | €9/host/month or €79/year | 1-10 | Freelancers, solo operators, small teams |
| **Team** | €29/host/month (min 5) | 5-100 | SME ops teams, startups with infra |
| **Enterprise** | POQ | Unlimited | MSPs, large infra, custom SLA |

**Rules:**
- Annual billing at 20% discount (encourages commitment, improves cash flow)
- Free tier limited to `dsd health` + `dsd cve` on 1 host — enough to demonstrate value, not enough to run production
- Pro unlocks: `dsd hardware`, `dsd security`, `dsd net`, `--report`, `--json` API, baseline history
- Team adds: multi-host dashboard, `dsd health --diff` across fleet, email/Slack alerts
- Enterprise adds: SSO, audit log, SLA, custom integrations, dedicated support

**First paying customer target:** Pro at €79/year — achievable within 6 weeks of launch (Sprint 2 goal).

---

### TAM / SAM / SOM

**TAM — Total Addressable Market**
- Linux servers in production: ~40M worldwide (conservative, 2026)
- System monitoring/observability market: ~$20B by 2026
- Linux-specific ops tooling segment: **~$4B**

**SAM — Serviceable Addressable Market**
- SMEs + mid-market with 5-500 Linux hosts not using enterprise APM
- ~2M companies globally fitting this profile
- Average spend: ~$500/year/company
- SAM: **~$1B**

**SOM — Serviceable Obtainable Market (realistic 3-year)**
- Solo founder, no VC, bootstrapped
- Community-led growth via HN, Reddit r/sysadmin, DevOps Slack communities
- SOM target: **€500K-€2M ARR by end of Year 3**

---

### 3-Year Revenue Projection

| Year | Paying Customers | Avg ARR/Customer | ARR | Key Milestone |
|---|---|---|---|---|
| **Y1** | 50-200 | €400 | €20K-€80K | PMF confirmed, 50 paying, Pro tier only, first MSP conversation |
| **Y2** | 500-2,000 | €300 | €150K-€400K | Team tier live, first MSP deal, Slack/email alerts, UnpackOps RCA beta |
| **Y3** | 2,000-8,000 | €250 | €500K-€1.5M | Enterprise tier, channel partners, UnpackOps platform, Gauge (FinOps) beta |

*Average ARR/customer declines as free-to-Pro conversions grow the base — offset by Team/Enterprise upsells.*

---

### The MSP Multiplier

MSPs (Managed Service Providers) are the highest-leverage customer segment:

> One MSP managing 200 clients × 10 servers each = 2,000 hosts
> Team pricing: €29/host/month = **€58,000/year from one customer**

This is the Y1 target in a single deal. MSPs need exactly what DashDiag provides:
- Multi-distro support (their clients run everything)
- Air-gapped/no-agent operation (security-conscious clients)
- `--json` output for integration into their own dashboards
- `--report` flag for client-facing reports
- CVE scanning as a service delivery feature

**MSP acquisition strategy:** target MSPs advertising SLES/RHEL support on LinkedIn. The SLES 16 CVE screenshot (74 advisories, 2 CRITICAL on fresh install) is the opening conversation.

---

### Upside Drivers

1. **Platform stickiness** — `--json` API connects DashDiag to UnpackOps RCA and Gauge (FinOps). Once a customer uses three products, churn drops to near zero.
2. **Multi-distro validation** — 7 distros tested in production. Most competitors only test Ubuntu. This is a real differentiator for enterprise/MSP customers running RHEL/SLES.
3. **Air-gapped positioning** — financial services, healthcare, government all require on-premise tools. DashDiag works with zero internet access. No competitor in this price range does.
4. **Word of mouth velocity** — CLI tools spread via GitHub stars, HN posts, r/sysadmin recommendations. Zero CAC if the first 50 users love it.

---

### Risks

| Risk | Mitigation |
|---|---|
| Datadog/New Relic adds lightweight CLI mode | Speed to market — be established before they notice |
| Open source forks (Netdata, node_exporter) | Actionable output + CVE + hardware — not just metrics |
| Solo founder bandwidth | Sprint discipline, no feature creep, ship fast |
| Pricing too low for enterprise | POQ tier with annual commitment protects margin |
| SLES/RHEL customer needs SLA | Enterprise tier with SLA offering from Y2 |

---

### Key Decision: Freemium vs Free Trial

**Chosen model: Freemium** (Free tier permanent, not time-limited trial)

Rationale:
- CLI tools need organic adoption — engineers try before buying
- Free tier creates viral spread via GitHub, HN, blog posts
- Free users become paid users when they hit host limits or want `--report`
- Free tier on 1 host is a permanent marketing channel
- Alternative (14-day trial) would kill word-of-mouth for a CLI tool

---

### Pricing Review Triggers

Revisit pricing at these milestones:
- First 50 paying customers — validate willingness to pay
- First MSP deal — validate Team tier price point
- First Enterprise inquiry — validate POQ approach
- €100K ARR — consider raising Pro tier to €12/month



## 31. Viral Channel Strategy — Gaming Community & SteamOS

*Written 2026-05-14. Strategic note only — minimal product changes required.*

---

### The Insight

Gamers are a **distribution channel, not a revenue channel.**

The conversion path:
> r/SteamDeck post → 50K views → 2K installs → 200 are sysadmins at their day job → 20 paying customers

The gamer never pays. Their employer does. This is identical to how major B2B dev tools grew virally:
- **Homebrew** — started as a dev convenience tool, now on every Mac in every company
- **htop** — free forever, standard on every production server globally
- **fzf** — viral on r/unixporn, now in enterprise dotfiles everywhere

DashDiag follows the same pattern: gamers find it → share it at work → ops team adopts → team buys Pro/Team license.

---

### Why It Works Without Any Extra Dev Work

SteamOS 3.x (Steam Deck) is Arch-based Linux. `dsd health` already runs on it.

What DashDiag already catches that gamers care about:
- `dsd gpu` — GPU temperature, VRAM usage, power draw, Xid errors
- `Thermal CRIT` — thermal throttling kills frame rates, dsd catches it
- `dsd hardware` — drive health (load times), RAM, NVMe temps, CPU freq
- `CPU CRIT` — load at 108% of capacity (stress test validated)

The Steam Deck throttles aggressively under sustained load. A screenshot of `dsd health` showing `Thermal CRIT CPU 96°C — thermal throttling active` during a gaming session would resonate immediately with r/SteamDeck's 2M+ members.

---

### The SteamOS Install Problem

SteamOS has an **immutable read-only rootfs**. This is the critical friction point:
- `/usr` is read-only by default
- `pacman` (package manager) is disabled
- Standard installs to `/usr/local/bin` get **wiped on every OS update**
- `sudo steamos-readonly disable` unlocks temporarily but updates re-lock it

Developer mode only enables SSH — it does NOT fix the read-only problem. Any user can enable it in the Deck settings in 30 seconds, but it doesn't help with persistence.

**Options evaluated:**

| Option | Verdict |
|---|---|
| Install to `/usr/local/bin` | ❌ Wiped on SteamOS updates |
| Flatpak | ❌ Sandbox blocks `/proc` and `/sys` — dsd breaks entirely |
| Distrobox container | ✅ Works but too many steps for casual users |
| Install to `~/.local/bin` | ✅ Persists, but requires PATH setup |
| **AppImage** | ✅ **Best option — single binary, no install, survives updates** |

**The right answer: AppImage.**

```bash
curl -L https://dashdiag.sh/dsd -o ~/dsd && chmod +x ~/dsd && ~/dsd health
```

Single command. No install. Survives every SteamOS update. Works immediately. This is already how most power users on the Deck install CLI tools.

**The Reddit post headline:**
> "No install needed — download and run. Found thermal throttling on my Deck in 2 seconds."

AppImage build is already on the packaging roadmap — the Steam Deck angle makes it **higher priority** since it directly enables the viral play.

---

### Hardware Required

A **Steam Deck OLED** (~€550 new, €300-400 refurbished).

**Buy trigger: after first paying customer.** Not before. The viral play costs nothing until the product is ready to receive traffic.

**What the Deck validates that nothing else does:**
- Real SteamOS 3.x immutable rootfs — confirms AppImage install works
- AMD Van Gogh APU — validates AMD GPU collector via `/sys/class/drm/`
- Real thermal throttling under gaming load — Deck is notorious for it
- Battery collector (Deck is essentially a laptop)
- Developer mode SSH — same flow casual users would follow

**Alternative before buying:** SteamOS recovery image in a VM — free, confirms `dsd health` doesn't crash, covers 80% of validation. Good enough to de-risk before buying hardware.

---

### The Play

One well-timed Reddit post on r/SteamDeck:

> "I built a one-command Linux health tool. No install needed — just download and run. Caught thermal throttling at 96°C during a Cyberpunk session. [screenshot]
> `curl -L https://dashdiag.sh/dsd -o ~/dsd && chmod +x ~/dsd && ~/dsd health`"

Cost: €0. Potential reach: 50K-200K views in 48h if it resonates.

Same post works on:
- r/linux_gaming
- r/SteamDeck
- r/linuxmasterrace
- Hacker News (Show HN)
- r/sysadmin (different angle — professional)

---

### What NOT to Do

- **Don't build gaming-specific features** — `dsd gaming` or `dsd deck` subcommands add maintenance burden for a non-paying segment
- **Don't optimise for gamers** — they're a funnel, not a customer segment
- **Don't promise SteamOS support** — just let it work and let users discover it
- **Don't post before AppImage is ready** — without it the install story is too painful

---

### Dev Work Required (minimal)

| Item | Priority | Reason |
|---|---|---|
| AppImage packaging | **High** | Enables Steam Deck install story + Linux packaging generally |
| AMD GPU via `/sys/class/drm/` | Medium | Steam Deck APU + production AMD servers |
| SteamOS VM validation | Low | Confirm no crashes before posting |

---

### Priority

**AppImage first, then post.** Timing: at or shortly after public launch when GitHub repo is public and landing page is live.


## 32. Marketing Copy — Key Headlines & Positioning Statements

*Written 2026-05-14. Raw marketing insights captured from real-world observations.*

---

### Headline Candidates

**From the Ubuntu cheat sheet observation:**
> "Ubuntu ships a CLI cheat sheet. DashDiag ships answers."

**From the SLES 16 CVE screenshot:**
> "One command. 74 security advisories. 2 critical. On a fresh install."

**From the thermal throttling screenshot:**
> "Your server has warning lights. Now you can see them."

**From the car dashboard metaphor:**
> "Your car has a dashboard. Your server should too."

**From the MSP angle:**
> "One command per server. Know everything. Bill accordingly."

**From the air-gapped positioning:**
> "No agent. No cloud. No data leaves your machine. Just answers."

**From the multi-distro validation:**
> "RHEL, Debian, Ubuntu, SLES, Fedora, Rocky, openSUSE. One tool. One command."

**From the firewall false-positive fix:**
> "dsd health caught a potential lock-out on a fresh Ubuntu install. Before we did."

---

### The Ubuntu Cheat Sheet Insight

Canonical ships an official CLI cheat sheet with every Ubuntu Server download. It covers basic file management, LXD virtualization, and Ubuntu Pro.

**What this tells us:**
- Ubuntu Server users need hand-holding for basic operations
- The complexity gap between "installed Linux" and "know what's happening" is large
- This is the exact gap DashDiag fills — not a tutorial, not a cheat sheet, just answers

**Landing page angle:**
> "Ubuntu ships a cheat sheet to help you use the command line.
> DashDiag ships answers about what's actually happening on your server."

---

### Positioning Matrix

| Situation | What users do today | What DashDiag does |
|---|---|---|
| Fresh server install | Read cheat sheet, run 10 commands | `dsd health` — one command |
| Security audit | Check CVE lists manually, run apt/dnf | `dsd cve --all` — full advisory list |
| Performance issue | `top`, `iostat`, `dmesg`, `journalctl` | `dsd health` — root cause surfaced |
| Hardware inventory | `lshw`, `dmidecode`, `smartctl`, `iw` | `dsd hardware` — unified output |
| Pre-handoff checklist | Manual checklist, tribal knowledge | `dsd health --report` — shareable PDF |
| MSP client review | SSH to each server, run manual checks | `dsd health --json` — scriptable fleet |

---

### Copy Don'ts

- Don't say "monitoring" — implies agents, dashboards, ongoing cost
- Don't say "observability" — enterprise jargon, wrong audience
- Don't say "DevOps platform" — too broad, no meaning
- Don't lead with features — lead with the problem ("74 advisories on a fresh install")
- Don't compare to Datadog — different category, different buyer

### Copy Dos

- Lead with the output, not the tool ("CPU at 108% capacity — here's what's causing it")
- Use real numbers from real hardware ("74 advisories", "97°C", "89% VRAM")
- Show the command is short (`dsd health`, not `dsd health --format=json --output=...`)
- Emphasise zero setup ("no agent, no config, no account")
- Show it works on their distro (multi-distro validation is a differentiator)


## 33. Revised Financial Model — Three Growth Scenarios

*Written 2026-05-15. Replaces the conservative estimates in §30 with a fuller scenario analysis.*

---

### Why §30 Was Too Conservative

The original estimate (€500K-€2M ARR by Y3) assumed:
- Solo founder forever
- No fundraising
- Pure organic word-of-mouth growth
- Pro tier only as primary revenue

That's survivable but not the real opportunity. The actual ceiling is much higher.

---

### The MSP Multiplier (Revisited)

Europe alone has ~40,000 MSPs. The math on even modest MSP penetration:

| MSPs | Hosts/MSP | Price | Monthly ARR |
|---|---|---|---|
| 10 MSPs | 500 hosts | €29/host/mo | €1.45M/mo |
| 100 MSPs | 500 hosts | €29/host/mo | €14.5M/mo |
| 1,000 MSPs | 100 hosts | €29/host/mo | €2.9M/mo |

**10 MSP deals = potential €17M ARR.** This is Year 2 territory, not Year 3.

---

### The Platform Multiplier

DashDiag alone = a tool. Average contract value: €79-500/year.

DashDiag + UnpackOps RCA + Gauge (FinOps) = a platform. Average contract value: €500-5,000/year.

Platform companies command:
- 10x the pricing of point tools
- 3-5x lower churn (switching cost is high)
- 5-10x the valuation multiple at exit

The `--json` API connecting all four products is the platform moat. Every customer who uses two products is 80% less likely to churn than a single-product user.

---

### Three Growth Scenarios

#### Scenario A — Conservative (Solo, Bootstrapped)
*Original §30 estimate. Stays solo, no fundraising, organic growth only.*

| Year | Customers | ARR | Key driver |
|---|---|---|---|
| Y1 | 50-200 | €20K-€80K | Word of mouth, HN post |
| Y2 | 500-2,000 | €150K-€400K | Team tier, first MSP |
| Y3 | 2,000-8,000 | €500K-€2M | Platform bundling begins |

**Ceiling:** €2M ARR. Profitable but small. Founder controls everything.

---

#### Scenario B — Base Case (First Hire + Small Raise)
*€500K-€1M seed round. Hire one salesperson focused on MSPs + one engineer.*

| Year | Customers | ARR | Key driver |
|---|---|---|---|
| Y1 | 200-500 | €100K-€300K | Salesperson closes first 5 MSPs |
| Y2 | 1,000-5,000 | €1M-€3M | 20 MSP deals, Team tier dominant |
| Y3 | 5,000-20,000 | €5M-€10M | Platform play, first Enterprise deals |

**Ceiling:** €10M ARR by Y3. Fundable at Series A. 

---

#### Scenario C — Bull Case (Platform + US Expansion)
*Series A of €3-5M. Team of 8-10. US market entry in Y2.*

| Year | Customers | ARR | Key driver |
|---|---|---|---|
| Y1 | 500-1,000 | €300K-€500K | EU MSPs, HN viral, SteamOS Reddit |
| Y2 | 5,000-20,000 | €3M-€8M | US MSP partnerships, Enterprise tier |
| Y3 | 20,000-80,000 | €20M-€50M | Full platform, channel partners |

**Ceiling:** €50M ARR by Y3. Exit opportunity (acquisition) at €100-500M.

---

#### Scenario D — Lottery Ticket (Acquisition)
*Product gets noticed by Datadog, Red Hat, SUSE, or IBM.*

The multi-distro validation, SLES/RHEL enterprise positioning, and `--json` platform API make DashDiag a natural acquisition target for:

- **SUSE** — DashDiag as a native diagnostic layer for SLES/openSUSE
- **Red Hat / IBM** — RHEL diagnostic tool for enterprise support contracts
- **Datadog** — lightweight CLI complement to their agent-based platform
- **CrowdStrike / Qualys** — CVE scanning integration

**Acquisition range:** €20M-€200M depending on ARR and strategic fit.
**Trigger:** 1,000+ paying customers or a large enterprise reference customer.

---

### The Two Decisions That Change Everything

**Decision 1: When to hire the first salesperson**

A good enterprise salesperson focused on MSPs could close €500K ARR in year 1. That's 10x what you'd close while also building product. The right hire is someone who already has MSP relationships — not a junior SDR.

Hiring trigger: first €50K ARR (proves willingness to pay, de-risks the hire).

**Decision 2: Whether to raise**

| Stay bootstrapped | Raise €500K-€1M seed |
|---|---|
| Full control | Dilution ~15-20% |
| Slower growth | 5-10x faster growth |
| €2M ceiling realistic | €10M+ ceiling realistic |
| Zero pressure | Investor expectations |
| Exit optional | Exit expected |

**Recommendation:** stay bootstrapped through first €100K ARR to prove the model. Then raise if you want to go after the €10M+ opportunity. Don't raise before product-market fit is confirmed.

---

### Geographic Sequencing

**Y1:** Spain + EU (home market, SLES/RHEL enterprise base, GDPR alignment)
**Y2:** UK + DACH (Germany/Austria/Switzerland — strong SUSE/SAP ecosystem)
**Y3:** US (largest market, highest willingness to pay, requires US entity)

The US market is 5-10x the EU market for enterprise Linux tooling. A single US MSP partnership could 10x your EU numbers. But US sales require US presence (legal entity, US-based salesperson, US pricing in USD).

---

### Exit Scenarios

| Exit type | When | Range | Who |
|---|---|---|---|
| Acqui-hire | Y1-Y2 | €1M-€5M | Any larger startup needing Go/Linux expertise |
| Strategic acquisition | Y2-Y3 | €20M-€100M | SUSE, Red Hat, Datadog |
| Private equity | Y3+ | €50M-€200M | PE roll-up of DevOps tools |
| IPO | Y5+ | €500M+ | Requires €50M+ ARR |

**Most likely exit:** strategic acquisition at Y2-Y3 once 500+ paying customers and at least one enterprise reference. The SLES 16 validation and multi-distro coverage makes DashDiag uniquely attractive to SUSE specifically — they have no native CLI diagnostic tool.

---

### Key Metrics to Track

| Metric | Target Y1 | Target Y2 | Target Y3 |
|---|---|---|---|
| Paying customers | 50 | 500 | 5,000 |
| ARR | €50K | €500K | €5M |
| MRR growth | 15%/mo | 10%/mo | 7%/mo |
| Churn | <5%/mo | <3%/mo | <2%/mo |
| CAC | <€50 | <€200 | <€500 |
| LTV | >€200 | >€1,000 | >€5,000 |
| LTV:CAC | >4:1 | >5:1 | >10:1 |
| NPS | >40 | >50 | >60 |

---

### Bottom Line

The €2M estimate in §30 is what happens if nothing goes right and nothing goes wrong — steady, safe, solo.

The real opportunity is:
- **€10M ARR** with one good salesperson and one MSP focus
- **€50M ARR** with a seed round and US expansion
- **€100M+ exit** if SUSE, Red Hat or Datadog come calling

The product is already strong enough. The question is ambition, not capability.



## 34. Session Log — 2026-05-14/15 (10-Distro Sweep + Bug Fixes + UX Polish)

*Session duration: ~8 hours. Focus: hardware validation, marketing assets, bug fixes, UX consistency.*

---

### Distros Validated This Session

| Distro | IP | Status |
|---|---|---|
| SLES 16 | 192.168.1.150 | ✅ Full dataset, 1,240 baselines |
| openSUSE Tumbleweed | 192.168.1.151 | ✅ |
| Fedora 44 | 192.168.1.152 | ✅ |
| RHEL 10.1 | 192.168.1.153 | ✅ |
| Debian 13 | 192.168.1.154 | ✅ |
| Rocky 10.1 | 192.168.1.155 | ✅ |
| Ubuntu 26.04 | 192.168.1.156 | ✅ |
| AlmaLinux 10.1 | 192.168.1.157 | ✅ |
| CentOS Stream 10 | 192.168.1.158 | ✅ |
| Linux Mint 22.3 | 192.168.1.145 | ✅ |

---

### Features Shipped

- **`dsd hardware` full inventory** — System (DMI), CPU (model/cores/freq/max boost), RAM (total + per slot from dmidecode), Drives (NVMe + SATA/SAS via smartctl), Thermals, NICs (state/speed/driver/MAC/errors)
- **Hostname + OS in banner** — every command now shows `⚡ DashDiag (dsd) dev — hostname · OS` on first line, works over SSH without TTY
- **`NVMe` renamed to `Drives`** — covers NVMe + SATA/SAS via smartctl --scan-open
- **CPU max boost frequency** — `Frequency: 3551 MHz (max 4465 MHz)`
- **Known service port detection** — k8s/docker/prometheus ports downgraded from WARN to INFO with service name
- **`done in Xs` always visible** — was missing when WARNs/CRITs present
- **Watch mode screen clear** — was appending, now clears on refresh
- **INFO insights in summary** — PrintSummary now renders INFO group after WARNs

---

### Bugs Fixed

| Bug | Distro Found | Fix |
|---|---|---|
| UFW false positive CRIT (inactive contains "active") | Ubuntu | `strings.Contains(lower, "status: active")` |
| apt CVE scanner misses Ubuntu `resolute-security` repos | Ubuntu | Broadened filter to `strings.Contains(line, "security")` |
| dnf advisory deduplication — 354 rows → 101 unique | AlmaLinux | Added `seen` map by advisory ID |
| casper-md5check.service false CRIT | Linux Mint | Added to cloudInitUnits ignore list |
| Sudoers ALL entries shown as usernames | Linux Mint | Skip when user field == "ALL" |
| Clock CRIT misleading on RTC local TZ | Linux Mint | Detect `/etc/adjtime LOCAL`, show explanatory message |
| jbd2/kworker kernel threads flagged as hung | Linux Mint | Filter by ppid==2 + isKernelThread() |
| SMART false FAILED as non-root | All | Detect exit status 2 → show "needs root" |
| AppArmor "All profiles enforcing" shown as non-root | All | Guard on mode != "unknown" AND profiles > 0 |
| Sudo "none" shown as non-root | All | Show "unknown (needs root)" when NeedsRoot=true |
| Hint ordering inconsistent (fix before inspect) | All | Standardised: inspect → fix → persist throughout |
| `to persist` not grouped in renderer | All | Added to prefix list in printHints + printHintsPlain |
| Single-command hints white, multi-command grey | All | StyleDim applied consistently to all hint commands |
| Subtitle "read only checks" white, "done in Xs" grey | All | ANSI dim applied to subtitle in progress.go |

---

### Marketing Assets

**Screenshots added:**
- `hero-thermal-cpu-crit-sles16.png` — Thermal + CPU CRIT during stress, 97°C
- `cve-top-74-advisories-sles16.png` — 74 advisories, 2 CRITICAL (samba, cups)
- `security-clean-sles16.png` — all green security posture
- `gpu-vram-warn-89pct-sles16.png` — VRAM WARN 89%
- `health-normal-sles16.png` — Subscription + Snapshots visible
- `health-rocky10-hostname.png` — hostname+OS header feature
- `ubuntu26-health.png` — KernelSec + k8s INFO
- `ubuntu26-hardware.png` — full hardware inventory
- `ubuntu26-cve-clean.png` — zero advisories, fully patched

**Data folders committed:**
- sles16-data/ (89 CRIT baselines, 25 samples, 1240 total)
- tumbleweed-data/, fedora44-data/, rhel10-data/, debian13-data/
- rocky10-data/, ubuntu26-data/, almalinux10-data/
- centos-stream10-data/, mint22-data/

---

### Key Decisions Made

- **Distro count: 10** — SLES 16, Tumbleweed, Fedora 44, RHEL 10.1, Debian 13, Rocky 10.1, Ubuntu 26.04, AlmaLinux 10.1, CentOS Stream 10, Linux Mint 22.3
- **Drives collector** replaces NVMe — covers all drive types
- **AppImage** is the Steam Deck packaging solution (immutable rootfs problem)
- **SteamOS viral channel** — distribution not revenue, post after AppImage is ready
- **MSP multiplier** — 10 MSPs × 500 hosts × €29/mo = €17M ARR potential
- **Pricing**: Free(1 host) / Pro(€79/yr) / Team(€29/host/mo) / Enterprise(POQ)

---

## 35. Backlog — Updated 2026-05-15

*Priority order: Sprint 2 first (revenue), then polish, then new features.*

---

### Sprint 2 — First Paying Customer (NOW)

- [ ] Set static IP on Linux Mint 22.3 (currently DHCP at 192.168.1.145)
- [ ] Take Linux Mint screenshots: `dsd hardware` (new full inventory), `dsd health` (clean Mint output)
- [ ] Return Lenovo Legion 5 laptop (all data safe in GitHub)
- [ ] Build landing page at dashdiag.sh
- [ ] Write Show HN post with SLES 16 CVE screenshot
- [ ] LinkedIn outreach to 5 MSPs managing SLES/RHEL
- [ ] Set up Stripe for Pro tier (€79/year)
- [ ] First paying customer target: 6 weeks

---

### Packaging (Blocks viral growth)

- [ ] **AppImage** — single binary, no install, survives SteamOS updates
  - Install command: `curl -L https://dashdiag.sh/dsd -o ~/dsd && chmod +x ~/dsd && ~/dsd health`
  - Required for Steam Deck viral play
- [ ] `.deb` package (Debian/Ubuntu/Mint)
- [ ] `.rpm` package (RHEL/Fedora/SLES/Rocky/Alma/CentOS)
- [ ] Homebrew formula (macOS)
- [ ] `install.sh` one-liner

---

### Hardware Validation (Pending)

- [ ] **SATA drives** — Proxmox HP ProDesk G2 (192.168.10.10, separate subnet)
  - Mix of SATA + NVMe — first real SATA path test for `dsd hardware`
- [ ] **Old MacBook Ubuntu** — aged Intel SSD, Ubuntu + SATA in one shot
- [ ] **Oracle Linux 10.1** — downloaded, not yet installed
- [ ] **SteamOS 3.x** — validate `dsd health` on immutable rootfs (VM first, Steam Deck after first paying customer)
- [ ] **openSUSE Leap** — different from Tumbleweed (stable release, different repos)

---

### Drive Improvements

- [ ] **`dsd health` SATA in health check** — `collectSATADrives()` appended to nvme_linux.go but the `dsd health` Drives check doesn't surface SATA findings yet — needs heuristics wiring
- [ ] **SATA validation** — needs Proxmox or MacBook for real SATA drives
- [ ] **USB NIC exclusion from speed checks** — `enx*` devices don't reliably report speed

---

### AMD GPU Support

- [ ] `dsd gpu` via `/sys/class/drm/` for AMD GPUs (RDNA/RDNA2/Van Gogh)
  - Currently only NVIDIA via `nvidia-smi`
  - Needed for: Steam Deck (AMD Van Gogh APU), production AMD EPYC servers
  - Also enables `dsd health` GPU check on AMD systems

---

### WiFi Support

- [ ] `dsd hardware` WiFi section — signal (dBm), TX bitrate, band (2.4/5/6GHz)
  - Deferred: rtw88 driver unreliable on Ubuntu 26.04
  - Build and test on Steam Deck where WiFi works reliably

---

### Clock Check

- [ ] Consider downgrading Clock from CRIT to WARN when RTCInLocalTZ is the only cause
  - NTP IS working, kernel just reports unsync due to RTC mode
  - Currently: CRIT with explanatory message — acceptable but slightly alarmist

---

### UX Polish

- [ ] `dsd health --diff` — show only what changed since last run
- [ ] `dsd health deep` — full deep scan (planned, not built)
- [ ] `dsd net deep` — full network deep scan (planned, not built)
- [ ] `--report` flag — PDF report generation
- [ ] Gateway ping 0.0ms when TCP fallback (non-root ICMP blocked) — cosmetic fix

---

### Bible / Documentation

- [ ] Update §27 Multi-Distro Validation matrix (now 10 distros, update table)
- [ ] Add Oracle Linux to planned validation list
- [ ] Document SATA drive validation plan (Proxmox + MacBook)



---

## 36. Privacy Decisions — 2026-05-16

See `PRIVACY.md` in the repo root for the full policy.

### Core principle

**dsd reads your system. It tells you what it found. Nothing leaves the machine.**

No telemetry. No cloud. No account. No network calls.

### Decisions locked in

| Decision | Status | Notes |
|----------|--------|-------|
| Zero telemetry | ✅ Permanent | No analytics, no crash reporting, no phone-home |
| No account required | ✅ Permanent | dsd works without registration |
| State file is local only | ✅ Permanent | `~/.config/dsd/state.json` never uploaded |
| `--report` writes local file only | ✅ Permanent | Admin chooses if/how to share |
| Air-gap compatible | ✅ Permanent | Works identically on disconnected networks |

### `--share` — not yet implemented, privacy decisions pre-locked

When built, `--share` must follow these rules (non-negotiable):

1. **Explicit consent prompt** before any upload — show what will be shared
2. **Redaction by default** — hostname, IPs, MACs stripped before upload
   Opt-in: `--share --include-identity`
3. **Link expiry** — 24h default, max 7 days, no permanent pastes
4. **No account required** — anonymous upload
5. **EU data residency** — GDPR compliant storage
6. **`--report` always remains the zero-network alternative**

Any implementation of `--share` that violates these rules must be rejected.

### NPS / feedback

The interactive NPS prompt was removed (2026-05-16) — no backend to receive scores,
breaks non-interactive use, alarming on production servers.

Future feedback mechanism: opt-in only via `dsd config set feedback on`.
Never automatic. Requires a webhook/email endpoint first.

### What `--report` contains (treat as sensitive)

- Hostname, kernel version, distro
- Pending CVEs and advisory IDs
- Open ports and owning processes
- Package versions
- SMART drive data
- Usernames in sudoers
- AppArmor/SELinux profile names

Admins should treat `--report` output as an attack surface map.
Do not share publicly without reviewing contents.

### Reference

- Full policy: `PRIVACY.md`
- Security model: `SECURITY.md`
- Backlog item: `--share` implementation requires privacy review before any code is written


---

## 37. dsd fleet — Fleet Management Design — 2026-05-16

See full design: `docs/fleet-design.md`

### The niche

"Use RHEL Satellite, which might be an overkill for our environment
with around 20/22 VMs and 5 physical hosts"

This is a real, occupiable niche. Satellite is overkill. Ansible is
complex. dsd fleet is the answer for teams managing 5–100 Linux servers
who need visibility and basic patch management without enterprise overhead.

### What it does

```
dsd fleet health     # health check across all hosts in parallel
dsd fleet cve        # CVE status and patch priority across fleet
dsd fleet patch      # apply security patches with confirmation
dsd fleet report     # markdown fleet health summary
```

### Why it wins

| | Satellite | dsd fleet |
|--|-----------|-----------|
| Agent required | Yes | No — SSH only |
| Setup time | Days | 30 seconds |
| Distro support | RHEL only | All 14+ validated |
| Cost (20 hosts) | $$$$ | €79/year Pro |
| Air-gap | Complex | Yes |

### Monetization

dsd fleet is the Pro/Team tier feature — the natural upgrade from free
single-host `dsd health`. MSPs can manage per-client fleet configs.

### Build order

- Sprint 5: `dsd fleet health` (read-only, parallel SSH)
- Sprint 6: `dsd fleet cve` (aggregate CVE status)
- Sprint 7: `dsd fleet patch` (patch management with audit log)
- Sprint 8: reports, scheduled summaries, wizard

### Key technical decisions

- No agent — SSH + `dsd health --json` on each host
- Self-copy: dsd copies itself to remote hosts if not installed
- Goroutine pool (default 10 parallel SSH connections)
- Reuses existing `models.HealthSnapshot` — zero new data structures
- Fleet config: `~/.config/dsd/fleet.yaml`
- Audit log: `~/.config/dsd/fleet-log.jsonl`
- Privacy: same as single-host — zero telemetry, air-gap safe

---

## 38. Backlog — Demo Tasks — 2026-05-16

### Feature demonstrations pending (requires lab network at 192.168.10.20)

Three new features built today need real hardware validation and screenshots.
Lab network (192.168.10.20) must be accessible.

---

### Task 1 — SUSE pre-migration check demo

**Machine:** CT204 (openSUSE Leap 16 LXC) on Proxmox
**Commands:**
```bash
ssh root@192.168.10.20
pct exec 204 -- /usr/local/bin/dsd health
```
**What to look for:**
- `Packages ⚠️ SUSE migration risk: grub2-x86_64-efi is installed but NOT locked`
- If grub2-x86_64-efi is not installed in the LXC, the check will be clean —
  that's also valid (LXC has no EFI). Try on a physical SUSE machine if available.

**Deploy latest binary first:**
```bash
cd /Users/andreibeshkov/dev/dashdiag
GOOS=linux GOARCH=amd64 go build -o dsd-linux ./cmd/dsd
scp dsd-linux root@192.168.10.20:/tmp/dsd
ssh root@192.168.10.20 'pct push 204 /tmp/dsd /usr/local/bin/dsd'
```

---

### Task 2 — Boot slowness analysis demo

**Machine:** MacBook Air 2011 (192.168.10.10) — Ubuntu 24.04, dying SSD
**Why:** 14-year-old SSD with 794 bad sectors almost certainly has slow
fsck/disk timeout boot units. High probability of real WARN findings.

**Commands:**
```bash
ssh andrei@192.168.10.10         # password may have changed — check
sudo dsd health
```
**What to look for:**
- `Systemd ⚠️ slow boot unit: systemd-fsck@dev-sda1.service took XX.Xs`
- `Systemd ⚠️ slow boot unit: dev-sda1.device took XX.Xs`
- Or any unit > 10s shown with journalctl + systemd-analyze plot hints

**Alternative:** Proxmox host (192.168.10.20) — run `dsd health` there directly.
Proxmox hosts often have slow network-wait or storage init units.

**Deploy latest binary first:**
```bash
scp dsd-linux andrei@192.168.10.10:/tmp/dsd
ssh andrei@192.168.10.10 'sudo cp /tmp/dsd /usr/local/bin/dsd'
```

---

### Task 3 — SELinux double-layer demo

**Machine:** Oracle Linux 10.1 (192.168.1.145) — has SELinux enforcing
**Why:** Real RHEL-family machine with SELinux enforcing by default.

**Setup — create a failing service:**
```bash
ssh andrei@192.168.1.145
sudo bash -c 'cat > /etc/systemd/system/dsd-demo-fail.service << EOF
[Unit]
Description=DashDiag SELinux demo (intentionally failing)

[Service]
ExecStart=/usr/bin/cat /etc/shadow
Type=oneshot

[Install]
WantedBy=multi-user.target
EOF'
sudo systemctl daemon-reload
sudo systemctl start dsd-demo-fail.service   # this will fail — SELinux blocks it
```

**Then run:**
```bash
sudo dsd health
```

**What to look for:**
```
❌  Systemd: unit dsd-demo-fail.service has failed
   → to inspect: systemctl status dsd-demo-fail.service
   → to inspect: journalctl -u dsd-demo-fail.service -n 50
   → note: SELinux is enforcing — check AVC denials if permissions look correct
   → to check SELinux: ausearch -m avc -ts recent -c cat
```

**Cleanup after demo:**
```bash
sudo systemctl disable dsd-demo-fail.service
sudo rm /etc/systemd/system/dsd-demo-fail.service
sudo systemctl daemon-reload
```

**Deploy latest binary first:**
```bash
scp dsd-linux andrei@192.168.1.145:/tmp/dsd
ssh andrei@192.168.1.145 'sudo cp /tmp/dsd /usr/local/bin/dsd'
```

---

### Screenshots needed

| Feature | Machine | Expected output |
|---------|---------|-----------------|
| SUSE pre-migration | CT204 openSUSE LXC | `Packages ⚠️ SUSE migration risk` |
| Boot slowness | MacBook Air / Proxmox | `Systemd ⚠️ slow boot unit: X took Xs` |
| SELinux double-layer | Oracle Linux 192.168.1.145 | `❌ Systemd + note: SELinux enforcing` |

---

### Notes

- Deploy commit `48686e3` binary before all demos
- MacBook Air SSH password may have changed — may need console access
- Oracle Linux is on a separate network (192.168.1.x) — accessible directly
- All three features work without lab network — use Oracle Linux for SELinux,
  MacBook Air for boot slowness if lab is unavailable

---

## 39. The Operability Reframe — DashDiag Brand Positioning

**Date:** 2026-05-16  
**Origin:** Research conclusion + UnpackOps brand origin story

---

### The insight

The research conclusion said it better than any internal brief:

> *"The Linux diagnostics landscape is technically rich but experientially poor.
> The distributions that solve this — by making security subsystems observable,
> audible, and guided — will win enterprise adoption not because they are more
> secure, but because they are more operable."*

This is the problem DashDiag was built to solve. And it maps exactly to the
UnpackOps origin story: ExplainOps → UnpackOps → DashDiag.

---

### The four pillars

These are not marketing words. They are the exact capabilities dsd implements:

**Observable** — you can see what's happening
- Inline data on every OK row (memory GB, disk %, NIC speed)
- AVC samples shown inline — no manual grep
- Journal size, boot time, slow units surfaced automatically
- `--diff` shows what changed since last check

**Audible** — silent failures are surfaced
- journald volatile storage WARN (logs lost on reboot — nobody told you)
- SELinux dontaudit suppression INFO (denials hidden by design)
- SELinux silent denial surfaced with AVC context
- Boot slowness analysis — `systemd-analyze blame` tells you which is slow,
  dsd tells you what to do next
- SUSE migration risk WARN — grub2 not locked before zypper migration

**Guided** — you know what to do next
- Boolean-first SELinux fix order (booleans → context → audit2allow)
- Fix commands on every WARN and CRIT
- Distro-aware commands (dnf vs apt vs zypper)
- SELinux double-layer hint when unit fails — check AVC before giving up
- SUSE grub lock command included inline

**Operable** — the system works for the admin, not against them
- 1.8 seconds vs 74+ manual commands
- Works on 19+ distros without reconfiguration
- LXC container awareness — no false positives from host sensors
- Air-gap compatible — zero network calls
- No agent, no daemon, no account

---

### How this changes messaging

**Before (feature-led):**
> "74 commands vs 1"
> "21 checks in 1.8 seconds"

**After (operability-led):**
> "Linux is technically rich but experientially poor.
> DashDiag makes it operable."

The 74 commands story stays — but as *evidence* of the operability problem,
not the headline. The headline is the problem and the promise.

---

### The UnpackOps connection

ExplainOps → UnpackOps → DashDiag is a straight line:

- **ExplainOps** (original name): explain what the system is doing
- **UnpackOps** (brand): unpack the opaque — make the invisible visible
- **DashDiag** (product): the diagnostic layer that does it in practice

DashDiag's `--json` output is the connective tissue of the UnpackOps platform:
- dsd diagnoses the Linux system
- Keyorix manages the secrets on that system
- The RCA platform correlates what went wrong
- Gauge (FinOps) tracks what it costs

All four products share the same philosophy: systems should be observable,
audible, guided, and operable. DashDiag is the proof of concept.

---

### Landing page headline options (operability-led)

```
Linux is technically rich. Operationally poor.
DashDiag fixes the experience.

---

Your system knows what's wrong.
It just doesn't tell you.
DashDiag does.

---

Observable. Audible. Guided.
One command. Every Linux distro.

---

Make Linux operable.
dsd health
```

---

### The positioning statement (internal)

DashDiag is an operability layer for Linux — making security subsystems
observable, surfacing silent failures as audible signals, and guiding
administrators to the right fix without tribal knowledge.

Not a monitoring tool. Not a log aggregator. Not an agent.
A single command that makes the system explain itself.

---

### How to use this in conversations

**With sysadmins:**
"You know the system is doing something. dsd tells you what."

**With DevOps/SRE:**
"Observability for your application stack, operability for the Linux underneath it."

**With CISOs/security buyers:**
"SELinux is a triumph of security engineering and a failure of user experience.
dsd fixes the UX without touching the security model."

**With MSPs:**
"Your clients' servers are opaque to them. dsd makes them readable — to you
and to them."

**With enterprises (air-gap/RHEL):**
"The distributions that win enterprise adoption will be the ones that are
more operable, not just more secure. dsd is that layer."

---

### Reference

- Research quote source: Deep Research Analysis: Linux Diagnostics & Troubleshooting Pain Points
- UnpackOps brand origin: §26 (Platform Vision)
- DashDiag --json as platform API: §26b

---

## 39b. The Operability Scope — Beyond Linux

**Date:** 2026-05-16  
**Decision:** The four pillars are OS-agnostic. DashDiag's mission is to
make *systems* observable, audible, guided, and operable — not just Linux.

---

### Current state

| Platform | Status |
|----------|--------|
| Linux (19+ distros) | ✅ Production validated |
| macOS | ✅ Validated (arm64 + Intel) |
| Windows | 🔲 Future — not started |

### Why the pillars are OS-agnostic

Observable, Audible, Guided, Operable — none of these words say "Linux".

Every operating system has the same fundamental problem:
- Systems know what's wrong but don't tell you clearly
- Diagnostic information is scattered across dozens of tools
- Silent failures waste hours of admin time
- Fix commands require tribal knowledge

Windows has this problem. macOS has this problem.
Linux just has it worst because it's the most complex and fragmented.

DashDiag starts on Linux because that's where the pain is deepest and the
audience is most receptive. But the mission is broader.

### The positioning statement (updated)

**Before:**
"DashDiag is an operability layer for Linux"

**Now:**
"DashDiag is an operability layer for systems"

The qualifier "Linux" is removed from the mission. It stays in the
marketing copy where it's accurate (the current product is Linux-first),
but the *vision* is OS-agnostic.

### Feature evaluation rule (updated)

Every future feature should be evaluated:
> Does it make *systems* more observable, audible, guided, or operable?

Not "Linux systems". Systems. This keeps the door open for:
- Windows support (Event Viewer, WMI, Windows Defender, NTFS)
- macOS deepening (launchd, Spotlight, macOS Security)
- Container-native mode (no assumption of host OS)
- Network devices (switches, routers — same four pillars apply)

### Windows — when and how

Windows is not a short-term priority. The audience is Linux/macOS admins.
But the architecture supports it — the collector/analysis/render pipeline
is OS-abstracted by design. `platform/windows.go` would follow the same
pattern as `platform/linux.go` and `platform/macos.go`.

When to start Windows:
- After the landing page is live
- After the first paying customers
- After fleet management (`dsd fleet`) is production-ready on Linux
- Signal: Windows admins asking for it

### What to say publicly (now)

"dsd works on Linux and macOS. Windows support is on the roadmap."

Don't promise a date. Don't overstate Windows capability. Just make clear
the vision is cross-platform and the door is open.

### What this means for marketing

- Replace "make Linux operable" with "make systems operable" in evergreen copy
- Keep "Linux" in specific product claims (19+ distros, etc.)
- In investor/partner conversations: "we start with Linux because that's
  where the pain is deepest, but the four pillars apply to every OS"

### The UnpackOps connection (reinforced)

UnpackOps is not a Linux company. It's an operability company.
DashDiag happens to start with Linux because that's where the problem
is most acute. The platform vision — Keyorix, RCA, Gauge — is already
cross-platform by design.

The four pillars are the brand. The OS is the starting point.

---

## 39c. Product Hierarchy — DashDiag within UnpackOps

**Date:** 2026-05-16  
**Decision:** DashDiag does the dirty work. UnpackOps carries the vision.

---

### The hierarchy

```
UnpackOps
  (the company, the brand, the platform vision)
  "Make systems observable, audible, guided, and operable"
      │
      ├── DashDiag        — operability engine (the dirty work)
      │     dsd command   — reads /proc, parses audit logs, 
      │                     runs 74 checks in 1.8s
      │
      ├── Keyorix         — secrets management
      │
      ├── RCA platform    — root cause analysis
      │
      └── Gauge           — FinOps
```

---

### What "dirty work" means

DashDiag does what no one else wants to do manually:

- Reads `/proc`, `/sys`, `/dev/kmsg` directly
- Parses 14+ package manager formats
- Counts AVC denials in audit.log byte by byte
- Walks journald binary archives
- Runs `smartctl` and interprets SMART attributes
- Samples IO await over 1 second
- Detects 19+ distros and adjusts thresholds accordingly
- Suppresses 30+ known LXC false positives
- Correlates CPU load with thermal readings

None of that is glamorous. All of it is essential.

The dirty work is what makes the four pillars real on real hardware.
UnpackOps is the promise. DashDiag is the proof.

---

### Why this framing works

**For marketing:**
DashDiag doesn't need to explain the whole vision —
UnpackOps.com carries that. DashDiag just needs to work,
and to be described as the "operability engine" or
"system health layer" of the UnpackOps platform.

**For positioning:**
"DashDiag does the dirty work for UnpackOps" gives DashDiag
a clear role without overloading the name. The name can stay.
The role is defined by what it does in the hierarchy.

**For the `--json` API surface:**
DashDiag's `--json` output is not just a feature —
it's the connective tissue of the platform. Every other
UnpackOps product can consume DashDiag's structured output:
- RCA platform reads dsd health --json to understand system state
- Keyorix reads dsd health --json to know which secrets are in use
- Gauge reads dsd health --json for resource utilization signals

DashDiag does the sensing. UnpackOps does the thinking.

---

### How to talk about the hierarchy

**With sysadmins (product-first):**
"dsd — one command, every system check"
Don't mention UnpackOps unless asked.

**With DevOps / SRE teams (platform context):**
"DashDiag is the operability layer of the UnpackOps platform —
it's what gives every other product real-time system state."

**With investors / partners (vision):**
"UnpackOps is building the operability layer for modern infrastructure.
DashDiag is the foundation — the engine that reads the system and
surfaces what matters. Every product in the portfolio consumes it."

**With enterprises (integration angle):**
"DashDiag's --json output is the API. Build on top of it,
pipe it into your observability stack, or use the UnpackOps
platform to get the full picture."

---

### Brand rules

| Context | Use |
|---------|-----|
| CLI / terminal | `dsd` |
| Product name | DashDiag |
| Platform name | UnpackOps |
| Company name | Keyorix SL (legal entity) |
| Vision statement | UnpackOps — make systems operable |
| Product tagline | DashDiag — the system health engine |

---

### The one-liner for each layer

```
UnpackOps:  "Make systems observable, audible, guided, and operable."
DashDiag:   "The operability engine that does the dirty work."
dsd:        "One command. Every check. Every distro."
```

---

## 39d. The DashDiag Name — Dual Meaning (Brand Decision)

**Date:** 2026-05-16  
**Decision:** "Dash" carries two simultaneous meanings — both intentional.

---

### The double meaning

**Dash as Dashboard:**
The car dashboard analogy — everything the system knows, visible at a
glance. Oil pressure, temperature, speed, fuel — all surfaced without
opening the hood. The OBD port connection: OBD (On-Board Diagnostics)
is the standard that makes cars debuggable. DashDiag is OBD for servers.

**Dash as Speed:**
A dash is a sprint. Fast. 1.8 seconds, not 74 commands.
The name itself carries the speed promise. You don't run DashDiag and
wait — you dash through diagnostics.

Both meanings point at the same thing:  
*Fast diagnostics at a glance.*

---

### Why this is stronger than one analogy

Most tool names carry one meaning. DashDiag carries two:

| Meaning | Maps to | dsd behaviour |
|---------|---------|---------------|
| Dashboard | Observable | everything surfaced at a glance, inline data on every row |
| Dash (speed) | Operable | 1.8s, concurrent collectors, zero wait |

"Diag" anchors both — this is diagnostics, not monitoring, not dashboarding.
The name is the product promise: *fast diagnostics at a glance.*

---

### How to use this in copy

**Short version:**
```
DashDiag — fast diagnostics at a glance.
```

**Expanded (when explaining the name):**
```
Dash — because it's fast. One command, 1.8 seconds.
Diag — because it diagnoses, not just displays.
Dashboard — because everything is visible at a glance.
```

**In conversations:**
"The name means two things intentionally — a dash as in fast,
and a dashboard as in at-a-glance. Both matter: it's useless if
it's slow, and useless if it buries the signal."

---

### The `dsd` command name

`dsd` is the CLI. Three letters, no OS implied, no baggage.
Reads as "dashed" — the past tense of dash.
*I dsd'd the server. Everything's clean.*

---

### What does NOT change

The four pillars (Observable, Audible, Guided, Operable) still stand.
The OS-agnostic mission still stands.
The product hierarchy (DashDiag under UnpackOps) still stands.

The name just got a second meaning that makes it stronger.
