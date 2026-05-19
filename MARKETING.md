# DashDiag Marketing — Story & Positioning

## The OBD Analogy

### Core Metaphor

Every car built since 1996 has an OBD port — On-Board Diagnostics.
When your check engine light comes on, a mechanic plugs in a scanner and gets:
"cylinder 3 misfire, coolant temp sensor reading high, oxygen sensor response slow."

Before OBD, mechanics guessed. After OBD, they knew.

**DashDiag is OBD for your server.**

---

### Social Media Post Draft

**Hook:**
Your car has had a health dashboard since 1996.
Your server still doesn't.

**Story:**
Last night I left a stress test running on a RHEL machine.
This morning I ran one command:

```
sudo dsd health --story
```

This is what came back:

```
17:00  Memory ↓ CRIT — RAM at 97% (0.1 GB free)
17:00  CPU ↓ CRIT — load at 264% (42 / 16 cores)
17:00  Logs ↓ CRIT — 5 OOM kills: traefik, coredns, stress
17:00  IO ↓ CRIT — disk latency 28.5ms (10x normal)
17:12  Memory ↑ OK
17:12  CPU ↑ OK
17:12  IO ↑ OK
```

Full incident timeline. No log diving. No guessing.
What failed, when, what recovered, what's still broken.

That's the OBD readout for your server.

**CTA:**
DashDiag — one command, instant system health.
`brew install dsd` (coming soon)
→ dashdiag.sh

---

### Why the analogy works

- Everyone has seen a check engine light — instant relatability
- OBD is invisible infrastructure that just works — same as DashDiag should feel
- Mechanics = SREs/DevOps — professional tool, not consumer toy
- "Your car has had this since 1996" creates urgency — why doesn't your server?
- The story output IS the OBD readout — you can show it, not just describe it

---

### Variations

**LinkedIn (professional):**
> We've had OBD in cars since 1996.
> Plug in a scanner, get: cylinder 3 misfire, coolant sensor reading high.
> No guessing. No experience required. Just data.
>
> I've been building the same thing for Linux servers.
> One command. Instant health overview. Historical incident timeline.
> Works on RHEL, Ubuntu, macOS. No agent. No cloud. No registration.
>
> This morning it showed me a full overnight incident — memory CRIT, 5 OOM kills,
> IO latency spike — all resolved — in a single `dsd health --story` output.
>
> Still early. Looking for DevOps/SRE teams who want to try it.
> DM me or → dashdiag.sh

**Twitter/X (short):**
> Your car has had OBD diagnostics since 1996.
> Plug in scanner → "cylinder 3 misfire, coolant sensor high"
>
> I built the same thing for Linux servers.
> `dsd health --story` →
> [screenshot of overnight incident story]
>
> dashdiag.sh

**HN Show HN:**
> Show HN: DashDiag – OBD diagnostics for Linux servers (no agent, no cloud)
>
> I got tired of SSHing into servers and running 10 commands to understand
> what happened overnight. Built a CLI tool that reads directly from /proc,
> /sys, and kernel interfaces — no wrappers, no agents, no cloud.
>
> The `--story` flag reads saved baselines and narrates what happened:
> [paste story output]
>
> Works on RHEL 10, Ubuntu 24, macOS. Single binary, CGO_ENABLED=0.

---

### Screenshot opportunities

1. **The story output** — overnight incident with Memory CRIT → recovery arc
2. **Side by side** — car OBD scanner display vs `dsd health` output
3. **Speed** — `✅ System healthy. Checks passed in 1.3s`
4. **Depth** — the full collector list with inline drilldowns

---

### Taglines

- "OBD for your server"
- "One command. Full picture."
- "Your car has had this since 1996."
- "Instant system health. No agent. No cloud."
- "dsd health — like a mechanic, but faster"

---

## CI/CD Integration — The SSH Signal

### The Insight

When you run `ssh host 'dsd health'` without a TTY, you're not using it manually.
You're scripting it. That's a CI/CD use case — and DashDiag handles it correctly by design.

- **Plain text output** — no color codes that break log parsers
- **Exit codes follow Unix convention** — 0 OK, 1 WARN, 2 CRIT
- **`--json` flag** — machine-readable output for pipeline parsing
- **No agent, no registration** — works in any environment that has SSH

### Real CI/CD patterns

**Gate a deployment on server health:**
```bash
# GitHub Actions — block deploy if server is degraded
- name: Pre-deploy health check
  run: ssh deploy@${{ secrets.SERVER }} 'dsd health'
```

**Multi-server health sweep from a jump host:**
```bash
for host in web1 web2 db1 db2; do
  echo "=== $host ==="
  ssh $host 'dsd health --terse'
done
```

**Parse JSON in a monitoring script:**
```bash
ssh $host 'dsd health --json' | jq '.checks[] | select(.level == "CRIT")'
```

**Post-deploy validation:**
```bash
ssh $host 'dsd health' && echo "Deploy healthy" || alert "Deploy degraded"
```

### Why this matters for positioning

Most health tools require an agent, a daemon, or a cloud connection.
DashDiag runs over plain SSH — the infrastructure every team already has.

No ports to open. No agents to manage. No SaaS to sign up for.
Just SSH and a binary.

This makes DashDiag composable — it fits into whatever pipeline or script
the team already runs, rather than requiring adoption of a new platform.

### Social media angle

> We discovered something interesting while building DashDiag.
>
> When you run `ssh host 'dsd health'` without a TTY,
> the tool automatically switches to script-friendly output:
> plain text, grouped hints, Unix exit codes.
>
> Exit 0 = healthy. Exit 1 = warnings. Exit 2 = critical.
>
> So you get a pre-deploy health gate for free:
> `ssh $SERVER 'dsd health' && ./deploy.sh`
>
> No agent. No cloud. No new infrastructure.
> Just SSH and one binary.

---

## The SELinux Blind Spot — A Technical Differentiator Story

### What We Found

While validating DashDiag on RHEL 10.1 with auditd running, we generated 17
real SELinux AVC denial events. Then we ran `dsd health` and compared two
outputs — before and after a bug fix.

**Before the fix:**
```
KernelSec    OK
```

**After the fix:**
```
KernelSec    CRIT  17 SELinux denials (mode: enforcing)
```

The 17 denials were real. They existed in `/var/log/audit/audit.log` the
entire time. The collector was just reading the wrong source.

---

### Why It Happened — The Linux Audit Framework

When `auditd` is running, the kernel sends AVC (SELinux denial) messages to
a privileged audit netlink socket that auditd owns exclusively. auditd writes
them to `/var/log/audit/audit.log`.

The kernel does **not** send them to the ring buffer — dmesg, journald, kmsg —
when a registered audit daemon is listening. This is intentional: it prevents
security events from being lost, delayed, or tampered with by unprivileged
log consumers.

This is documented, expected behavior. Not a bug. Not a RHEL issue.

The consequence: **any monitoring tool that looks for SELinux violations in
journald or dmesg will silently return zero on any system where auditd is
running.** Which is every hardened RHEL, CentOS, AlmaLinux, and Rocky Linux
system in production.

---

### Who This Affects

The affected approach is:
```bash
# This returns nothing on systems with auditd running:
journalctl --since "1 hour ago" | grep "avc:  denied"
dmesg | grep "avc:  denied"
```

This affects:
- Prometheus `node_exporter` (reads /proc and system calls, not audit.log)
- Datadog host agent (reads journald and syslog)
- Netdata (reads /proc and cgroup interfaces)
- Nagios/Icinga SELinux checks (typically grep dmesg or journald)
- Any custom script or runbook that uses `journalctl | grep avc`
- Any monitoring tool not running as root with direct audit.log access

None of these tools will report SELinux denials on a hardened RHEL system
with auditd active. They will show zero. The system will appear clean.

---

### What DashDiag Does

DashDiag reads from `/var/log/audit/audit.log` directly — the same source
the audit daemon uses. It parses Unix timestamps from AVC entries and counts
denials within a configurable time window (default: last hour).

If the audit log is unreadable (non-root), it falls back to journald rather
than silently returning zero.

The fix was two files, ~50 lines. The discovery required a real RHEL machine
with auditd running — something you can't replicate in a CI environment or
find in documentation.

---

### The Positioning

This is not a bug report. Red Hat would close it in minutes — auditd
behaving this way is correct by design.

The story is that common monitoring tools are silently wrong on hardened
Linux systems, and DashDiag isn't.

**The line:**
> Most monitoring tools look for SELinux violations in journald.
> On any hardened RHEL system — which means auditd is running —
> they will always report zero. Not because nothing is happening.
> Because they're reading the wrong place.
> DashDiag reads from the audit subsystem itself.

This is technically verifiable. Anyone with a RHEL machine and 5 minutes
can reproduce it. It's not a claim — it's a demonstration.

---

### Founder Credibility Layer

Andrei contributed to Nagios 20 years ago — including the full Russian
localisation. Nagios is one of the tools silently blind to this issue.

This is not a talking point to attack Nagios. Nagios is 25+ years old and
the auditd/SELinux architecture it doesn't handle was designed well after
Nagios was established. The tool predates the problem. That's the point.

The credibility arc:
> *"I contributed to Nagios 20 years ago. Last week I found a silent gap
> in how it handles SELinux on modern hardened Linux. Built the fix into
> something new."*

This works because:
- It's not an attack — it's evolution. Nagios was right for its era.
- It establishes deep domain knowledge from the inside, not theory.
- It gives the story a human arc: contributor → problem found → new tool.
- It's verifiable — the Nagios Russian localisation is historical record.
- "Still alive after 25 years" is actually a compliment, not a dig.

**Use cases for this angle:**
- HN Show HN — "I was a Nagios contributor" earns immediate credibility
  with the audience that remembers when Nagios was the answer
- First customer conversations with SREs who've used Nagios — they'll
  immediately understand what "reads journald instead of audit.log" means
- LinkedIn founder story — the full-circle angle resonates strongly

**What NOT to do:**
- Don't make it about Nagios being bad — it's about the problem evolving
- Don't name-drop Nagios in a headline — it invites defensive responses
- Use it as context in conversation, not as an attack in copy

**The cleanest version of the line:**
> *"Twenty years ago I contributed to Nagios. Last week, testing DashDiag
> on RHEL, I found something Nagios quietly gets wrong on every hardened
> modern Linux server. Not Nagios's fault — the problem didn't exist when
> Nagios was designed. But it exists now."*

---

### Customer Conversation Framing

Use this in conversations with security-conscious platform engineers:

> "We found something interesting during RHEL validation. Do you run auditd
> on your production servers? Most hardened systems do. It turns out that
> when auditd is active, SELinux denial messages never reach journald —
> the kernel sends them directly to the audit socket instead. Any monitoring
> tool reading journald for SELinux events will report zero, always, on those
> systems. We fixed this by reading from /var/log/audit/audit.log directly.
> Happy to show you the before/after."

Target personas where this resonates:
- Platform engineers at regulated companies (finance, healthcare, gov)
- SREs at companies running RHEL/CentOS/AlmaLinux
- Security engineers who own compliance posture
- Anyone who has ever said "SELinux is always in permissive mode in prod
  because it's too hard to monitor properly"

That last one is the buyer. SELinux in permissive mode because the team
gave up on monitoring it is a real and common failure mode. DashDiag makes
it monitorable without an agent or a SIEM.

---

### Social Media Angles

**Technical (Twitter/X, LinkedIn):**
> Found something unexpected while testing DashDiag on RHEL.
>
> Generated 17 SELinux denials. Ran `dsd health`. Got:
> `KernelSec    OK`
>
> The denials were real. They were in /var/log/audit/audit.log.
> The collector was reading journald — where they weren't.
>
> When auditd runs, the kernel sends AVC messages to the audit socket
> directly. They never reach journald. By design. This is correct behavior.
>
> The consequence: every monitoring tool that reads journald for SELinux
> events silently returns zero on any hardened RHEL system.
>
> We fixed it. DashDiag now reads from the audit subsystem itself.
> Same source as auditd. No intermediary.
>
> This only surfaced because we tested on a real machine with auditd active.
> You can't find this in documentation.

**Founder arc (LinkedIn — strongest version):**
> Twenty years ago I contributed to Nagios.
> Full Russian localisation. I was proud of it.
>
> Last week, testing DashDiag on RHEL, I found something that Nagios
> quietly gets wrong on every hardened modern Linux server.
>
> When auditd is running — and it's running on every properly hardened
> RHEL system — the kernel sends SELinux denial messages directly to the
> audit socket. They never reach journald. Never reach dmesg.
>
> Any monitoring tool reading journald for SELinux events will always
> return zero on those systems. Always. Silently.
>
> Nagios does this. So does Prometheus node_exporter. So did we, until
> we caught it.
>
> Not Nagios's fault. The auditd architecture postdates Nagios by years.
> The tool was right for its time. The problem evolved.
>
> We fixed it by reading from /var/log/audit/audit.log directly —
> same source as auditd itself.
>
> This only surfaces on a real hardened machine. You can't find it in
> documentation. You find it by testing.

**Story-led (LinkedIn long form):**
> While validating DashDiag on RHEL 10.1, I generated some SELinux policy
> violations on purpose — just to see if the tool would catch them.
>
> It didn't.
>
> 17 real AVC denials in /var/log/audit/audit.log.
> `dsd health` reported: `KernelSec OK`
>
> I spent an hour in the source code before I understood why.
>
> When auditd is running — which it is on every hardened RHEL system —
> the kernel sends SELinux denial messages to the audit netlink socket,
> not to the kernel ring buffer. auditd owns that socket exclusively.
> The messages go to /var/log/audit/audit.log and nowhere else.
>
> journalctl? Empty. dmesg? Empty. /proc/kmsg? Empty.
> The system appears clean. It isn't.
>
> This means every monitoring tool that reads journald for SELinux events
> is silently wrong on every properly hardened production Linux server.
>
> We fixed it by reading from the audit log directly — same source as
> auditd itself. The fix was ~50 lines. Finding it took a real machine.
>
> This is why testbeds matter.

**Short punchy (Twitter/X):**
> Fun fact: if auditd is running, SELinux denials never reach journald.
> Kernel sends them to the audit socket directly. By design.
>
> Every monitoring tool reading journald for SELinux events returns zero
> on every hardened RHEL server in production.
>
> We found this the hard way. Fixed it. DashDiag now reads from
> /var/log/audit/audit.log — same source as auditd.

---

### Landing Page Usage

This story works as a **"what we got right"** section:

> **We read from the right place.**
>
> On hardened RHEL systems, SELinux denial messages go to the audit
> subsystem — not journald, not dmesg. auditd intercepts them first.
> Most monitoring tools reading journald will always report zero denials
> on these systems, even when violations are happening.
>
> DashDiag reads from /var/log/audit/audit.log directly — the same source
> as auditd. If your SELinux policy is generating denials, we'll catch them.

Pair with the before/after output from `selinux-blind-spot-evidence.md`.

---

### Evidence File

Full technical evidence — before/after outputs, sample AVC entries,
explanation of Linux Audit Framework behavior:
→ `marketing-assets/selinux-blind-spot-evidence.md`

**System:** RHEL 10.1, auditd 4.0.3, SELinux enforcing (targeted policy)
**Date discovered:** 2026-05-12
**Commit fixing it:** `968a097` — "fix: SELinux denial detection blind when auditd is running"

---


### What happened

A real RHEL 10.1 laptop with AMD Ryzen 7 5800H, 16GB RAM, RTX 3070, k3s running.
Cron jobs scheduled to alternate stress every 30 minutes:

- :00 — CPU + memory + IO + network stress (5 minutes)
- :30 — GPU stress (gpu_burn for 2 minutes)
- `dsd health --terse` ran every 30 minutes, logging to `/root/.dsd/cron.log`

Then I went to sleep.

### What the morning report showed

```
$ sudo dsd health --story
⚡ DashDiag (dsd) v0.2.0-32-g5034efd-dirty
System health — 48 snapshots — 18:03 11.05.2026 to 03:00 12.05.2026 on localhost.localdomain
────────────────────────────────────────────────────────

Events:
  19:00  Memory ↓ CRIT — RAM usage at 98% (0.1 GB free of 15.2 GB total)
  19:00  Thermal ↓ WARN — CPU temperature 89.25°C — elevated (source: k10temp)
  19:00  Processes ↓ CRIT — 11 hung (uninterruptible) processes
  19:00  CPU ↓ CRIT — load average at 257% of capacity (41.14 / 16 CPUs)
  19:00  Swap ↓ CRIT — swap usage at 84% (6.5 GB used)
  19:43  Memory ↑ OK
  19:43  Thermal ↑ OK
  19:43  Processes ↑ OK
  19:43  CPU ↑ OK
  19:43  Swap ↑ OK

  20:00  Memory ↓ CRIT — RAM usage at 97%
  20:00  Thermal ↓ CRIT — CPU temperature 98.375°C — thermal throttling active
  20:00  CPU ↓ CRIT — load average at 272% of capacity (43.58 / 16 CPUs)
  20:00  Processes ↓ CRIT — 6 hung (uninterruptible) processes
  20:00  Logs ↓ CRIT — 5 OOM kills: traefik, coredns, stress
  20:00  IO ↓ WARN — disk nvme1n1 await latency 10.6 ms
  20:00  Swap ↓ CRIT — swap usage at 83% (6.5 GB used)
  20:00  Network ↓ CRIT — gateway ping is 364 ms — severe latency

  20:30  GPU ↓ WARN — RTX 3070 VRAM usage at 95% (7747/8192 MB)
  20:30  Swap ↑ WARN — swap activity detected: 16 pages/s

  ...continues for 7 more hours, alternating CPU/memory stress
        and GPU stress every 30 minutes, every event captured...

  03:00  Memory ↓ WARN — RAM usage at 93%
  03:00  Thermal ↓ WARN — CPU temperature 92°C
  03:00  CPU ↓ CRIT — load average at 266%
  03:00  Processes ↓ CRIT — 5 hung processes
  03:00  Swap ↓ CRIT — heavy swap activity: 29989 pages/s in
```

### Why this output matters

**No log diving.** No `dmesg | grep oom`. No `journalctl --since yesterday`.
No SSH into 4 different commands. One command, full timeline.

**Real incident detection.** Not just thresholds — actual recovery cycles.
The `↓ CRIT` followed by `↑ OK` pattern shows the system degrading and
recovering autonomously. That's how an SRE thinks about incidents.

**Real signals caught:**
- **20:00** — CPU genuinely thermal throttled at 98.375°C. Not a synthetic
  threshold trip. The machine was actually struggling.
- **03:00** — 29,989 pages/s swap activity. That's a number that would make
  any SRE wince. Real production systems in this state are unrecoverable
  without intervention.
- **01:00** — 19.6ms NVMe await latency. NVMe should be sub-5ms. Caught.
- **GPU + CPU stress windows clearly separated.** :00 = CPU stress signature,
  :30 = GPU stress signature. The 30-minute cron cadence is visible in the
  data itself.

### Marketing angle

This is the demo. Show this output to any SRE for 5 seconds and they get it.

The narrative writes itself:
- 9 hours of system stress
- 48 health snapshots
- Every incident captured with timestamps
- Every recovery captured
- One command at the end told the whole story

Three headlines that work with this output:

> **"9 hours. 48 snapshots. Every incident captured. One binary."**

> **"I left a stress test running overnight. This morning I ran one command."**

> **"Your incident response runbook starts with `dsd health --story`."**

### Social media — long form

**LinkedIn / Twitter thread:**

> Spent the night beating up a RHEL server.
>
> Scheduled cron jobs to stress CPU, memory, IO, network, and GPU on a 30-min
> alternating cycle. Each round of stress lasts 2-5 minutes.
>
> Then I went to sleep.
>
> This morning, one command:
>
> `sudo dsd health --story`
>
> [screenshot of overnight story output]
>
> 9 hours, 48 snapshots, every incident captured with timestamps and recovery.
> Memory CRIT, thermal throttling at 98°C, OOM kills, swap thrashing, GPU
> stress — all visible in a single command.
>
> No agent. No cloud. No log diving. Just SSH and one binary.
>
> This is what I'm building. DashDiag — OBD for your server.

### Why this is the right asset

Most observability marketing shows dashboards. Dashboards require setup,
agents, cloud accounts, and pricing pages. DashDiag's marketing shows a
terminal output. Anyone reading it understands in 5 seconds. There's
nothing to set up to imagine using it.

The terminal output IS the product. The marketing IS the product.

### Demo scenarios for landing page

1. **The "morning after" scenario** — overnight stress, morning story
2. **Pre-deploy gate** — `ssh prod 'dsd health' && deploy.sh`
3. **The 1.3 seconds** — `✅ System healthy. Checks passed in 1.3s`
4. **The drilldown** — Hardening WARN with `→ to inspect: ss -tlnp`
5. **The GPU offender** — `dsd gpu` showing gpu_burn process by name + PID

### Validation data — single source of truth

Raw cron log saved at `/root/.dsd/cron.log` on RHEL test machine.
48 snapshots, 9 hours, 2026-05-11 18:03 → 2026-05-12 03:00 EDT.

This file is the reference for:
- Future correlation engine rule design (real incident patterns)
- Marketing screenshots
- Demo content
- Customer conversations ("here's what one night of monitoring looks like")


---

## dsd cis — CIS Compliance Audit Story

### The one-line pitch

> Your server's CIS compliance score in under 5 seconds — with the exact command to fix every failure.

### The problem this solves

Running a CIS audit used to mean one of three things:
- A $10,000/year compliance tool (Qualys, Nessus, CIS-CAT Pro)
- A consultant who shows up, runs a script, and hands you a PDF
- A 200-page CIS PDF and an afternoon with grep

The result is that most Linux servers sit in production for months or years without anyone checking whether they pass even the most basic Level 1 benchmarks. A default Linux Mint install fails 12 out of 28 checks before the sysadmin has touched anything.

DashDiag makes this a 5-second command.

### The demo (real output from a default Linux Mint 22.3 install)

```
$ dsd cis

CIS Ubuntu 22.04 LTS Level 1 — andrei-Legion

  ── SSH
  ❌ 5.2.1     Ensure permissions on /etc/ssh/sshd_config are configured (0600)
           finding: sshd_config mode 644
           to fix:  chmod 600 /etc/ssh/sshd_config
  ❌ 5.2.6     Ensure SSH X11 forwarding is disabled
           finding: X11Forwarding yes
           to fix:  set X11Forwarding no in /etc/ssh/sshd_config
  ❌ 5.2.7     Ensure SSH MaxAuthTries is 4 or less
           finding: MaxAuthTries is 6
           to fix:  set MaxAuthTries 4 in /etc/ssh/sshd_config
  ❌ 5.2.13    Ensure SSH idle timeout is configured (ClientAliveInterval > 0)
           finding: ClientAliveInterval not set — sessions never time out
           to fix:  set ClientAliveInterval 300 and ClientAliveCountMax 3
  ✅ 5.2.10    Ensure SSH root login is disabled
  ✅ 5.2.11    Ensure SSH PermitEmptyPasswords is disabled
  ── NETWORK
  ✅ 3.1.1     Ensure IP forwarding is disabled
  ❌ 3.2.2     Ensure ICMP redirects are not accepted
           finding: accept_redirects is 1 — ICMP redirects accepted
           to fix:  sysctl -w net.ipv4.conf.all.accept_redirects=0
  ── AUDIT
  ❌ 4.1.1     Ensure auditd is installed and running
           finding: auditd not installed or not running
           to fix:  apt install auditd && systemctl enable --now auditd
  ── AUTH
  ❌ 5.4.1     Ensure password expiration is 365 days or less
           finding: PASS_MAX_DAYS is 99999
           to fix:  set PASS_MAX_DAYS 365 in /etc/login.defs
  ── FILES
  ✅ 6.1.1     Ensure /etc/passwd permissions are 644 or stricter
  ✅ 6.1.2     Ensure /etc/shadow permissions are 000 or 640

  28 rules — 15 pass  12 fail  1 skipped

  Tip: dsd cis --fail-only to see only failures.
```

### Why this output is the marketing

The terminal output IS the pitch. No dashboard to set up. No agent to install. No cloud account. Anyone who reads it understands the product in 5 seconds.

Every failure line follows the same pattern:
1. The CIS rule ID — traceable to the benchmark document
2. What was found (concrete, specific)
3. The exact command to fix it

That third point is the differentiator. Most compliance tools tell you what's wrong. DashDiag tells you what to type.

### The numbers that matter

- 28 CIS Level 1 checks in a single command
- 12 failures on a default Linux Mint install (zero hardening applied)
- 5 seconds to run (no network, no cloud, no agent)
- 0 dependencies beyond the dsd binary

### What gets checked

| Section | Count | Examples |
|---------|-------|---------|
| SSH configuration | 17 | sshd_config permissions, AllowUsers, X11Forwarding, MaxAuthTries, idle timeout, banner |
| Network parameters | 4 | IP forwarding, source routing, ICMP redirects, martian logging |
| Audit logging | 2 | auditd installed and running, rules configured |
| Password policy | 1 | PASS_MAX_DAYS <= 365 |
| File permissions | 3 | /etc/passwd, /etc/shadow, /etc/group |
| User accounts | 2 | No NIS legacy entries, root is only UID 0 |

### Commands to feature in copy

```bash
dsd cis                  # Level 1 — full output
dsd cis --fail-only      # only the failures + their fix commands
dsd cis --level 2        # Level 1 + Level 2 checks
dsd cis --json           # machine-readable output for CI/CD pipelines
```

### Positioning

**Against Qualys / Nessus / CIS-CAT Pro:** Those are $10k/yr SaaS tools with agents, dashboards, and account setup. dsd cis runs in 5 seconds, touches nothing outside the local machine, and requires zero setup. For a sysadmin who wants to spot-check a server before handing it to a client, or a startup that needs to pass a vendor security questionnaire, dsd cis is the answer. The enterprise tools are for compliance programs. dsd cis is for engineers.

**Against Lynis:** Lynis is the closest open-source equivalent. It runs hundreds of checks and produces a long scrolling report. dsd cis is opinionated — 28 Level 1 checks, mapped to CIS IDs, with exact remediation per finding. Less comprehensive than Lynis, but faster to act on.

**The key phrase:** "No consultant required."

### Pro tier angle

The free tier runs `dsd cis` with full Level 1 output. Pro gates:
- `--level 2` (advanced checks)
- `--json` (CI/CD integration)
- STIG ID mapping (`--stig`)

The JSON output is the enterprise unlock: pipe it into your own reporting, Slack alerts, or a compliance dashboard. That's a $79/yr justification on its own for any team that needs to demonstrate CIS compliance to a customer or auditor.

### Social angles

**Reddit / HN:**
> Title: I ran CIS Level 1 against my server and found 12 failures in 5 seconds
>
> Body:
> Just added a `dsd cis` command to DashDiag.
>
> Ran it against a default Linux Mint install (no hardening applied):
> 15 pass, 12 fail, 1 skipped.
>
> Every failure shows the CIS rule ID, what was found, and the exact command to fix it.
> Takes under 5 seconds, no root required, nothing leaves the machine.
>
> The 12 failures on a default install surprised me: sshd_config was 644 (should be 600),
> X11Forwarding was on, no idle timeout, PASS_MAX_DAYS was 99999, auditd not installed.
> These are the defaults on most distros. Nobody fixes them because nobody checks.
>
> [link to GitHub]

**LinkedIn:**
> Most servers in production have never been audited against CIS benchmarks.
>
> Not because sysadmins don't care. Because the tools are expensive, slow, or require an agent.
>
> I added a `dsd cis` command to DashDiag. 28 CIS Level 1 checks. Under 5 seconds.
> Every failure shows the exact command to fix it.
>
> A default Linux Mint install fails 12 checks before you've touched anything.
> That's the baseline most production servers start from.

**Twitter/X:**
> ran `dsd cis` on a fresh Linux Mint install
> 12 CIS Level 1 failures before touching anything
> every one includes the exact fix command
> takes 5 seconds, no root, nothing leaves the machine

### Demo scenarios for landing page

1. **The spot-check** — sysadmin SSHes into a new server before handing it to a client: `dsd cis --fail-only`
2. **The CI gate** — `dsd cis --json | jq '.fail == 0'` in a pipeline
3. **The before/after** — run dsd cis, apply fixes, run again, 0 failures
4. **The vendor questionnaire** — "we need to demonstrate CIS compliance" → `dsd cis --json > cis-audit-2026-05.json`


### STIG mode — the government contractor angle

Running `dsd cis --stig` switches from CIS IDs to DISA STIG IDs (V-238xxx format). The underlying checks are largely the same. The output is not.

```
$ dsd cis --stig

DISA STIG Ubuntu 20.04 LTS Level 1 — my-server

  ── SSH
  ❌ V-238201  The SSH daemon configuration file must have mode 0600 or less permissive
           finding: sshd_config mode 644
           to fix:  chmod 600 /etc/ssh/sshd_config
  ❌ V-238213  The SSH daemon must use FIPS-approved ciphers
           finding: Ciphers not explicitly configured — defaults may include weak ciphers
           to fix:  set Ciphers aes128-ctr,aes192-ctr,aes256-ctr,...
  ❌ V-238214  The SSH daemon must use FIPS-approved MACs
           finding: MACs not explicitly configured
  ✅ V-238210  The SSH daemon must not allow root logins
  ✅ V-238211  The SSH daemon must not allow empty passwords

  36 rules — 17 pass  17 fail  1 manual  1 skipped
```

**Why this matters for a different audience:**

CIS is a best-practice standard — any sysadmin can choose to follow it.
STIG is a US Department of Defense requirement. If you work on a government contract, handle federal data, or sell software to DoD or civilian agencies, you are not choosing whether to comply — you are required to. Non-compliance is a contract risk, not a recommendation.

The tools that produce STIG-format output are expensive:
- **CIS-CAT Pro** — the official CIS tool, $2,000-$10,000/yr, Windows-first
- **SCAP Workbench / OpenSCAP** — open source but requires SCAP content files, XML profiles, and meaningful setup time
- **Nessus / Qualys** — $10,000+/yr, agent-based, SaaS

`dsd cis --stig` is, as far as we know, the only free CLI tool that outputs DISA STIG IDs with exact remediation commands in a single binary with zero setup.

**The STIG-specific checks that CIS doesn't cover:**
- Ciphers must be explicitly FIPS-approved (no arcfour, blowfish, 3des)
- MACs must be explicitly FIPS-approved (no md5, sha1, umac-64)
- KexAlgorithms — no SHA-1 based group exchanges
- PASS_MAX_DAYS must be ≤ 60 (stricter than CIS Level 1 which allows 365)
- PASS_MIN_DAYS must be ≥ 1 (minimum password age — STIG only)
- PASS_WARN_AGE must be ≥ 7 (7-day warning — STIG only)
- ClientAliveCountMax must be 0 (STIG is stricter than CIS on idle sessions)

**The search terms this audience uses:**
They don't search "CIS benchmark tool". They search:
- "DISA STIG Ubuntu scanner"
- "V-238217 check automated"
- "Ubuntu STIG compliance tool free"
- "FedRAMP SSH hardening script"
- "DoD STIG audit CLI"

These are high-intent searches from people with a real compliance deadline.

**The pitch to this audience in one line:**
> DISA STIG compliance audit. One binary. No setup. Every failure with an exact fix.

**Social angle (LinkedIn, government/contractor audience):**
> If you're working on a government contract and need STIG compliance,
> you know the options: CIS-CAT Pro ($$$), OpenSCAP (complex setup),
> or a consultant with a spreadsheet.
>
> I added `dsd cis --stig` to DashDiag.
> DISA STIG Ubuntu 20.04 LTS V1R11 checks. V-238xxx IDs.
> One binary. Under 5 seconds. Every failure with the exact remediation command.
>
> A default Ubuntu install fails 17 STIG checks out of the box.
> `dsd cis --stig --fail-only` shows you exactly what to fix.

### Strategic note — gating decision

Before the landing page goes live, decide: is `dsd cis` free or Pro?

Current build: everything free.

Recommended: make the core output free, gate `--level 2` and `--json` behind Pro.
Reason: the free output builds trust and demonstrates value. The JSON output (CI/CD integration) and Level 2 (advanced checks) are the things a paying customer actually needs. This gives a clear free → Pro upgrade path without removing value from the free tier.

---

## The Problem Nobody Knew They Had — dsd timeline Story

*Real finding on RHEL 10.1, May 19 2026*

### The insight

A server running k3s and containers. Load at 7.25. No failed services. No alerts. Health checks green across the board. An admin glancing at the dashboard would move on.

`dsd timeline` found 500 kernel errors in 60 seconds that nobody knew about.

### What happened

`veth1` is a virtual ethernet pair — one end inside a container, the other on the host. When k3s schedules pods rapidly, it creates and destroys veth pairs in bursts. Each creation floods `systemd-udevd` with netlink events. The kernel's netlink receive buffer fills faster than it can drain. The kernel returns `ENOBUFS — No buffer space available`. `udevd` retries. Gets rejected. Retries. 271 times in one burst. 229 times in the next.

The whole thing happens silently, deep in the kernel event layer. No failed service. No high CPU. No alert. Just a server gradually getting noisier.

### The output

```
$ dsd timeline

⏱  Incident timeline — last 1h

  Load average:
  ⚠️  21:19:46 (now)    load: 7.25  5.86  5.50

  TIME       LEVEL   UNIT             MESSAGE
  ──────────────────────────────────────────────
  20:36:24   jrnl    systemd-udevd    veth1: Failed to get link information:
                                      No buffer space available  ×271
  20:37:00   jrnl    systemd-udevd    veth1: Failed to get link information:
                                      No buffer space available  ×229

⚠️  2 WARN event(s) found in 2.5s
```

### Why this matters for positioning

The admin would not have run `journalctl -u systemd-udevd --since "1 hour ago" | grep ENOBUFS` preemptively. Nobody does. That's a search you run *after* the incident has escalated enough to be visible — intermittent container connectivity failures, slow pod startup, unexplained latency. By then it's an outage.

`dsd timeline` merges the journal stream, dmesg stream, and load trace, collapses 500 duplicate lines into two entries with counts, and presents the pattern in 2.5 seconds. **The admin didn't know to ask for this. DashDiag found it anyway.**

The fix: `sysctl -w net.core.rmem_max=134217728`. Under two seconds to apply.

### The one-liner pitch for this story

> The server felt fine. `dsd timeline` found 500 silent kernel errors nobody knew about. One sysctl to fix.

### Social media angles

**Twitter/X:**
> Server load: 7.25. No alerts. Health checks green.
>
> Ran `dsd timeline`.
>
> Found 500 kernel errors in the last 60 seconds.
> Silent ENOBUFS floods on the container veth interface.
> Nobody would have found this until containers started dropping connections.
>
> Fix: one sysctl. 2 seconds.
> Finding it: `dsd timeline`. 2.5 seconds.

**LinkedIn:**
> I was looking at a RHEL 10.1 server running k3s. Load sitting at 7.25.
> No failed services. CPU fine. Disk fine. Every health check green.
> The kind of state where you move on and check something else.
>
> Then I ran `dsd timeline`.
>
> 500 kernel ENOBUFS errors in the last 60 seconds.
> `systemd-udevd` hammering the netlink buffer as k3s created container veth pairs.
> Silent. No alert. No error message anywhere obvious.
> The kind of thing that eventually shows up as "intermittent container networking issues"
> in a post-mortem, with no clear start time.
>
> The fix was one sysctl. Applied in under 2 seconds.
> Finding it took `dsd timeline` 2.5 seconds.
>
> The tool doesn't wait for you to ask the right question.

### Why this is the canonical "synthesis gap" demo

This is the finding that best demonstrates the core DashDiag value proposition:
admins can read individual metrics accurately but cannot connect them into a causal
narrative under pressure. The load was elevated but no single check explained why.
`dsd timeline` connected the dots — journal events, load trace, timestamps — without
the admin knowing to look there.

This is the synthesis gap. This is what DashDiag closes.
