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


---

## Four LVM Failures, One Command — dsd disk Story

*Real finding on RHEL 10.1, May 19 2026*

### The setup

A test server running k3s with an LVM configuration that looked healthy at a glance:
- Two 1TB NVMe drives (SK Hynix, both SMART PASSED)
- VG `rhel` for the OS (100% full — already a known problem)
- VG `dsd_test` with a thin-provisioned pool, several snapshots, and a RAID1 mirror

The kind of setup that accumulates complexity over time. The kind nobody has
a full mental model of.

### What was broken (and silent)

Four things were wrong simultaneously:

1. **Thin pool at 100%** — `dsd_test/thin_pool` had been filled to capacity
   by a cascade of snapshots preserving overwrites. The pool was full. Any
   new write to any thin volume would fail silently or block.

2. **Filesystem at 100%** — `/mnt/thin_test` (backed by the thin pool) was
   completely full. Writes were failing.

3. **Missing PV** — one Physical Volume in `dsd_test` had been detached
   (simulating a drive pull). LVM knew the PV was missing and the VG was
   running in a degraded state with data at risk.

4. **RAID1 degraded** — `raid_fail`, a RAID1 LV with one leg on the missing
   PV, was running with only one copy of the data. No redundancy. No alerts.

None of these generated a notification. The server kept running.

### The output

```
$ sudo dsd disk --plain

Physical Drives — 2 found
  nvme1n1  1TB  NVMe  [SKHynix_HFS001TDE9X084N]
  nvme0n1  1TB  NVMe  ✅ SMART: PASSED  wear:0%  spare:100%  temp:55°C

Filesystems (17)
  ❌  /mnt/thin_test    ext4   31.5G / 31.5G  (100%)

LVM (2 VG(s))
  ✅  dsd_test  957.9GB total  777.6GB free  (81%)
       ❌ 1 missing PV(s) — data at risk
  ❌  rhel      952.3GB total  0.0GB free  (0%)

  Thin pools (1):
  ❌  dsd_test/thin_pool   Data: 100%  Meta: 45%

  RAID/mirror LVs (2):
  ❌  dsd_test/raid_fail   raid  DEGRADED
  ✅  dsd_test/raid_test   raid  in sync

⚠️  3 disk concern(s) found in 0.3s
```

0.3 seconds. Four failures. Prioritised by severity.

### What "no dsd" looks like

Without dsd, finding these four problems requires:

```bash
# thin pool usage
lvs -o lv_name,data_percent,snap_percent

# missing PV
vgs --reportformat json | grep partial
pvs | grep unknown

# RAID health
lvs -o lv_name,lv_attr,copy_percent,lv_health_status
# look for 'p' in position 9 of lv_attr — means "partial"

# filesystem full
df -h | grep 100%
```

Four separate commands. You have to know to run each one. You have to know
what "partial" in position 9 of `lv_attr` means. You have to know that
`data_percent=100` on a thin pool means imminent write failures, not just
"getting full."

Most admins do not run these commands preemptively. They run them after
something breaks.

### Why RAID degraded is the most dangerous

A RAID1 with one leg missing is running with zero redundancy. If the remaining
drive has a bad sector during a read, data is gone. There's no second copy.

LVM will not alert you. `dmesg` will not alert you. The system just runs.

`dsd disk` checks `lv_health_status` on every RAID/mirror LV on every run.
It surfaces `partial` as `DEGRADED` in plain English. No knowledge of
`lv_attr` position encoding required.

### The one-liner for this story

> Four LVM failures — thin pool full, missing drive, degraded RAID,
> filesystem at 100% — all silent. `dsd disk` found them in 0.3 seconds.

### Social angles

**Twitter/X:**
> RAID degraded. Thin pool full. Drive missing. Filesystem at 100%.
>
> All silent. No alerts. Server running fine.
>
> `sudo dsd disk`
>
> 0.3 seconds. All four. Plain English.
>
> dashdiag.sh

**LinkedIn:**
> I deliberately broke four things in an LVM setup on a test server.
>
> — Thin pool filled to 100% (writes would silently fail)
> — RAID1 running with one leg missing (zero redundancy)
> — A Physical Volume detached (VG partially degraded)
> — The underlying filesystem at 100% (full)
>
> None of them generated an alert. The server kept running.
>
> Then I ran `sudo dsd disk`. 0.3 seconds later:
> four ❌ entries, plain English, exactly what was wrong.
>
> The knowledge required to find these manually: lv_attr position encoding,
> thin pool data% vs snap%, vgs partial state, SMART vs LVM vs filesystem
> layering. Most admins have some of it. Nobody has all of it under pressure
> at 2am.
>
> That's what DashDiag is for.

### Evidence files

```
marketing-assets/rhel101-session11-data/dsd-disk-lvm-healthy.txt  ← before
marketing-assets/rhel101-session11-data/dsd-disk-lvm-broken.txt   ← after (all 4 failures)
```


---

## Story 7: The Backup That Was Quietly Broken From Day One (Linux Mint 22.3)

**Platform:** Linux Mint 22.3 (Zena), fresh install, multi-boot machine  
**Time to find:** 2 seconds  
**How it would normally be found:** When the next backup fails, or when the system can't write to /boot  

### What happened

Fresh Mint 22.3 install on a machine that previously had Ubuntu on a separate NVMe disk. During setup, Mint's installer created the usual LVM layout on the second drive. Timeshift — Mint's built-in backup tool — ran automatically on first boot and configured itself without prompting.

Everything looked normal. Timeshift showed "backup complete." The desktop was clean. `df -h` showed the root filesystem at 1%.

Then we ran `dsd health`:

```
CRIT: Disk: disk usage at 100% on /run/timeshift/2218/backup (/dev/nvme0n1p2)
   Largest directories:
   1.8G  /run/timeshift/2218/backup/timeshift
    63M  /run/timeshift/2218/backup/initrd.img-7.0.0-15-generic
    61M  /run/timeshift/2218/backup/initrd.img-7.0.0-14-generic
```

### What was actually wrong

Timeshift had auto-detected the old Ubuntu disk's 2GB boot partition (`nvme0n1p2`) — a separate ext4 partition from the previous OS — and silently selected it as the backup target. It was already completely full.

The backup appeared to succeed because Timeshift wrote what it could and didn't surface the overflow as an error in its GUI. The backup was incomplete and the 2GB partition was 100% full.

What an admin sees without dsd:
- Timeshift: ✅ Last backup: today
- Disk usage (`df -h /`): 1% used
- Nothing in system logs

What dsd found in 2 seconds on first run:
- `/dev/nvme0n1p2` at 100% full
- Exact path: `/run/timeshift/2218/backup`
- Largest files listed — immediately actionable

### Why this matters

This is the canonical "problem you didn't know to ask about." The admin didn't misconfigure anything — Timeshift made a reasonable-looking automatic choice that happened to be wrong. The backup looked fine. The system ran fine. Without dsd, this would have been discovered when:

1. A future backup failed with a cryptic error about disk space
2. The system couldn't update the bootloader (also lives on that partition)
3. Something worse

The knowledge required to find this manually: know that Timeshift mounts its backup target at `/run/timeshift/<pid>/backup`, know to run `df -h` specifically on that mountpoint, know to correlate it with the `/dev/nvme0n1p2` device from the previous OS install. Most admins would never connect these dots on a machine that "seems fine."

That's what DashDiag is for.

### Evidence files

```
marketing-assets/mint22-data/health.json    ← full health output with CRIT
marketing-assets/mint22-data/disk.json      ← disk collector showing the full partition
```

### Social post angle

> Fresh Linux Mint install. Timeshift said "backup complete."
> 
> I ran `dsd health`. First result:
> 
> ❌ disk usage at 100% on /run/timeshift/2218/backup
> 
> Timeshift had silently picked the wrong partition — a 2GB leftover from the previous OS.
> The backup was broken from day one. Everything looked fine.
> 
> dsd found it in 2 seconds.



---

## Story 7 — Addendum: What Timeshift Actually Does (It's Worse)

After publishing the story we checked the actual logs. Timeshift doesn't say "backup complete" — **it says nothing at all to the system.**

### What Timeshift logged

```
[07:19:54] E: Error creating directory .../snapshots-boot:     No space left on device
[07:19:54] E: Error creating directory .../snapshots-hourly:   No space left on device
[07:19:54] E: Error creating directory .../snapshots-daily:    No space left on device
[07:19:54] E: Error creating directory .../snapshots-weekly:   No space left on device
[07:19:54] E: Error creating directory .../snapshots-monthly:  No space left on device
[07:19:54] E: Error creating directory .../snapshots-ondemand: No space left on device
```

Six errors in its own private log file at `/var/log/timeshift/*.log`. Then:

```
[07:19:55] Status: NO_SNAPSHOTS_HAS_SPACE
```

It concluded it has space and zero snapshots — reporting the device is available while simultaneously failing to write to it.

### How the failure was communicated to the user

```
pkexec: notify-send -t 10000 -u low -i gtk-dialog-info TimeShift "Failed to create snapshot"
```

A desktop notification. **10 seconds. Low urgency. Gone.**

- `journalctl -u timeshift` → no entries
- `/var/log/syslog` → nothing
- `dmesg` → nothing
- `dsd logs` → nothing

The only persistent evidence was Timeshift's own private log file, which no monitoring tool reads, and the 100% full partition that dsd found.

### The corrected story

> Fresh Mint install. Timeshift silently failed — 6 errors, no snapshots created.
> The only notification: a desktop popup that vanished after 10 seconds.
> No journal entry. No syslog. No alert.
>
> `dsd health` found the evidence Timeshift left behind:
> ❌ disk usage at 100% on /run/timeshift/2218/backup
>
> The backup was broken from day one. The system had no idea.


---

## Story 8 — Fresh Desktop OS, First Run, 15 Problems (Linux Mint 22.3)

**Platform:** Linux Mint 22.3 (Zena), kernel 6.14, fresh install  
**Time to find everything:** 1.3 seconds  
**How many issues the admin knew about:** 0  

### Setup

New Linux Mint install on a developer laptop. The installer finished, Timeshift ran, the desktop came up. Everything looked fine. This is day one.

We ran one command:

```
sudo dsd health
```

1.3 seconds later:

---

### Finding 1: The backup was already broken

```
❌ Disk: disk usage at 100% on /run/timeshift/2218/backup (/dev/nvme0n1p2)
```

Timeshift had silently picked the wrong partition — a 2GB leftover from the previous OS on a second drive. Six "No space left on device" errors in its own private log. No journal entry. No syslog. A 10-second desktop popup that had already vanished.

The backup was broken from the first boot. The admin had no idea.

---

### Finding 2: No firewall

```
⚠️ Firewall: nftables is installed but no rules are active — host is unprotected
```

Mint ships with nftables installed but no rules active and ufw disabled. The machine was completely open the moment it got a network connection. No port blocking, no connection filtering, nothing.

This is the default. Most Mint users never touch it.

---

### Finding 3: 22 seconds wasted on every boot

```
⚠️ Systemd: slow boot unit: gpu-manager.service took 11.5s
⚠️ Systemd: slow boot unit: plymouth-quit-wait.service took 10.8s
```

Two services adding over 22 seconds to every boot:

- **gpu-manager** — scans for NVIDIA/AMD GPUs for PRIME switching on Optimus laptops. On a laptop with a single active GPU, it runs anyway and takes 11.5 seconds doing nothing useful.
- **plymouth-quit-wait** — the boot splash screen, waiting for something that never signals fast enough on hybrid GPU systems.

Fix for both is one command each. Neither is on by default, neither has any visible impact if disabled on a single-GPU system. dsd identifies both, explains why, and gives the exact fix command.

---

### Finding 4: AppArmor security policies not enforcing

```
⚠️ KernelSec: 6 AppArmor profile(s) in complain mode — not enforcing
⚠️ KernelSec: 1 AppArmor denial(s) in the last hour
```

LibreOffice, Transmission, and four related profiles were all in complain mode — logging policy violations but not blocking them. One denial had already happened in the last hour. On a fresh install, before any user software was run.

Complain mode is fine for development. For a machine where you actually use the software, you want enforce mode.

---

### Finding 5: Disk almost full despite 953GB drive

```
⚠️ LVM: volume group vgmint is 98% full (22.1 GB free of 953.4 GB)
ℹ️ LVM: inactive volume group ubuntu-vg is 11% full — no LVs mounted (old OS partition?)
```

Two separate LVM problems:

1. The root VG (`vgmint`) has 953GB total but only 22GB free — 98% full. The default Mint installer only allocated 929GB to the root LV, leaving the rest unallocated.
2. The old `ubuntu-vg` from the previous OS is still sitting there, consuming 100GB of the second disk, doing nothing.

Neither shows up in `df -h` the way a normal admin would check.

---

### Finding 6: SSH hardening — 4 issues, all defaults

```
⚠️ SSH allows password authentication
⚠️ SSH weak MAC(s): umac-64@openssh.com, hmac-sha1
ℹ️ LoginGraceTime is 120s (recommend ≤60s)
ℹ️ X11Forwarding enabled
ℹ️ AgentForwarding enabled
ℹ️ SSH idle timeout not set
```

Six SSH findings, all from Mint's default sshd config. None of these were misconfigured — they're the defaults shipped with the OS. hmac-sha1 has been broken for years. Password auth on a developer machine is a credential leak waiting to happen.

---

### The full picture

On a fresh desktop OS install, before the user had done anything:

| Category | Issues found |
|---|---|
| Backup | ❌ Broken from day one, silent failure |
| Firewall | ⚠️ No rules active |
| Boot speed | ⚠️ 22s wasted on every boot |
| Security policy | ⚠️ AppArmor not enforcing, 1 denial already |
| Disk | ⚠️ Root VG 98% full, 100GB orphan |
| SSH | ⚠️ 6 hardening issues, all defaults |
| Kernel tuning | ⚠️ swappiness, rmem_max wrong |

**Total time: 1.3 seconds.**

None of these would surface a ticket. None would cause an immediate failure. All of them would eventually cause a problem — the backup when you actually need it, the firewall when someone scans your IP, the boot time every morning, the AppArmor denial when an application gets exploited.

This is the whole point of DashDiag. Not finding fires. Finding the kindling.

### Social post angle

> Fresh Linux Mint install. Ran `dsd health`.
> 1.3 seconds later:
>
> ❌ Timeshift backup broken (full partition, no alert)
> ⚠️ No firewall rules active
> ⚠️ 22 seconds wasted on every boot (gpu-manager + plymouth)
> ⚠️ AppArmor: 6 profiles not enforcing, 1 denial already
> ⚠️ LVM root VG 98% full
> ⚠️ SSH: password auth, hmac-sha1, no idle timeout
>
> The OS installed fine. Everything looked normal.
> That's the problem dsd solves.

### Evidence files

```
marketing-assets/mint22-data/health.json     ← full JSON output
marketing-assets/mint22-data/timeshift-failure.log  ← Timeshift's own error log
```


---

## Story 9 — The Update Manager That Wouldn't Tell You (Linux Mint 22.3)

**Platform:** Linux Mint 22.3 (Zena), fresh install  
**Time to find:** 2 seconds  
**What the built-in tool showed:** "A new version of Update Manager is available"  

### What happened

Fresh Mint install. The Update Manager icon appeared in the system tray. We opened it.

It showed one item:

> **mint-upgrade-info 1.3.0**  
> "A new version of Update Manager is available"

That's it. The only thing the Update Manager wanted to tell us was that it needed to update itself first. No security advisories. No CVE list. No severity. Just: update me before I can help you.

We ran `dsd cve --all` instead.

```
Found 151 pending security advisory(ies)

🔴 CRITICAL (9)
  libc6           [2.39-0ubuntu8.6]  →  2.39-0ubuntu8.7
  libc-bin        [2.39-0ubuntu8.6]  →  2.39-0ubuntu8.7
  libssl3t64      [3.0.13-0ubuntu3.6]  →  3.0.13-0ubuntu3.9
  openssl         [3.0.13-0ubuntu3.6]  →  3.0.13-0ubuntu3.9
  sudo            [1.9.15p5-3ubuntu5.24.04.1]  →  patched
  pkexec          [124-2ubuntu1.24.04.2]  →  patched
  polkitd         [124-2ubuntu1.24.04.2]  →  patched
  libpolkit-*     [124-2ubuntu1.24.04.2]  →  patched

⚠️  IMPORTANT (29)
  python3.12, libcurl4, libexpat1, webkit2gtk, bind9-libs,
  libxml2, libssh-4, gnutls, avahi...

→ to fix all: apt-get upgrade
```

### The problem

Linux Mint's Update Manager has a bootstrap problem: it shows you a meta-update about itself before it will show you anything useful. Until you update the Update Manager, you don't see the security advisories. You just see the prompt to update the tool.

The machine had:
- **glibc** pending patch (CVE-class: memory safety)
- **OpenSSL** with 2 confirmed CVEs in the changelog
- **sudo** — privilege escalation tool with a pending security patch
- **polkit/pkexec** — the tool used to run GUI applications as root
- **WebKit** — browser engine (remote code execution class)

None of this was visible in the Update Manager. The admin would see "no updates" until they first clicked through the meta-update.

### Why this matters

The Update Manager's job is to tell you what's wrong. When its first message is "update me before I can tell you what's wrong," it's not doing its job. A freshly installed machine with 9 CRITICAL security updates pending looked clean to the Update Manager.

`dsd cve --all` found all 151 in 2 seconds without any prerequisites.

### Social post angle

> Fresh Mint install. Opened the Update Manager.
>
> It said: "A new version of Update Manager is available."
> That's all. No security info. Just: update me first.
>
> Ran `dsd cve --all` instead:
>
> 🔴 CRITICAL (9): glibc, OpenSSL, sudo, polkit, pkexec
> ⚠️  IMPORTANT (29): Python, curl, WebKit, libxml2, bind9...
>
> 151 pending security updates.
> The built-in tool showed zero of them.

### Evidence files

```
marketing-assets/mint22-data/cve.json        ← full cve output
marketing-assets/mint22-data/cve-all.json    ← all 172 advisories
```


---

## Story 9 — Addendum: After the 1.2GB Update, Still Not Done

After updating through the Update Manager (1.2GB downloaded, ~150 packages), we ran `dsd cve --all` again.

```
Found 3 pending security advisory(ies)

⚠️  IMPORTANT (1)
  libgnutls30t64   [3.8.3-1.1ubuntu3.5]  →  3.8.3-1.1ubuntu3.6

   LOW (2)
  rsync            [3.2.7-1ubuntu1.2]    →  3.2.7-1ubuntu1.4
  openvpn          [2.6.19-0ubuntu0.24.04.1]  →  2.6.19-0ubuntu0.24.04.2
```

Three packages with real CVEs still unpatched after the "full" update.

**What was in them:**
- `libgnutls30t64` — CVE-2026-33846, CVE-2026-42009 (DTLS buffer issues)
- `rsync` — CVE-2025-10158, CVE-2026-29518, CVE-2026-41035, CVE-2026-43617
- `openvpn` — CVE-2026-35058, CVE-2026-40215

**Why they were skipped:**  
The Update Manager uses `apt-get upgrade` which skips packages that require installing or removing additional dependencies. openvpn depends on the updated libgnutls — the resolver deferred all three rather than resolve the chain.

The fix is `apt-get dist-upgrade` (or `apt full-upgrade`). The Update Manager doesn't run that by default.

**Three layers of the same problem:**
1. Update Manager said "update me first" — hid 151 advisories
2. After the 1.2GB update — 3 packages with 8 CVEs left behind by `apt upgrade`
3. `dsd cve --all` found them both times, immediately

After running `sudo apt-get dist-upgrade`, `dsd cve --all` returned clean.

## Story 10 — The Containers Your Monitoring Doesn't Know Exist

### What We Found

While validating DashDiag on AlmaLinux 9, we set up a Podman container managed
as a systemd service using the modern quadlet format — a `.container` file in
`/etc/containers/systemd/`. The container failed to start (image pull failed
inside an LXC). Then we ran every standard container monitoring tool available.

None of them saw it.

`docker ps` — not applicable, no Docker installed.
`podman ps` — empty. Zero containers listed.
`podman ps -a` — empty. The container never fully started.
Socket-based monitoring (Prometheus Podman exporter, any tool using the Podman API) — empty.

Then we ran `dsd docker`:

```
Runtime: podman

Containers (0 total)
  ✅  no containers

[Podman quadlets]
  ❌  test-nginx     failed    test-nginx.service
     → systemctl status test-nginx.service
     → journalctl -u test-nginx.service -n 20
```

And `dsd health`:

```
WARN: Docker: 1 Podman quadlet(s) failed: test-nginx
```

The container was failing. It had been failing since boot. Every standard
monitoring tool returned clean. DashDiag found it in under a second.

---

### Why It Happened — The Socket Assumption

Every container monitoring tool in existence is built around one assumption:
containers are visible via the container runtime socket.

Docker socket: `/var/run/docker.sock`
Podman socket: `/run/podman/podman.sock`

Query the socket, get the containers. That's the model.

Quadlets break this model completely.

Podman quadlets are containers defined as systemd unit files. When you create
`/etc/containers/systemd/nginx.container`, systemd generates `nginx.service`
automatically and manages the container lifecycle directly — no socket involved.
The container is started, stopped, and restarted by systemd, not by Podman
daemon commands.

The consequence: **a quadlet container that fails to start never appears in
`podman ps`, never appears in `podman ps -a`, and is completely invisible to
any monitoring tool that queries the Podman socket.** The socket doesn't know
it exists because the socket was never involved.

The only place this failure is visible is in the systemd unit state and the
journal. Which is where DashDiag looks.

---

### Who This Affects

Quadlets are the recommended way to run containers on RHEL 9+, AlmaLinux 9+,
Rocky Linux 9+, and any RHEL-based system following Red Hat's current guidance.
Red Hat has been pushing quadlets as the production-ready replacement for
`podman generate systemd` since Podman 4.4 (2022). On any modern RHEL-family
server, quadlets are the right answer.

The affected monitoring approach is:

```bash
# These all return empty on a quadlet-only host with a failed container:
podman ps -a
curl --unix-socket /run/podman/podman.sock http://localhost/containers/json
# Prometheus Podman exporter: /metrics shows 0 containers
# Datadog agent: reports no containers
# Any tool using the Podman REST API: empty container list
```

This affects:
- Prometheus Podman exporter (queries socket)
- Datadog agent container monitoring (queries socket)
- Netdata container module (queries socket)
- Any custom healthcheck script using `podman ps`
- Any monitoring tool built on the Docker/Podman REST API

None of these tools will report a failed quadlet container. The monitoring
returns clean. The container is broken.

---

### What DashDiag Does Differently

DashDiag doesn't trust the socket as the single source of truth.

`dsd docker` scans `/etc/containers/systemd/` directly for `.container` and
`.pod` files — no socket required. For each quadlet file found, it derives
the corresponding systemd service unit name and checks its state via systemctl.

Critically, this works even when the Podman socket is completely inactive.
`dsd health` uses a fast file-existence check (`PodmanQuadletsPresent()`) to
decide whether to include the container collector — so a pure-quadlet host
with no socket running still gets full container health coverage.

The check is:
1. Does `/etc/containers/systemd/` contain any `.container` or `.pod` files?
2. If yes: check each derived service unit state via systemctl
3. Any failed unit → WARN in `dsd health`, details in `dsd docker`

Three lines of logic. Surfaces what every other tool misses.

---

### The Positioning

This is the same class of finding as the SELinux/auditd blind spot (Story 3):
the architecture changed, the tools didn't.

Quadlets became the RHEL standard in 2022. Monitoring tools built around the
socket assumption haven't caught up. The gap between "what's actually running"
and "what monitoring reports" is invisible until something breaks.

DashDiag finds the gap.

**One-liner:** Your containers can be failing right now and every monitoring
tool you have reports clean. DashDiag checks where the failure actually is.

---

### Social Media Angles

**Technical (Mastodon/LinkedIn):**
> A Podman quadlet container failing silently.
>
> `podman ps -a` — empty.
> Prometheus Podman exporter — 0 containers.
> Datadog — nothing.
>
> `dsd docker`:
> ```
> [Podman quadlets]
>   ❌  nginx    failed    nginx.service
> ```
>
> Quadlets are managed by systemd, not the socket. Every tool that queries
> the socket misses them. dsd checks where the failure actually is.

**Short hook:**
> Your container monitoring is blind to quadlets.
> podman ps returns empty. The container is failing.
> One architectural assumption. Total blind spot.
> dsd docker finds it anyway.

**Founder voice (LinkedIn):**
> I built DashDiag to find problems that other tools miss.
>
> Today's finding: Podman quadlets — the modern RHEL way to run containers —
> are completely invisible to every monitoring tool that uses the Podman socket.
> Including Prometheus. Including Datadog. Including `podman ps -a`.
>
> Because quadlets are managed by systemd, not the socket. When the container
> fails, the socket doesn't know. Only systemd knows.
>
> `dsd docker` scans `/etc/containers/systemd/` directly. No socket needed.
> Found a failed nginx container on the first run. Everything else reported clean.
>
> Same class of blind spot as the SELinux/auditd issue I wrote about last month.
> The architecture changed. The tools didn't.
>
> → dashdiag.sh

---

### Evidence

- Test environment: AlmaLinux 9.4 LXC (CT 213, pve01)
- Podman version: 5.8.2
- Quadlet file: `/etc/containers/systemd/test-nginx.container`
- Service unit: `test-nginx.service` (failed — image pull failed in LXC network)
- Podman socket: **inactive** during verification
- `dsd docker` output: ❌ test-nginx failed with fix hints
- `dsd health` output: `WARN: Docker: 1 Podman quadlet(s) failed: test-nginx`
- Commit: ac26dd8
