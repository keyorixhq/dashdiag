# DashDiag — Operability Reframe — Marketing Copy

**Created:** 2026-05-16  
**Origin:** Research conclusion — "technically rich but experientially poor"

---

## The Core Insight

The research said it better than any brief:

> "The Linux diagnostics landscape is technically rich but experientially poor.
> The distributions that solve this — by making security subsystems observable,
> audible, and guided — will win enterprise adoption not because they are more
> secure, but because they are more operable."

This is the problem DashDiag was built to solve.

---

## The Four Pillars (with evidence)

### Observable — you can see what's happening
dsd surfaces what the system knows but doesn't show:
- Memory, disk %, NIC speed on every OK row — no drilling needed
- AVC denial samples inline — no manual grep pipeline
- Journal size, boot time, slow units surfaced automatically
- `--diff` shows what changed since last check

### Audible — silent failures are surfaced
dsd makes the inaudible loud:
- journald volatile storage — logs lost on every reboot, nobody told you
- SELinux dontaudit suppression — denials hidden by design, now visible
- SELinux silent denial — hours of "permission denied" with no log entry
- SUSE migration risk — grub not locked, system will not boot after migration

### Guided — you know what to do next
dsd tells you exactly what to run:
- Boolean-first SELinux: booleans → context → audit2allow (in order)
- Fix commands on every WARN and CRIT
- Distro-aware: dnf vs apt vs zypper automatically
- SELinux double-layer: when a unit fails, check AVC before giving up

### Operable — the system works for the admin, not against them
- 1.8 seconds vs 74+ manual commands
- 19+ distros, zero reconfiguration
- No agent, no daemon, no account, no cloud
- Air-gap compatible

---

## Headlines

### Primary
```
Linux is technically rich. Operationally poor.
DashDiag fixes the experience.
```

### Variants
```
Your system knows what's wrong. It just doesn't tell you.
DashDiag does.

Observable. Audible. Guided. One command. Every Linux distro.

Make Linux operable.

The system that explains itself.
```

---

## LinkedIn post — the operability manifesto

```
Linux is one of the most technically sophisticated operating systems ever built.

It is also one of the most experientially painful to operate.

SELinux silently denies access. No error message.
journald loses logs on reboot. No warning.
A slow boot unit takes 23 seconds. No explanation.
zypper migration bricks the system. No pre-check.

This is not a competence problem.
It is a design problem.

Systems that prioritise kernel correctness over operational clarity
produce administrators who disable SELinux, who miss log loss,
who spend hours on problems that a single clear message would have solved.

DashDiag is our answer to that design problem.

One command. Every finding surfaced. Every fix included.
Observable. Audible. Guided. Operable.

Not because Linux should be dumbed down.
Because experienced admins deserve systems that work with them,
not against them.

→ dashdiag.sh

#linux #sysadmin #devops #observability #operability
```

---

## LinkedIn post — the short version

```
"The Linux diagnostics landscape is technically rich but experientially poor."

That line from a research report is the best summary of why we built DashDiag.

SELinux is a triumph of security engineering and a failure of user experience.
journald is powerful and silent about its own failures.
systemd-analyze blame tells you which service is slow — not why.

DashDiag makes Linux systems:

Observable — you can see what's happening
Audible — silent failures are surfaced
Guided — you know what to do next
Operable — the system works for you, not against you

One command. 1.8 seconds. Every distro.

→ dashdiag.sh

#linux #sysadmin #devops
```

---

## Twitter / X

```
"Linux is technically rich but experientially poor."

That research quote is why DashDiag exists.

Observable. Audible. Guided. Operable.

dsd health → dashdiag.sh
```

---

## Landing page — hero section

```
Linux is technically rich. Operationally poor.

Your system knows what's wrong.
It just doesn't tell you.

DashDiag does.

Observable. Audible. Guided. One command.
```

---

## Landing page — the four pillars section

```
Observable
See what's happening without drilling into raw output.
Memory, disk, NICs, journal size — inline on every check.

Audible
Silent failures are the worst kind.
Volatile journal, SELinux denials, dontaudit suppression —
dsd surfaces what the system hides.

Guided
Every finding comes with the exact command to fix it.
Boolean-first SELinux. Distro-aware package commands.
The right fix in the right order.

Operable
1.8 seconds. 19+ distros. No agent. No account.
The system that works for the admin, not against them.
```

---

## Persona-specific messaging

### For sysadmins
"You know the system is doing something. dsd tells you what."

### For DevOps / SRE
"Observability for your application stack.
Operability for the Linux underneath it."

### For CISOs / security buyers
"SELinux is a triumph of security engineering and a failure of user experience.
dsd fixes the UX without touching the security model."

### For MSPs
"Your clients' servers are opaque to them.
dsd makes them readable — to you and to them."

### For enterprises (air-gap / regulated)
"The distributions that win enterprise adoption are the ones that are
more operable, not just more secure. dsd is that layer."

---

## The UnpackOps connection (for investor / partner conversations)

ExplainOps → UnpackOps → DashDiag is a straight line.

Unpack the opaque. Explain the silent. Make the complex guided.

DashDiag is the first product in that platform — the diagnostic layer
that makes Linux systems explain themselves. Every other UnpackOps product
(Keyorix, RCA platform, Gauge) shares the same philosophy:
systems should be observable, audible, guided, and operable.

DashDiag proves it works on the hardest substrate: bare Linux.

---

## OS-Agnostic Expansion (added 2026-05-16)

### The updated positioning

The four pillars — Observable, Audible, Guided, Operable — say nothing
about Linux. They apply to every operating system.

**Updated mission:**
"DashDiag makes *systems* observable, audible, guided, and operable."

Not "Linux systems". Systems.

### What to say in different contexts

**Landing page (honest about current state):**
```
Works on Linux and macOS today.
Windows on the roadmap.

Observable. Audible. Guided. Operable.
Whatever the OS.
```

**LinkedIn / social:**
```
We started with Linux because that's where the pain is deepest.

But systems being technically rich and experientially poor
isn't a Linux problem. It's a systems problem.

Windows admins lose hours to Event Viewer.
macOS admins dig through Console.app.
Linux admins grep through 74 commands.

Same problem. Different syntax.

DashDiag starts with Linux because that's where the tools
are most fragmented and the community most receptive.
But the mission is broader.

Observable. Audible. Guided. Operable.
For any system.

→ dashdiag.sh
```

**Investor / partner conversations:**
"We start with Linux because that's where the operability gap is
largest and the audience most willing to adopt new tooling. The
architecture is OS-agnostic by design — Windows support follows the
same collector/analysis/render pipeline. The four pillars apply to
every operating system."

### Feature evaluation rule (OS-agnostic version)

Every feature must answer:
> Does it make **systems** more observable, audible, guided, or operable?

Not "Linux systems". This keeps the roadmap open to:
- Windows (Event Viewer, WMI, Windows Defender, PowerShell)
- macOS deepening (launchd, Spotlight, macOS Security framework)
- Container-native mode (OS-agnostic health checks)
- Network devices (same four pillars, different substrate)

### What NOT to say

Avoid: "DashDiag is a Linux tool"
Say: "DashDiag starts with Linux — Windows is on the roadmap"

Avoid: "make Linux operable" (in evergreen copy)
Say: "make systems operable"

Keep "Linux" in: specific product claims, distro counts, validated
hardware lists — anywhere accuracy matters more than aspiration.
