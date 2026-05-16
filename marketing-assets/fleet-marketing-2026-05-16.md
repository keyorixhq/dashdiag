# DashDiag Fleet — Marketing Positioning & Copy

**Created:** 2026-05-16  
**Status:** Draft — do not use competitor names in public copy

---

## The Legal Note

"Red Hat Satellite for the rest of us" says exactly the right thing but
risks a trademark cease and desist from Red Hat. Keep it in internal docs
only. All public-facing copy must use problem/audience language instead.

---

## Positioning Statements (safe, public-facing)

### Ultra-short (tweet / headline)
- "Fleet management without the enterprise overhead."
- "Patch 50 servers before lunch. Without an agent."
- "Know what's wrong across your entire fleet. One command."
- "No agent. No server. No PhD required."
- "Linux fleet health for the team that doesn't have a dedicated ops team."

### One sentence
- "dsd fleet gives you visibility and patch management across all your
  Linux servers — without an agent, without a dedicated management server,
  and without three days of setup."

### The contrast (no competitor names)
- "Enterprise fleet tools cost thousands and take days to set up.
  dsd fleet takes 30 seconds."

### Audience-specific
- "For the sysadmin managing 20 servers, not 2000."
- "For the team where one person runs everything."
- "For the MSP who patches client servers by SSHing into each one."

---

## The Terminal Is the Pitch

The command output itself is the most powerful marketing asset.
No competitor names needed — the contrast is self-evident.

```bash
$ dsd fleet health

Fleet health — 5 hosts — 2026-05-16 14:32

  web-01    ✅  OK                        1.2s
  web-02    ⚠️  3 security updates        1.4s
  db-01     ❌  CRIT: 12 critical CVEs    1.8s
  worker-1  ✅  OK                        1.1s
  worker-2  ⚠️  /boot 81%, swappiness     1.3s

──────────────────────────────────────────
2 OK · 2 WARN · 1 CRIT · 0 unreachable

done in 3.1s (5 hosts parallel)
```

This screenshot needs no caption. Any sysadmin managing multiple servers
immediately understands what they're looking at and what it would have
taken them to get this information manually.

---

## LinkedIn Post Angles

### Angle 1 — The manual pain story
```
How do you check if all your servers are healthy?

Most sysadmins SSH into each one. Run free -h. Run df -h.
Check journalctl. Check failed units. Check pending patches.

Per server.

One by one.

We built dsd fleet.

One command. All hosts. Parallel.
Patches prioritised by severity.
Fix commands included.

dsd fleet health web-01 web-02 db-01 db-02 worker-1

→ dashdiag.sh

#linux #sysadmin #devops #infrastructure
```

### Angle 2 — The setup time story
```
We asked sysadmins how long their fleet management tool took to set up.

The honest answers:

"3 days for the server, 1 day per host for the agent"
"We gave up and went back to SSH-ing into each one"
"It's been six months and we still haven't finished the rollout"

dsd fleet setup time: 30 seconds.

Add your hosts to fleet.yaml.
Run dsd fleet health.
Done.

No agent. No management server. No rollout project.
Just SSH access and the tool you already use.

→ dashdiag.sh

#linux #sysops #infrastructure #devops
```

### Angle 3 — The MSP angle
```
You manage 15 client environments.

Every Monday morning you SSH into each one.
Check for critical CVEs. Check disk space.
Make sure nothing is on fire.

35 minutes. Every week. Just to know what you already know.

dsd fleet health does it in 4 seconds.

One config file per client.
One command.
Full fleet health summary, sorted by severity.

→ dashdiag.sh

#linux #msp #sysadmin #infrastructure
```

### Angle 4 — The no-agent story (security angle)
```
Every fleet management agent is a persistent process
running as root on your production servers.

It has network access.
It phones home.
It's a permanent attack surface.

dsd fleet uses SSH.

The same access you already trust.
No persistent process.
No phone home.
No agent to patch, monitor, or rotate credentials for.

When you're done, there's nothing running on your servers
except your workloads.

→ dashdiag.sh

#linux #security #sysadmin #devops
```

---

## Twitter / X (short versions)

- "Fleet management without the enterprise overhead. dsd fleet → dashdiag.sh"

- "Check all your Linux servers at once:
  dsd fleet health web-01 web-02 db-01
  No agent. No server. Just SSH.
  → dashdiag.sh"

- "Enterprise fleet tools take 3 days to set up.
  dsd fleet takes 30 seconds.
  → dashdiag.sh"

- "No agent. No management server. No rollout project.
  Just: dsd fleet health
  → dashdiag.sh"

---

## Landing Page Copy

### Hero section
```
Fleet health for the team that can't afford the enterprise tool.

dsd fleet health  →  every server, one command, 4 seconds.

No agent required. Works on any Linux distro.
Start in 30 seconds.
```

### Feature bullets
```
✅ Health check across all servers in parallel
✅ CVE status by severity — patch priority built in
✅ Security patches applied with one command
✅ No agent — uses SSH access you already have
✅ Works on RHEL, Debian, Ubuntu, SUSE, Arch — all in one fleet
✅ Air-gap compatible
✅ Nothing running on your servers when you're not using it
```

### The comparison table (no competitor names)
```
                    Enterprise tools    dsd fleet
Setup time          3 days              30 seconds
Agent required      Yes                 No
Distro support      Often RHEL only     All major Linux
Cost (20 servers)   $$$$                €79/year
Dedicated server    Required            Not needed
Air-gap             Complex             Yes
```

---

## MSP-specific messaging

```
Run dsd on every client.
One config per client environment.
Weekly fleet health report in their inbox.
You see problems before they do.

dsd fleet — the diagnostic layer for Linux MSPs.
```

---

## Internal reference only (do not use publicly)

These phrases say the right thing but name competitors:

- "Red Hat Satellite for the rest of us" — trademark risk
- "Ansible without the YAML" — potentially ok but aggressive
- "Nagios without the 1990s UI" — potentially ok but aggressive

Use the problem/audience language in all public copy.
Save competitor comparisons for sales conversations where context is clear.
