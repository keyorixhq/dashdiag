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
