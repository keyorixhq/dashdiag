# DashDiag Backlog

This file tracks all planned features not yet implemented.
Items in cmd/*.go files are also tagged `TODO(backlog)` inline.
Build order rule: **never build deep before fast is in production use.**

---

## Commands

### dsd k8s
Kubernetes cluster health — pod restarts, node pressure, failing deployments, PVC usage.
Fast/deep split. Build after dsd health and dsd net are validated in production.
Estimated scope: ~5 days.

### dsd k8s deep
Extended k8s analysis — resource quotas, HPA status, network policies, certificate expiry.
Phase gate: after dsd k8s fast is in production use.
Estimated scope: ~3 days.

### dsd docker
Container health — running/stopped/unhealthy containers, image age, volume usage.
Phase 3. Build after dsd health fast is validated.
Estimated scope: ~2 days.

### dsd logs
Log health — journald error rate, log volume, OOM kills in recent logs, segfaults.
Phase 3. Reads journald directly, no external tools.
Estimated scope: ~2 days.

### dsd security
Security posture — open ports, SSH config, sudo rules, world-writable files, SUID binaries.
Phase 3. High signal for security-conscious users.
Estimated scope: ~2 days.

### dsd compare (multi-server)
Compare health snapshots across multiple hosts — outlier detection, drift between nodes.
Phase 3. Fleet upgrade path. Requires --json output from multiple hosts piped in.

Red Hat does this via cloud upload and ML across registered fleets. DashDiag does it
locally — no cloud, no agent, no registration. One command:

  dsd health --json | ssh host2 dsd compare --stdin
  cat host1.json host2.json host3.json | dsd compare

Key capabilities to implement:
- Identify which host looks different from the others (outlier detection)
- Show which checks diverged between hosts (e.g. host3 has swap, others don't)
- Flag hosts where a value is outside 2 standard deviations of the fleet average
- Drift detection: compare current state against a saved "golden" snapshot

This is a genuine differentiator vs Red Hat Insights — same capability, zero infrastructure.
Estimated scope: ~3 days. See also: --json output (already implemented as the data layer).

### dsd pve (Proxmox)
Proxmox VE health — VM/LXC status, storage pool usage, cluster quorum.
Phase 4. Specialist audience. After dsd docker is validated.
Estimated scope: ~3 days.

### dsd net deep
Jitter analysis, bond detection, wireless signal strength, traceroute on problem detected.
Phase gate: after dsd net fast is in production use.
Estimated scope: ~2 days.

---

## Collectors (dsd health additions)

### ~~Entropy collector~~ ✅ DONE
Implemented in internal/collectors/entropy_linux.go.
Reads /proc/sys/kernel/random/entropy_avail. WARN < 256, CRIT < 64.

### Package security advisory
Surface available security updates. dnf check-update --security / apt / brew outdated.
WARN if any security updates pending. High visibility to users.
Estimated scope: ~1 day.

### Sysctl advisor / kernel tuning
Compare live sysctl against known-good profiles per workload (web, db, k8s node).
Auto-detect workload from running processes (nginx, postgres, kubelet etc).
Estimated scope: ~2 days.

### CVE exposure check
Cross-reference installed packages against local OVAL advisory feed.
WARN CVSS >= 7.0, CRIT CVSS >= 9.0 or known exploited.
Advisory data downloaded and cached locally (~weekly). No cloud registration.
Estimated scope: ~1 week.

### Configuration drift detection
Compare current sysctl/kernel params against a user-defined "known good" baseline.
Extends existing baseline infrastructure. Use case: post kernel-upgrade validation.
Estimated scope: ~1 day.

---

## Strategic Discussions Required

These items need a design/strategy session before implementation begins.
Do not start building until the discussion is complete and decisions are recorded.

### [DISCUSS] Team mode — how should it work?
Before building any paid tier, answer these questions:

**Sharing model:**
- How does a user share a snapshot? URL? File? Email?
- Is sharing pull (recipient requests) or push (sender uploads)?
- Does a shared snapshot expire? How long?
- Can a recipient re-run the check or only view the saved state?
- What happens when the shared system is behind a firewall?

**Team workspace:**
- What does a "team" own? Snapshots? Alerts? Policies?
- Is the team model org-based (like GitHub orgs) or invite-based?
- How does a solo user graduate to a team account?
- What is the free tier limit? (e.g. 1 host, 7 days history, no sharing)

**Fleet view:**
- How do multiple hosts register to a team workspace?
- Push model (host uploads on cron) vs pull model (server SSHes in)?
- What does the fleet overview screen look like — table? map? timeline?
- How does dsd compare fit into the fleet view?

**Identity and auth:**
- SSO only? Email/password? CLI token?
- How does the CLI authenticate to dashdiag.sh? API key in ~/.dsd.yaml?
- How do we handle key rotation and revocation?

**Monetisation boundary:**
- What is free forever vs paid?
- Is the paid gate per-host, per-user, or per-team?
- What is the pricing model — seat-based, usage-based, or flat?
- What triggers an upgrade prompt inside the CLI?

**Privacy and trust:**
- What data leaves the machine on --share?
- Can users redact hostnames or IPs from shared snapshots?
- Where is data stored and for how long?
- GDPR implications for EU users (Andrei is in Spain)?

Suggested session format: 1-2 hour whiteboard session.
Output: decisions recorded in SPEC.md §30 before any backend work begins.

### [DISCUSS] Viral growth mechanics — how do we get word-of-mouth?
- --share URL: what does the landing page look like for a non-dsd user?
- --badge: where exactly does the badge embed and what does it show?
- Is there a "powered by DashDiag" attribution in shared snapshots?
- What is the install command we want spreading? (curl | bash vs brew vs apt)
- Should dsd health output include a one-liner install hint for new users?

### [DISCUSS] Pricing strategy
- What is the anchor price for team workspace?
- Is there a per-host fee or unlimited hosts per team?
- Open source core + paid cloud, or freemium CLI?
- Competitor reference: Datadog charges ~$15/host/month. What is DashDiag's angle?


### --share flag
Upload snapshot to dashdiag.sh and return a shareable URL.
Viral feature — every shared link is a product impression.
Requires dashdiag.sh backend. Build after landing page is live.
Estimated scope: ~1 day (CLI side) + backend.

### --badge flag
shields.io-compatible badge endpoint showing system health status.
Embeds in GitHub README. Viral — visible to every repo visitor.
Requires dashdiag.sh backend.
Estimated scope: ~2 hours (CLI side) + backend.

### Team workspace MVP (paid tier)
Shared snapshot history across a team. First paid product.
Requires dashdiag.sh backend, auth, and billing.
Estimated scope: ~10 days.

### dsd policy (CI gate)
YAML policy file defines health thresholds. dsd health --policy fails CI if violated.
Free tier feature that drives paid cloud management upsell.
Estimated scope: ~3 days.

### dsd trial start
Onboarding command for paid tier trial.
Requires backend. Build after team workspace MVP.
Estimated scope: ~1 day.

---

## Polish

### dsd health deep
Per-core CPU breakdown, per-process memory detail, extended sysctl analysis.
Build rule: implement only after dsd health fast is in production use.
Estimated scope: ~3 days.

### CIS/STIG compliance checks
Compare system config against CIS Benchmark or STIG profiles.
Enterprise-only. Implement after core health checks are stable and paying customers exist.
Estimated scope: ~2 weeks.

### dsd init cloud detection improvements
DMI file reads for accurate cloud provider detection.
Correct IO thresholds per cloud provider (EBS vs NVMe vs network disk).
Estimated scope: ~1 day.

### --dry-run on file-writing operations
Trust building for dsd init and dsd hook.
Show what would be written without writing it.
Estimated scope: ~0.5 days.
