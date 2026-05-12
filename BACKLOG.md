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

**Why this matters:**
Docker is the most common deployment context for backend developers. Every backend
team uses Docker. It's also the easiest distro-agnostic way to test DashDiag inside
a container.

**Two testing layers worth validating:**

Layer 1 — `dsd health` from INSIDE a container:
```
docker run -it --rm -v /:/host:ro alpine sh -c "wget dashdiag.sh/dsd && ./dsd health"
```
What to verify:
- Container banner shows correctly
- cgroup limits are respected (Memory shows container limits, not host)
- Platform detection (`platform.DetectContainerContext`) works
- File reads from /host/proc, /host/sys work correctly

Layer 2 — `dsd docker` AGAINST the daemon (new command):
Read `/var/run/docker.sock` or shell out to `docker ps`. Catch:
- Stopped containers that should be running
- Containers restarting frequently (CrashLoopBackOff equivalent)
- Volumes filling up (`docker system df`)
- Stale images (>30 days unused)
- Failed health checks
- Container resource pressure (CPU/memory near limit)

**Where to test:**
RHEL machine has k3s (containerd, not docker) — NOT testable there directly.
Debian/Ubuntu is the natural Docker testbed. Most users install Docker on Ubuntu.

**Test scenarios to set up:**
- Spin up deliberately broken containers (OOM, crash loops, unhealthy)
- Validate dsd catches stopped + restart-looping containers
- Test container detection when DashDiag itself runs inside Docker
- Validate cgroup v1 vs v2 (Debian 12 = cgroup v2, Ubuntu 20.04 = mixed)

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

### [DISCUSS] Multi-socket / NUMA testing
Rent Hetzner AX162-S or similar (2x AMD EPYC) for a few hours to validate:
- NUMA topology collector (/sys/devices/system/node/)
- Per-socket load imbalance detection (/proc/stat per-CPU)
- IRQ affinity analysis (/proc/interrupts)
- Cross-node memory traffic
- CPU pinning drift detection

Hetzner dedicated auction servers: ~€0.50-2/hour.
Also: ask friends with multi-socket hardware.
Build after core product is stable and first paying customer exists.

---

## [STRATEGIC] V2 Diagnostic Engine — From Collector to Doctor

These ideas were captured during a strategic review session. The core insight:
DashDiag v1 is a high-quality collector platform. V2's moat is interpretation —
becoming "OBD that reads codes" not just "OBD that shows sensor values".

Do NOT start any of these items before first paying customer is acquired
(target: 6 weeks from initial sprint per project guide).

### [V2-CORRELATION] Symptom correlation engine
The highest-leverage v2 feature. Move from "showing symptoms" to "explaining them".

Examples of rules to encode:
- CPU high + IO wait high + Memory CRIT → likely memory pressure causing swap thrashing
- Memory pressure + swap + high disk writes → memory leak or cache thrashing
- Network retransmits + CPU idle → NIC / kernel networking issue
- Entropy low + TLS failures → crypto / bootstrapping failure
- IO CRIT on one device + Disk OK overall → single drive degradation
- Multiple OOM kills + same service → memory leak in that service
- Sysctl drift + recent reboot → kernel parameter not persisted

Implementation phases:
1. Hardcoded ruleset (~10 rules) in heuristics package
2. Confidence scoring per rule match
3. "Likely cause ranking" in summary output
4. (V3) graph-based DAG of symptom → cause → fix

Output design:
  Instead of: ❌ Memory 97%, ❌ CPU 280%, ❌ IO 28ms latency
  Show:       ❌ Memory pressure with cascade
              ├─ Memory 97% (primary symptom)
              ├─ CPU 280% (consequence: swap thrashing)
              └─ IO 28ms (consequence: high swap I/O)
              → likely cause: memory leak or insufficient RAM

Estimated scope: 1 week for v0 ruleset, ongoing iteration for accuracy.

### [V2-COLLECTOR] Filesystem & inode pressure
- inode exhaustion per mount (df -i equivalent via statfs)
- filesystem read-only remount detection (compare /proc/mounts to fstab)
- mount degradation / stale NFS
- ext4/xfs reservation pressure
Signals: /proc/mounts, statfs syscall, dmesg ext4/xfs errors via LogsCollector
Estimated scope: ~2 days.

### [V2-COLLECTOR] Kernel instability extensions
Extend LogsCollector:
- soft lockups (kernel: BUG: soft lockup)
- hard lockups (NMI watchdog)
- kernel panic history (/sys/fs/pstore, /var/crash)
- watchdog resets
Signals: journalctl -k, /sys/fs/pstore, dmesg patterns
Estimated scope: ~2 days.

### [V2-COLLECTOR] Network deep diagnostics
Extend NetworkCollector:
- TCP retransmissions rate (/proc/net/netstat)
- SYN backlog saturation
- TIME_WAIT explosion (already partial in TCP states)
- connection tracking table usage (/proc/sys/net/netfilter/nf_conntrack_count)
Signals: /proc/net/netstat, /proc/net/sockstat, conntrack
Estimated scope: ~2 days. Belongs in `dsd net deep`.

### [V2-COLLECTOR] CPU scheduling pathology
- run queue saturation (load vs cores)
- context switch spike detection
- iowait vs steal time separation (VM-host vs host-host)
- CPU throttling due to cgroups (/sys/fs/cgroup/cpu.stat)
Signals: /proc/stat, /proc/schedstat, cgroup files
Estimated scope: ~2 days. Belongs in `dsd health deep`.

### [V2-COLLECTOR] Storage performance diagnostics
- write amplification estimate (SSD wear prediction from SMART)
- queue depth saturation (/sys/block/*/queue/nr_requests vs in_flight)
- fsync latency spikes (eBPF — significant complexity)
- disk scheduler latency distribution
Signals: iostat -x equivalent, /sys/block/*/queue/, /proc/diskstats
Estimated scope: ~3 days. fsync latency would need eBPF — defer to v3.

### [V2-COLLECTOR] TLS / certificate health (high-value cross-platform)
New `dsd tls` standalone command:
- expired cert detection (local cert paths)
- remote endpoint cert expiry (configurable list)
- TLS handshake failures from logs
- system trust store drift (compare to known baseline)
Signals: /etc/ssl/certs/*, openssl s_client, /etc/pki/ca-trust/
Estimated scope: ~3 days. High leverage for DevOps audience.

### [V2-COLLECTOR] Security drift detection (extends Hardening)
- SSH config drift vs baseline
- sudoers unexpected changes (audit /etc/sudoers timestamp + diff)
- new SUID binaries (find / -perm -4000, compare to baseline snapshot)
- cron job injection detection (/etc/cron*, /var/spool/cron/)
- writable PATH binaries
- new users with UID 0
Signals: file system scans, baseline comparison
Estimated scope: ~3 days.

### [V2-COLLECTOR] Process-to-network anomaly mapping
- unknown process listening on port
- port-process mismatch (e.g. nginx listening on :22)
- reverse shell heuristics (tty-less shell + network connection)
Signals: /proc/*/cmdline cross-referenced with /proc/net/tcp
Estimated scope: ~2 days.

CAUTION: This drifts toward EDR territory (CrowdStrike, SentinelOne).
EDR is a regulated, compliance-heavy market. Do not position DashDiag as
EDR-class without explicit strategic decision.

### [V2-COLLECTOR] macOS additions
Lower priority — DashDiag audience is primarily Linux servers.
- top CPU processes by app bundle
- memory pressure breakdown (swap vs compressed memory)
- LaunchAgents / LaunchDaemons inspection (~/Library/LaunchAgents)
- Spotlight indexing health (mdutil -s /)
Estimated scope: ~3 days combined. Defer until macOS user demand exists.

---

## [STRATEGIC] V2 Framing Decision Required

The original analysis claimed: "Collectors are commoditized. Interpretation is not."

Counter-position: DashDiag's collectors are NOT commoditized — most tools shell out
to top/vmstat/ss with shallow parsing. DashDiag reads /proc and /sys directly with
mount detection, build tags, and platform-aware logic. THAT is the moat for v1.

For v2, the framing shifts toward interpretation. The correlation engine becomes
the unique value, not the collectors.

**DECISION RECORDED (initial review):** Lean toward "system doctor" — correlation
engine over collector expansion. Rationale:
- Anyone can add another collector; correlation rules encode actual SRE knowledge
- The cascade output format ("Memory pressure with cascade") differentiates strongly
- v1 already has solid collector coverage (18 collectors validated on RHEL + macOS)
- Overnight stress cron data is a natural validation dataset for correlation rules

Open questions still requiring decision:
- Are we a "comprehensive observability CLI" or a "system doctor"?
- Confirm: lean hard into correlation, accept fewer collectors in v2?
- This decision affects messaging, pricing tier structure, engineering priorities.
- Re-confirm after first paying customer is acquired and gives input.
