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
Estimated scope: ~3 days.

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

### Entropy collector
Read /proc/sys/kernel/random/entropy_avail. Low entropy silently breaks crypto.
WARN < 256, CRIT < 64. Add to buildHealthCollectors(). Linux only.
Estimated scope: ~2 hours.

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

## Monetisation Infrastructure

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
