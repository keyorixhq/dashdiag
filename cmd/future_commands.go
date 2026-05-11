package cmd

// TODO(backlog): dsd docker — container health check.
// Running/stopped/unhealthy containers, image age, volume usage.
// Phase 3. Build after dsd health fast is validated in production.
// Estimated scope: ~2 days. See BACKLOG.md for full spec.

// TODO(backlog): dsd logs — log health check.
// Journald error rate, log volume, OOM kills, segfaults in recent logs.
// Phase 3. Reads journald directly via /run/log/journal, no external tools.
// Estimated scope: ~2 days. See BACKLOG.md for full spec.

// TODO(backlog): dsd security — security posture check.
// Open ports, SSH config weaknesses, sudo rules, world-writable files, SUID binaries.
// Phase 3. High signal for security-conscious users.
// Estimated scope: ~2 days. See BACKLOG.md for full spec.

// TODO(backlog): dsd compare — multi-server comparison.
// Outlier detection and drift between nodes. Reads --json output from multiple hosts.
// Phase 3. Fleet upgrade path.
// Estimated scope: ~3 days. See BACKLOG.md for full spec.

// TODO(backlog): dsd pve — Proxmox VE health.
// VM/LXC status, storage pool usage, cluster quorum.
// Phase 4. Specialist audience. After dsd docker is validated.
// Estimated scope: ~3 days. See BACKLOG.md for full spec.

// TODO(backlog): dsd k8s — Kubernetes cluster health.
// Pod restarts, node pressure, failing deployments, PVC usage. Fast/deep split.
// Phase 4. Build after dsd health and dsd net are validated in production.
// Estimated scope: ~5 days. See BACKLOG.md for full spec.
