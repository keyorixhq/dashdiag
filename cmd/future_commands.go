package cmd

// TODO(backlog): dsd docker — container health check.
// Running/stopped/unhealthy containers, image age, volume usage, crash loops.
// Build after RHEL laptop Docker validation is complete. See BACKLOG.md.
// Estimated scope: ~2 days.

// TODO(backlog): dsd k8s — Kubernetes cluster health. Fast/deep split.
// Pod restarts, node pressure, failing deployments, PVC usage.
// OS-layer diagnosis (CNI, SELinux, firewalld, kubelet journal) is the moat.
// Collector code built and tested against k3s — needs full validation run.
// Estimated scope: ~5 days. See BACKLOG.md.

// TODO(backlog): dsd pve — Proxmox VE health.
// VM/LXC status, storage pool usage, cluster quorum, PBS backup status.
// Build on Proxmox host testbed. See BACKLOG.md.
// Estimated scope: ~3 days.
