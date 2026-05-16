# dsd fleet — Architecture & Design

**Status:** Planned — Sprint 5+  
**Target audience:** Small/medium teams with 5–100 Linux servers  
**Positioning:** Red Hat Satellite for the rest of us

---

## The Problem

Red Hat Satellite is the standard answer for managing a Linux fleet.
It requires:
- A dedicated Satellite server (8 vCPUs, 20 GB RAM minimum)
- An agent (katello-agent) on every managed host
- Days to set up, weeks to tune
- A Red Hat subscription
- Works only on RHEL-family distros

A team managing 20 VMs and 5 physical hosts does not need this.
They need three things:
1. See what's wrong across all hosts at once
2. Know which hosts need patching
3. Apply security patches without SSH-ing into each host manually

`dsd fleet` does exactly these three things. Nothing more.

---

## Commands

```
dsd fleet health                     # health check across all configured hosts
dsd fleet health --hosts web-01,db-01,worker-1
dsd fleet health --hosts-file ~/servers.txt
dsd fleet health --tags production   # filter by tag

dsd fleet cve                        # CVE status across all hosts
dsd fleet cve --severity critical    # only show CRIT CVEs

dsd fleet patch                      # show what would be patched (dry run)
dsd fleet patch --apply              # apply security patches (with confirmation)
dsd fleet patch --apply --hosts db-01,db-02

dsd fleet report                     # markdown summary of fleet health
dsd fleet report --out fleet-$(date +%Y%m%d).md
```

---

## No dashdiag.sh Server Involved

`dsd fleet` requires **zero dashdiag.sh infrastructure**.

The fleet coordinator is your own machine — your laptop, your jump host,
your CI runner. It SSHs directly into your servers and gets results back.
dashdiag.sh is not in the data path at all.

```
Your laptop (or any machine with SSH access)
  └─ SSH → web-01 → dsd health --json → result back to your laptop
  └─ SSH → web-02 → dsd health --json → result back to your laptop
  └─ SSH → db-01  → dsd health --json → result back to your laptop

dashdiag.sh: not involved
```

**Contrast with tools that require a management server:**

```
Agent-based tools:
  web-01 agent ──→ management server ←── you query the server
  web-02 agent ──→ management server
  db-01  agent ──→ management server

dsd fleet:
  your machine ──SSH──→ web-01 (runs dsd)
  your machine ──SSH──→ web-02 (runs dsd)
  your machine ──SSH──→ db-01  (runs dsd)
```

This means:
- **Air-gap compatible** — works with no internet on any host
- **Nothing to maintain** — no management server to patch, monitor, back up
- **No attack surface** — no persistent process, no open port, no agent credentials
- **Your data never leaves your network** — results go laptop → your terminal only
- **Works on day one** — if you can SSH in, dsd fleet works

The only dashdiag.sh server that exists is for `--share` (opt-in,
E2E encrypted, temporary). Fleet health, CVE scanning, and patching
use zero dashdiag.sh infrastructure.

## How It Works

No agent. No daemon. No server. Just SSH.

```
dsd fleet health web-01 web-02 db-01

1. Read host list (CLI args, --hosts-file, or ~/.config/dsd/fleet.yaml)
2. SSH into each host concurrently (goroutine per host)
3. Copy dsd binary if not present (or use pre-installed version)
4. Run: dsd health --json
5. Collect JSON results
6. Aggregate and render fleet summary
```

Each host needs only:
- SSH access (key-based, no password)
- Linux (any of the 14+ validated distros)
- No agent, no daemon, nothing pre-installed (dsd copies itself)

---

## Fleet Config File

`~/.config/dsd/fleet.yaml`

```yaml
hosts:
  - name: web-01
    address: 192.168.1.10
    user: andrei
    tags: [production, web]

  - name: web-02
    address: 192.168.1.11
    user: andrei
    tags: [production, web]

  - name: db-01
    address: 192.168.1.20
    user: andrei
    key: ~/.ssh/db_key        # override key per host
    port: 2222                # non-standard SSH port
    tags: [production, database]

  - name: worker-1
    address: 192.168.1.30
    user: deploy
    tags: [staging, worker]

settings:
  concurrency: 10             # max parallel SSH connections (default: 10)
  timeout: 30s                # per-host timeout (default: 30s)
  ssh_key: ~/.ssh/id_ed25519  # default key for all hosts
  dsd_path: /usr/local/bin/dsd # where dsd lives on remote hosts
```

---

## Output Design

### Summary view (default)

```
Fleet health — 5 hosts — 2026-05-16 14:32
SSH key: ~/.ssh/id_ed25519 · timeout: 30s

  web-01    ✅  OK                        1.2s
  web-02    ⚠️  3 security updates        1.4s
  db-01     ❌  CRIT: 12 critical CVEs    1.8s
  worker-1  ✅  OK                        1.1s
  worker-2  ⚠️  /boot 81%, swappiness     1.3s

────────────────────────────────────────────
2 OK · 2 WARN · 1 CRIT · 0 unreachable

Hosts needing attention:
  db-01    ❌ 12 critical CVEs
             → dsd fleet patch --apply --hosts db-01
  web-02   ⚠️  3 security updates pending
             → dsd fleet patch --apply --hosts web-02
  worker-2 ⚠️  /boot 81% — old kernels
             → dnf remove --oldinstallonly --setopt installonly_limit=2

done in 3.1s (5 hosts parallel)
```

### Detailed view (`--details`)

```
dsd fleet health --details

web-01 ✅  OK — 1.2s
  Memory    ✅  2.1/8 GB (26%)
  Disk      ✅  / 34%  /boot 12%
  CPU Load  ✅  3%
  Network   ✅  eth0 1Gbps

db-01 ❌  CRIT — 1.8s
  Packages  ❌  12 critical CVEs (dnf)
  Memory    ⚠️  6.8/8 GB (85%)
  Disk      ✅  / 52%
  ...
```

### CVE view (`dsd fleet cve`)

```
Fleet CVE status — 5 hosts — 2026-05-16

  HOST      CRITICAL  IMPORTANT  MODERATE  TOTAL
  web-01    0         0          3         3
  web-02    0         3          8         11      ⚠️
  db-01     12        4          21        37      ❌
  worker-1  0         0          0         0       ✅
  worker-2  0         1          4         5

────────────────────────────────────────────────
Patch priority:
  1. db-01    — 12 CRITICAL CVEs → dsd fleet patch --apply --hosts db-01
  2. web-02   — 3 important      → dsd fleet patch --apply --hosts web-02
  3. worker-2 — 1 important      → dsd fleet patch --apply --hosts worker-2
```

---

## Patching Flow (`dsd fleet patch --apply`)

```
dsd fleet patch --apply --hosts db-01,web-02

Patching plan:
  db-01   dnf upgrade --security  (12 CRIT, 4 important)
  web-02  dnf upgrade --security  (3 important)

Apply patches to 2 hosts? [y/N]: y

  db-01   patching...  ████████████████░░  85%
  web-02  patching...  ████████████████████ done ✅

  db-01   ✅ patched — reboot required (kernel update)
  web-02  ✅ patched — no reboot needed

Patch complete. Run to verify:
  dsd fleet health --hosts db-01,web-02
  dsd fleet cve --hosts db-01,web-02
```

**Safety rules for `--apply`:**
- Always dry-run first, show plan, require confirmation
- Never patch without explicit `--apply` flag
- Confirm again if >5 hosts or if any host has CRIT CVEs
- Log every patch operation with timestamp to `~/.config/dsd/fleet-log.jsonl`
- Never patch a host that is unreachable — skip and warn
- `--security-only` flag applies only security advisories (default)
- `--all` flag applies all updates (explicit opt-in, higher risk)

---

## Architecture

### Package structure

```
cmd/
  fleet.go            # dsd fleet (top-level command)
  fleet_health.go     # dsd fleet health
  fleet_cve.go        # dsd fleet cve
  fleet_patch.go      # dsd fleet patch

internal/
  fleet/
    config.go         # fleet.yaml loading + host resolution
    ssh.go            # SSH connection pool + exec
    runner.go         # parallel host execution
    aggregator.go     # combine per-host results
    render.go         # fleet-specific output (table, summary)
    patch.go          # patch plan + apply flow
    log.go            # audit log (fleet-log.jsonl)
```

### SSH execution model

```go
type FleetRunner struct {
    Hosts       []HostConfig
    Concurrency int
    Timeout     time.Duration
    SSHKey      string
}

type HostResult struct {
    Host     string
    Data     *models.HealthSnapshot  // reuse existing model
    Duration time.Duration
    Error    error                   // unreachable, auth fail, timeout
}

func (r *FleetRunner) RunHealth(ctx context.Context) []HostResult {
    sem := make(chan struct{}, r.Concurrency)
    results := make(chan HostResult, len(r.Hosts))

    for _, host := range r.Hosts {
        go func(h HostConfig) {
            sem <- struct{}{}
            defer func() { <-sem }()
            results <- r.runOnHost(ctx, h)
        }(host)
    }
    // collect results...
}

func (r *FleetRunner) runOnHost(ctx context.Context, host HostConfig) HostResult {
    // 1. SSH connect
    client, err := sshConnect(host, r.SSHKey, r.Timeout)
    if err != nil {
        return HostResult{Host: host.Name, Error: err}
    }
    defer client.Close()

    // 2. Ensure dsd is present (copy if needed)
    ensureDSD(client, host.DSDPath)

    // 3. Run dsd health --json
    out, err := sshExec(client, "dsd health --json")
    if err != nil {
        return HostResult{Host: host.Name, Error: err}
    }

    // 4. Parse JSON → existing models
    var snap models.HealthSnapshot
    json.Unmarshal(out, &snap)
    return HostResult{Host: host.Name, Data: &snap}
}
```

### Self-copy (no pre-install required)

```go
// If dsd not found on remote host, copy the current binary via SSH/SCP
func ensureDSD(client *ssh.Client, remotePath string) error {
    // Check if dsd exists
    _, err := sshExec(client, fmt.Sprintf("test -x %s", remotePath))
    if err == nil {
        return nil // already installed
    }

    // Copy current binary
    selfPath, _ := os.Executable()
    return scpCopy(client, selfPath, remotePath)
}
```

This means `dsd fleet` works on hosts that have never had dsd installed.
The first run copies the binary. Subsequent runs use the cached version.

---

## Monetization

`dsd fleet` is the Pro/Team tier feature. It's the natural upgrade path:

```
Free tier:  dsd health     (single host)
Pro €79/yr: dsd fleet      (unlimited hosts)
            dsd fleet patch (patch management)
            fleet report    (scheduled reports)
```

For MSPs: per-client fleet configs, separate billing per org.

---

## Competitive Positioning

| | Satellite | Ansible | dsd fleet |
|--|-----------|---------|-----------|
| Agent required | Yes | No (SSH) | No (SSH) |
| Setup time | Days | Hours | 30 seconds |
| Distro support | RHEL only | All | All 14+ validated |
| Patch management | Yes | With playbooks | Yes, built-in |
| Fleet health view | Yes | No | Yes |
| Cost for 20 hosts | $$$$ | Free (complex) | €79/year |
| Air-gap friendly | Complex | Yes | Yes |
| Target audience | Enterprise | DevOps engineers | Sysadmins, MSPs |

**The tagline:** "Red Hat Satellite for the rest of us."

---

## Build Order (sprints)

### Sprint 5 — `dsd fleet health` (read-only, no patching)
- fleet.yaml config loading
- SSH connection + `dsd health --json` execution
- Parallel execution (goroutine pool)
- Fleet summary output
- Error handling (unreachable, auth fail, timeout)
- Self-copy of dsd binary if not present

### Sprint 6 — `dsd fleet cve`
- Per-host CVE aggregation
- Priority ranking (CRIT first)
- Patch recommendation per host

### Sprint 7 — `dsd fleet patch`
- Dry run (show plan)
- `--apply` with confirmation
- Audit log
- Reboot detection (warn if kernel update)
- `--tags` filtering

### Sprint 8 — Polish
- `dsd fleet report` (markdown)
- Scheduled reports (cron integration)
- `dsd fleet init` (guided setup wizard)
- SSH key troubleshooting helpers

---

## Non-goals (explicitly out of scope)

- Puppet/Chef/Ansible integration (use those if you want them)
- Bare metal provisioning (wrong tool)
- Compliance frameworks (SCAP, HIPAA) — too complex, wrong audience
- Windows (Linux-only)
- Container orchestration (that's `dsd k8s`)
- Web dashboard (CLI first, always)

---

## Privacy / Security

- SSH private keys never leave the local machine
- dsd binary copied via SCP over SSH (encrypted)
- `--json` output stays in memory, never written to disk on remote host
- Fleet audit log (`fleet-log.jsonl`) is local only
- No fleet data sent to dashdiag.sh (zero telemetry, same as single-host)
- Air-gap compatible — works with no internet on any host
