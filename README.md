# DashDiag

**System diagnostics that tell you what's wrong AND what's causing it.**

`dsd health` runs 12 system checks in ~1.3 seconds. When something fires WARN
or CRIT, you don't get a generic hint — you get the specific process or
configuration causing the problem, attributed inline.

```
$ dsd health
Systemd      OK
Memory       CRIT  RAM at 94% (1.2GB free of 16GB)
   Top processes by memory:
   PID    MEM%  RSS    COMMAND
   12345  31.4  5.0GB  postgres
   23456  18.2  2.9GB  java
   ... (5 more)
CPU          OK
Disk         OK
Network      OK
[...]
```

No copy-paste cycle. No "let me Google this command" detour. The cause arrives
where the verdict does.

---

## Install

**macOS or Linux, x86_64 or arm64:**

```bash
curl -fsSL https://dashdiag.sh/install.sh | sh
```

Or download a pre-built binary from
[releases](https://github.com/keyorixhq/dashdiag/releases) and put it in your
`PATH` as `dsd`.

Verify:

```bash
dsd --version
```

---

## Usage

The whole tool is one command:

```bash
dsd health
```

That's it. No config file. No daemon. No setup. It reads kernel state,
applies sensible defaults, and tells you what it found.

For machine-readable output:

```bash
dsd health --json
```

For minimal output without inline drill-down:

```bash
dsd health --terse
```

---

## What it checks

Twelve checks run in parallel against `/proc`, `/sys`, and a few well-chosen
commands:

| Check          | What it diagnoses |
|----------------|-------------------|
| CPU            | Load average vs core count, sustained pressure |
| Memory         | RAM exhaustion, slab cache anomalies, OOM risk |
| Swap           | Swap pressure attributed to specific processes |
| Disk           | Per-mount usage, fast growth, mount-point health |
| IO             | Disk I/O wait attributed to specific processes |
| Network        | Interface health, TCP state pathologies, DNS failures |
| Processes      | Zombies (with their parents), hung uninterruptible processes |
| Systemd        | Failed units with their last log lines |
| Clock          | NTP sync, drift, time source health |
| Sysctl         | Kernel parameters drifting from sane defaults |
| FDLimits       | Processes near their file descriptor limits |
| KernelSecurity | SELinux / AppArmor enforcement state |

When a check fires WARN or CRIT, DashDiag automatically gathers the relevant
context — top processes by RSS for Memory, top by CPU% for CPU, TCP states
by process for Network, and so on — and shows it inline.

---

## Why this exists

Engineers running `top`, `ps`, `ss`, `netstat`, `iotop`, `vmstat`,
`systemctl status`, `journalctl`, and `dmesg` to figure out why a server is
unhappy. Memorizing flags. Reaching for cheat sheets. Copying commands from
Stack Overflow at 2am.

The information already exists in `/proc`. The right command for any
specific situation is knowable. A single tool can read everything, apply
opinionated thresholds, and tell you what's wrong AND show you the data
behind the verdict.

DashDiag is that tool. It does not replace observability platforms,
monitoring, or alerting. It is the thing you run when you SSH into a server
and want to know what's wrong, right now, without thinking.

---

## How it works

Every check is **passive** — DashDiag reads what the kernel already knows.
No daemons. No persistent state. No network calls (except where you
explicitly ask for them, like the gateway ping when Network is investigated).

Output goes to stdout (results) and stderr (progress messages), so
`dsd health --json | jq` does what you'd expect.

Wall time on a healthy system: ~1.3s. Wall time when something is wrong:
slightly longer, because drill-down attribution gathers more data — but
still under 2s in normal operation.

---

## Output formats

| Flag       | Format                                                |
|------------|-------------------------------------------------------|
| (default)  | Human-readable, color, inline drill-down on WARN/CRIT |
| `--plain`  | No color, otherwise identical to default              |
| `--json`   | Structured JSON with full Details field for drill-down |
| `--yaml`   | Same data as JSON, in YAML                            |
| `--terse`  | Verdict only, no inline drill-down                    |

---

## Examples

**Investigate why a server is slow:**

```bash
ssh user@server 'dsd health'
```

**Capture diagnosis for an incident report:**

```bash
dsd health --json > incident-2026-05-10.json
```

**Run on every host in a cluster (diagnose a fleet):**

```bash
for host in $(cat hosts.txt); do
  ssh "$host" 'dsd health --json'
done | jq -s '.'
```

**See more workflows:**

```bash
dsd examples
```

---

## Project status

DashDiag is in active development. The core `dsd health` command is stable
and tested on:

**Linux x86_64 and arm64:**

- Ubuntu 20.04, 22.04, 24.04
- Debian 12
- Fedora 40
- Rocky Linux 9 (RHEL 9 binary-compatible — also covers AlmaLinux, Oracle Linux)
- Amazon Linux 2023
- openSUSE Tumbleweed
- Arch Linux
- Alpine 3.21 (musl libc, busybox userland)
- Proxmox VE 8

**macOS:**

- arm64 (Apple silicon)

**Container contexts:**

- Docker (privileged and unprivileged)
- Colima / Lima
- Various base images (debian, rocky, alpine, fedora, etc.)

**ARM64 Linux** validated via QEMU.

The roadmap toward `v1.0` is in [BACKLOG.md](BACKLOG.md).

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
and the contribution flow.

For bugs, missing checks, or distros that misbehave, open an issue.

---

## License

DashDiag is released under the [Apache License 2.0](LICENSE).

---

## About

DashDiag is built by [Keyorix](https://keyorix.com) — operational tools
that respect engineers' time.

Sister products and roadmap: see [keyorix.com](https://keyorix.com).
