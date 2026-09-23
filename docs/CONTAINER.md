# Running dsd in a container

`ghcr.io/keyorixhq/dashdiag` is a [distroless](https://github.com/GoogleContainerTools/distroless)
image: the `dsd` binary and nothing else — no shell, no package manager, no
`smartctl`/`nft`/`journalctl`/`dpkg`/etc. That single fact governs almost
everything below: a check that works by shelling out to a tool this image
doesn't contain will never work from this image, in either mode — that's a
property of the image, not of what you mount into it.

There are two supported modes.

## Mode (a): container self-diagnosis (default)

```bash
docker run --rm ghcr.io/keyorixhq/dashdiag health
```

dsd sees exactly what any other process in that container sees: the
container's own cgroup limits, its own network namespace, its own (usually
empty) `/dev`. This is a legitimate, safe default — it answers "is this
container healthy?" — but it is **not** a host health check, and dsd says so:
every run inside a container prints a one-line notice pointing here, unless
you've passed `--host-root` (mode (b), below) to say you already know.

## Mode (b): host diagnosis

To diagnose the machine the container runs on, share the host's process,
network, and filesystem views with it, then tell dsd you've done so:

```bash
docker run --rm \
  --pid=host --network=host \
  -v /proc:/proc:ro -v /sys:/sys:ro -v /dev:/dev:ro \
  -v /etc:/etc:ro -v /var/log:/var/log:ro \
  --cap-add=SYS_ADMIN \
  ghcr.io/keyorixhq/dashdiag health --host-root
```

`--cap-add=SYS_ADMIN` is enough for most reads; a few paths (raw `/dev/kmsg`,
some SMART ioctls) additionally want `--privileged`. Reach for the narrower
`--cap-add` first.

**`--host-root` does not remap any path.** It only tells dsd's own notice
logic "the operator already knows /proc, /sys, /dev, /etc, and /var/log are
host-mounted" so it stops printing the self-diagnosis notice from mode (a) —
which would be actively wrong once those mounts are in place. The mounts
themselves are what make `/proc` etc. resolve to the host's data; dsd's
collectors read those absolute paths unchanged either way — the same code
path this binary uses on bare metal.

## What works, degrades, or stays unavailable

Honesty rule: a check that cannot work from a container reports itself as
unmeasured/unverified (an INFO insight, or the row is absent), never a false
OK. This table names the mechanism, not just the outcome.

| Check | Mode (a): container | Mode (b): host-root |
|---|---|---|
| CPU load / usage | Works — container's own cgroup-scoped view | Works — host-wide, once `/proc` is host-mounted |
| Memory | Works — container's own cgroup-scoped view (reported as such) | Works — host-wide |
| Swap | Works — swap is host-wide, not cgroup-namespaced | Works |
| Disk / filesystems | Degraded — sees only what's mounted into the container (usually just the overlay rootfs) | Works — `/proc/mounts` reflects the host's real mount table |
| SMART / NVMe / drives | **Unavailable** — no `/dev` block nodes by default, and `smartctl`/`nvme` aren't in this image regardless | **Still unavailable** — `/dev` is now visible, but the image has no `smartctl`/`nvme-cli` binary to call; this needs a non-distroless host agent, not this image |
| Network interfaces / bonding | Degraded — sees the container's own veth/bridge interface, not the host's NICs | Works — `--network=host` shares the host's netns directly (mounting `/proc` alone does not; interface state isn't a mountable path) |
| Systemd | Absent — no init system runs inside the container | **Still absent** — systemd state lives behind the host's real PID 1 and D-Bus socket, which bind-mounting `/proc` doesn't expose |
| Firewall (nft/iptables) | **Unavailable** — no `nft`/`iptables` binary in this image | **Still unavailable** — same: this image has no shell or package manager to add one |
| Hardening / sshd config | Absent — no sshd runs inside the container | Works — `sshd_config` is a plain file, readable once `/etc` is host-mounted |
| Logs (journal / dmesg) | **Unavailable** — no journald socket reachable; `/dev/kmsg` is typically inaccessible without extra capabilities | Degraded — `/var/log` exposes host log files if present; `journalctl`/`dmesg` still need both the binary (absent) and often `--privileged` |
| CVE / package advisories | **Unavailable** — the image ships no package manager (`dpkg`/`apt`/`rpm`/`dnf`) at all | **Still unavailable** — same reason; unaffected by mounts |
| Sessions (`w`) | **Unavailable** — no `utmp`/`wtmp`, no `w` binary | **Still unavailable** — same |

Rows marked **Still unavailable** in mode (b) are the ones worth reading
twice: mounting host paths widens *visibility*, but it cannot install a
binary this image was deliberately built without. If you need those checks
against a host, run the `.deb`/`.rpm`/AppImage/raw-binary install directly on
that host instead (see the main [Install](../README.md#install) section) —
that's the fully-capable build this repo also publishes, with no distroless
constraint.

## MCP from the image

```bash
docker run -i --rm ghcr.io/keyorixhq/dashdiag mcp
```

Same trust boundary as any other `dsd mcp` invocation (`docs/AGENTS.md`):
read-only, and in container mode (the default — no host mounts) an agent
using this tool is diagnosing the *container*, not the host it runs on. The
`dsd_health` MCP tool returns raw JSON (no human-readable banner — that
notice is `dsd health`'s text-mode-only), so the container-vs-host caveat
does not show up in the tool's own output; the agent (and whoever configured
it) is responsible for knowing which mode this container is running in. To
have the tool diagnose the host, add the mode (b) mounts/flags above to the
`docker run` line that starts the MCP server — there is no separate
`--host-root` for the MCP path, only for `dsd health`'s own CLI output.
