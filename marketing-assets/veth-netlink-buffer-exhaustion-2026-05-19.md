# The Problem Nobody Knew They Had

*A real finding from a real server, May 19 2026*

---

The server felt fine.

Load average sitting at 7.25. Not alarming — it's a 16-core machine running k3s and a handful of containers. CPU wasn't pinned. Disk wasn't full. No failed services. The kind of state where an admin glances at the dashboard, sees green, and moves on.

```
$ dsd health --plain

CPU Load     OK  66%
Memory       OK  4.2/13 GB (32%)
Disk         OK  15 mounts, max 44%
Network      WARN  eno1 at 100 Mbps
K8s          OK
Docker       OK
```

Nothing to see here.

---

Then we ran `dsd timeline`.

```
$ dsd timeline

⏱  Incident timeline — last 1h

  Load average:
  ⚠️  21:19:46 (now)    load: 7.25  5.86  5.50

  TIME       LEVEL   UNIT             MESSAGE
  ──────────────────────────────────────────────
  20:36:24   jrnl    systemd-udevd    veth1: Failed to get link information:
                                      No buffer space available  ×271
  20:37:00   jrnl    systemd-udevd    veth1: Failed to get link information:
                                      No buffer space available  ×229

⚠️  2 WARN event(s) found in 2.5s
```

**500 kernel errors. In 60 seconds. That nobody knew about.**

---

## What's Actually Happening

`veth1` is a virtual ethernet pair — one end lives inside a container, the other on the host. Every time the container network state changes, `systemd-udevd` tries to query that interface via netlink.

Netlink is the kernel's messaging system for network events. It has a receive buffer. When containers are created and destroyed rapidly — which is exactly what k3s does during pod scheduling — those network events flood the buffer faster than the kernel can drain it.

The kernel responds: **ENOBUFS. No buffer space available.**

`systemd-udevd` retries. Gets rejected. Retries again. 271 times in one burst. 229 times in the next. The whole thing happens silently, deep in the kernel event layer, completely invisible to every monitoring tool that was running.

---

## Why This Matters

When udevd can't track interface state, network event processing stalls. Container network setup slows down. k3s reconciliation loops back up. Load climbs without a clear CPU culprit.

That elevated load at 7.25 — not explained by any individual check — was partially this. A feedback loop with no error message, no failed service, no alert. Just a server gradually getting noisier in a way that would eventually manifest as intermittent container connectivity issues, slow pod startup, or unexplained latency spikes. The kind of thing that shows up in post-mortems as "we're not sure exactly when it started."

The fix is one command:

```bash
sysctl -w net.core.rmem_max=134217728
```

Under two seconds to apply. Immediate effect. Zero downtime.

---

## The Deeper Problem

A senior admin on this server would have checked the usual suspects: CPU, memory, disk, network interface errors, failed systemd units. All clean.

They would not have checked `journalctl -u systemd-udevd --since "1 hour ago" | grep ENOBUFS`. Nobody does that preemptively. That's a search you run *after* you already know something is wrong with container networking — which means *after* the incident has escalated enough to be visible.

`dsd timeline` merged the journal stream, the dmesg stream, and the load trace, collapsed 500 duplicate log lines into two entries with counts, and presented the pattern in 2.5 seconds.

**The admin didn't know to ask for this. DashDiag found it anyway.**

---

## What OBD for Your Server Actually Means

When you plug an OBD scanner into a car, it doesn't wait for the engine to seize. It reads every sensor — including the ones the driver never sees — and tells you what the car already knows about itself.

Most server monitoring tools are reactive. They alert when thresholds are crossed, when services fail, when disks fill. They answer the questions you knew to ask.

DashDiag reads what the server already knows. The kernel log. The journal event stream. The load trace. The netlink buffer state. It asks every question, not just the ones on your checklist.

Sometimes the answer is: everything is fine.

Sometimes it's 500 silent kernel errors that nobody knew about.

You want to know which one it is before your users do.

---

```bash
curl -sSL https://keyorix.com/dsd/install | sh
dsd timeline
```

*2.5 seconds. No agents. No configuration. No prior knowledge required.*
