# "74 Commands vs 1" Marketing Messages

> Core insight: a complete Linux health check requires 74+ individual commands
> manually. dsd health does it in 1 command, 1.8 seconds, with fix commands included.

## The numbers

- 21 check categories
- 74+ manual commands required
- 1.8s dsd runtime
- Fix commands included in output
- Works on all major distro families

---

## LinkedIn post

How many commands does it take to check if a Linux server is healthy?

We counted.

74.

And that's if you already know exactly what to run — on every distro, in the right order, without missing anything.

Memory: free -h, vmstat, grep Slab /proc/meminfo
Drives: smartctl -a for each disk individually
Hardening: ss -tlnp, sshd -T, cat /etc/sudoers, auditctl -l
Kernel security: sestatus, aa-status, uname -r, grep CONFIG_LSM /boot/config-*
Logs: dmesg, journalctl, /dev/kmsg, pstore
...

21 categories. 74+ commands. Scattered knowledge. No synthesis.

And when you're done, you have raw output — not answers. You still have to correlate everything yourself.

dsd health: 1 command. 1.8 seconds. 21 checks. Fix commands included.

That's DashDiag.

→ dashdiag.sh

#linux #sysadmin #devops #observability #infrastructure

---

## Twitter / X

How many commands does it take to check if a Linux server is healthy?

We counted: 74+

And that's if you already know what to run on every distro.

dsd health: 1 command. 1.8 seconds. 21 checks. Fix commands included.

→ dashdiag.sh

---

## Landing page headline

74 commands. Or one.

A complete Linux health check covers memory, CPU, thermals, disk, drives,
network, security, packages, logs, kernel, processes, and more.

That's 74+ individual commands — if you know exactly what to run, on every
distro, in the right order.

Or: dsd health

1 command. 1.8 seconds. 21 checks. Fix commands included.
Works on RHEL, Debian, Ubuntu, SUSE, Arch — and their derivatives.

---

## Notes for use

- Attach the 74-commands comparison table screenshot to the LinkedIn post
- The Twitter version works standalone — no screenshot needed
- Landing page version goes under the hero, before the demo GIF
- "Not answers — raw output" is the sharpest line. Keep it.
- The correlation point (dsd connects dots, manual commands don't) can be
  a follow-up post on its own
