## Evidence — SELinux Blind Spot Discovery (RHEL 10.1, 2026-05-12)

### Setup
- RHEL 10.1, auditd 4.0.3 running, SELinux enforcing (targeted policy)
- 17 real AVC denials generated in /var/log/audit/audit.log
- Both dsd health and dsd security run as root immediately after

### Before the fix — dsd health (KernelSec reads journald, misses everything)

KernelSec    OK          ← WRONG. 17 real AVC denials exist.
Hardening    WARN  2 unexpected port(s) listening on all interfaces: 6443/tcp, 10250/tcp

WARN: Sysctl: fs.inotify.max_user_watches=122241 is low for k8s
WARN: Hardening: 2 unexpected port(s) listening on all interfaces: 6443/tcp, 10250/tcp
WARN: Hardening: NOPASSWD sudo for: andrei
WARN: Hardening: 17 SELinux denials in the last hour (mode: enforcing)
                 ↑ SecurityCollector reads audit.log directly — catches it.
                   KernelSecurityCollector reads journald — misses it.

### After the fix — dsd health (KernelSec now reads audit.log)

KernelSec    CRIT  17 SELinux denials (mode: enforcing)   ← CORRECT
Hardening    WARN  2 unexpected port(s) listening on all interfaces: 6443/tcp, 10250/tcp

CRIT: KernelSec: 17 SELinux denials (mode: enforcing)
WARN: Hardening: 2 unexpected port(s) listening on all interfaces: 6443/tcp, 10250/tcp
WARN: Hardening: NOPASSWD sudo for: andrei
WARN: Hardening: 17 SELinux denials in the last hour (mode: enforcing)

### Sample AVC entry from /var/log/audit/audit.log

type=AVC msg=audit(1778573474.851:6602): avc:  denied  { entrypoint } for
  pid=41422 comm="runcon" path="/usr/bin/cat" dev="nvme1n1p3" ino=50349910
  scontext=system_u:system_r:avahi_t:s0
  tcontext=system_u:object_r:bin_t:s0
  tclass=file permissive=0

→ This entry exists in /var/log/audit/audit.log.
→ It does NOT appear in journalctl output.
→ This is confirmed, expected Linux Audit Framework behavior.

### Why auditd intercepts before journald

When auditd is running, the kernel sends AVC messages to the audit
netlink socket — a privileged channel that auditd owns exclusively.
auditd writes them to /var/log/audit/audit.log.

The kernel does NOT send them to the ring buffer (printk/dmesg/journald)
when a registered audit daemon is listening. This prevents security events
from being lost, delayed, or tampered with by unprivileged log consumers.

This is documented behavior (man 8 auditd, Linux Audit Subsystem docs).
It is not a bug in RHEL. It is the correct behavior.

### Which monitoring tools are affected

Any tool that detects SELinux violations by reading journald, dmesg,
/dev/kmsg, or /proc/kmsg will silently return zero on any system where
auditd is running — which is every hardened RHEL/CentOS/AlmaLinux/Rocky
system in production.

Known-affected approaches (reading wrong source):
- journalctl --since "1 hour ago" | grep "avc: denied"
- dmesg | grep "avc: denied"
- /dev/kmsg or /proc/kmsg polling
- Any Prometheus exporter, agent, or check that uses these

Correct source: /var/log/audit/audit.log (requires root)

### DashDiag behavior after fix

collectSELinux() in kernel_security.go:
1. Calls countAVCsFromAuditLog() — reads audit.log, parses Unix timestamps,
   counts type=AVC entries within the last hour window
2. Falls back to journalctl only if audit.log is unreadable (non-root,
   or no auditd installed)

This is the same source auditd uses. Same data. No intermediary.
