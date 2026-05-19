# DashDiag — journald Silent Log Loss Story — 2026-05-16

> Core insight: journald has four silent failure modes that most admins only
> discover during an incident. dsd health catches all four with fix commands.

## The four silent failures

1. **Volatile storage** — RHEL/Rocky don't create /var/log/journal/ by default.
   All logs wiped on every reboot. Nobody notices until they need them.

2. **Missing crash logs** — SyncIntervalSec defaults to 5 minutes. A process
   that crashes between flushes loses its final log lines permanently. The ones
   that would have told you exactly what went wrong.

3. **Unbounded growth** — no SystemMaxUse cap by default. Journal grows until
   it fills the disk. Then journald silently stops writing. No error, no alert.

4. **No text fallback** — binary format. Unreadable with grep, tail, less.
   Unreadable on Windows. Unreadable if journald itself is broken.

## What dsd found on a fresh Rocky Linux LXC container

```
⚠️  journald logs are volatile — all logs lost on reboot (no /var/log/journal/)
   → mkdir -p /var/log/journal
   → echo 'Storage=persistent' >> /etc/systemd/journald.conf

ℹ️  SyncIntervalSec is default 5min — final crash logs may be lost
   → echo 'SyncIntervalSec=30s' >> /etc/systemd/journald.conf

ℹ️  no text log fallback — logs require journalctl to read
   → apt/dnf install rsyslog
```

Three problems. One command. Fixable in under a minute.

---

## LinkedIn post

Your logs are lying to you.

Not because someone tampered with them. Because they were never written in the first place.

Here's what most Linux admins don't know about journald:

---

By default, journald flushes logs to disk every 5 minutes.

If your service crashes between flushes — the final log lines, the ones that would tell you exactly what went wrong — are gone. Silently. No error. No warning. Just missing.

By default, if /var/log/journal/ doesn't exist, all logs are volatile. Every reboot wipes them. RHEL and Rocky Linux don't create this directory by default.

By default, there is no size cap on the journal. It grows until it fills the disk. Then journald stops writing. Still no error.

By default, there's no rsyslog fallback. Binary logs. Unreadable with grep, tail, or less. Unreadable on Windows. Unreadable if journald itself is broken.

---

We ran DashDiag on a fresh Rocky Linux LXC container.

One command.

⚠️  journald logs are volatile — all logs lost on reboot
   → mkdir -p /var/log/journal
   → echo 'Storage=persistent' >> /etc/systemd/journald.conf

ℹ️  SyncIntervalSec is default 5min — final crash logs may be lost
   → echo 'SyncIntervalSec=30s' >> /etc/systemd/journald.conf

ℹ️  no text log fallback — logs require journalctl to read
   → apt/dnf install rsyslog

Three silent problems. One command. All fixable in under a minute.

You can't fix what you don't know is broken.

→ dashdiag.sh

#linux #sysadmin #devops #observability #systemd

---

## Twitter / X

By default, journald:

- flushes logs every 5 min (crash = missing final logs)
- loses all logs on reboot if /var/log/journal/ doesn't exist
- has no size cap (fills disk, then stops writing)
- has no rsyslog fallback (binary logs, unreadable without journalctl)

DashDiag catches all four. One command.

→ dashdiag.sh

---

## Landing page

Your logs aren't where you think they are.

journald has four silent failure modes that most sysadmins only discover during an incident:

• Logs lost on reboot — RHEL and Rocky don't create /var/log/journal/ by default
• Missing crash logs — 5-minute sync interval means final lines are never flushed
• Unbounded growth — no size cap, journal fills the disk, then silently stops writing
• No text fallback — binary format, unreadable without journalctl

dsd health catches all four. With fix commands.

Before the incident, not after.

---

## Screenshot to attach

dsd health output on Rocky Linux LXC showing all three findings.
Run: pct exec 203 -- /usr/local/bin/dsd health
(or fresh RHEL/Rocky VM for cleaner branding)
