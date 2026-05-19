# DashDiag — Log Health Findings Master Story — 2026-05-16

> Everything dsd found today related to logging across all test machines.
> Source material for LinkedIn posts, landing page copy, and MSP demos.

---

## All findings by machine

### Proxmox host (HP ProDesk 600 G2 / Debian 13 / Intel i7-6700)

```
ℹ️  no text log fallback — rsyslog not installed, binary-only logs
ℹ️  SyncIntervalSec default 5min — final crash logs may be lost
```

A production Proxmox host with no rsyslog. If journald corrupts,
there is no fallback. If a VM crashes, the host logs are unreadable
with grep or tail. And the last 5 minutes before any crash? Gone.

### Rocky Linux 10 LXC (CT203)

```
⚠️  journald logs are volatile — all logs lost on reboot
ℹ️  SyncIntervalSec default 5min — final crash logs may be lost
```

Fresh Rocky Linux LXC container. Standard RHEL default — no
/var/log/journal/ directory. Every reboot wipes all logs.
Nobody configured this. Nobody noticed. Until dsd did.

### AlmaLinux 10 LXC (CT200)

```
⚠️  journald logs are volatile — all logs lost on reboot
```

Same pattern as Rocky. RHEL-family containers don't persist
logs by default. Two machines, same silent failure.

### openSUSE Leap 16 LXC (CT204)

```
ℹ️  no text log fallback — rsyslog not installed
```

openSUSE ships without rsyslog. Binary-only logs.

### Debian 13 LXC (CT201) and Ubuntu 24.04 LXC (CT202)

```
Logs  ✅  OK
```

Debian and Ubuntu get this right by default. /var/log/journal/
created automatically. rsyslog installed. These are the reference
implementations that prove it's fixable — if the distro bothers.

---

## The pattern

| Distro family | Volatile journal | No text fallback | Sync risk |
|---------------|-----------------|-----------------|-----------|
| RHEL (Rocky, Alma, Oracle) | ⚠️ YES | varies | ℹ️ YES |
| SUSE (openSUSE, SLES) | varies | ⚠️ YES | ℹ️ YES |
| Debian/Ubuntu | ✅ NO | ✅ NO | ℹ️ YES |
| Proxmox host | ✅ persistent | ⚠️ YES | ℹ️ YES |

The sync risk (SyncIntervalSec=5min) is universal — it's a systemd
default, not a distro choice. Every Linux system using journald is
affected unless explicitly configured otherwise.

---

## The five checks dsd now runs

```
1. Journal corruption    — only archived files, no false positives
2. Volatile storage      — /var/log/journal/ + Storage= config
3. Rate limiting         — RateLimitBurst < 100 = logs silently dropped
4. No text fallback      — rsyslog/syslog-ng/text log files
5. Unbounded growth      — no SystemMaxUse cap + journal > 1GB
6. SyncIntervalSec risk  — default 5min = final crash logs lost
7. Log disk space        — 80% WARN, 90% CRIT on log volume mount
```

Seven checks. Zero commands for the admin. All with fix commands.

---

## LinkedIn post angles

### Angle 1: The distro comparison (tabular, educational)
"We ran dsd on RHEL, SUSE, Debian, and Ubuntu containers.
Only Debian and Ubuntu get logging right by default."
→ Attach the findings table above.

### Angle 2: The universal sync risk
"Every Linux server using journald has this problem.
Including yours. It's a systemd default, not a distro bug."
→ Short punchy post, no machine names needed.

### Angle 3: The "before the incident" framing
"We didn't find these on broken machines.
We found them on fresh, freshly installed, working systems.
That's the point."

---

## The master quote for all copy

"Your logs are lying to you.
Not because someone tampered with them.
Because they were never written in the first place."

---

## Fix commands (for landing page / docs)

```bash
# Fix volatile journal (RHEL/Rocky/Alma)
mkdir -p /var/log/journal
echo 'Storage=persistent' >> /etc/systemd/journald.conf
systemctl restart systemd-journald

# Fix sync interval (all distros)
echo 'SyncIntervalSec=30s' >> /etc/systemd/journald.conf
systemctl restart systemd-journald

# Fix unbounded growth (all distros)
echo 'SystemMaxUse=2G' >> /etc/systemd/journald.conf
journalctl --vacuum-size=2G

# Add text fallback (RHEL)
dnf install rsyslog && systemctl enable --now rsyslog

# Add text fallback (Debian/Ubuntu)
apt install rsyslog && systemctl enable --now rsyslog
```

---

## Screenshot checklist

- [ ] Rocky Linux LXC: dsd health showing volatile WARN + sync INFO
- [ ] AlmaLinux LXC: dsd health showing volatile WARN
- [ ] Proxmox host: dsd health showing no-fallback INFO
- [ ] Debian LXC: dsd health showing Logs OK (the contrast shot)
- [ ] Side by side if possible: RHEL vs Debian logging defaults
