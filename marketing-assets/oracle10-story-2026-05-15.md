# DashDiag Oracle Linux 10.1 Story — 2026-05-15

> Fresh Oracle Linux Server 10.1 install. One command. Four insights.

## The sequence

### Step 1 — fresh install, first run
```
dsd cve --all
→ 135 pending security advisories
→ 7 CRITICAL updates (root only)
```

### Step 2 — patch
```
dnf upgrade --security
→ 119 advisories resolved
→ 16 remaining (Ksplice kernel live-patch advisories — need reboot)
```

### Step 3 — reboot
```
dsd health
→ Packages  ✅  (all critical CVEs cleared)
```

### Step 4 — unexpected finding after reboot
```
dsd health (as root)
→ Disk  ⚠️  disk usage at 81% on /boot (/dev/nvme1n1p2)
```

The upgrade installed a new kernel but left behind 4 previous versions.
Each with its own 90MB+ initramfs. Silently filling /boot.

dsd showed the fix immediately:
```
→ to inspect: rpm -q kernel
→ to fix:     dnf remove --oldinstallonly --setopt installonly_limit=2
```

## What this proves

- dsd found what a routine patch cycle misses
- Not just CVEs — the operational debt left behind
- /boot cleanup is on the admin's radar before it becomes an incident
- Fix commands are distro-aware (dnf on Oracle/RHEL, apt on Debian, etc.)

## The LinkedIn post angle

"135 CVEs on a fresh Oracle Linux install. Patched. Rebooted. Clean.
Then dsd found one more thing nobody was looking for."

## Machine

- Oracle Linux Server 10.1
- kernel 6.12.0 + UEK (Unbreakable Enterprise Kernel)
- x86_64, physical machine at 192.168.1.145
- SELinux enforcing, firewalld, Cockpit on 9090
- auditd running but no rules configured (also flagged by dsd)
