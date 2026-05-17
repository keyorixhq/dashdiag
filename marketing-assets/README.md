# DashDiag Marketing Assets

Raw data and ready-to-use content for marketing, demos, and customer conversations.

## Stories

### `overnight-story-2026-05-11.md`
9 hours of alternating CPU + GPU stress on RHEL 10.1.
48 snapshots, every stress event captured. Real thermal throttling at 98°C.
Real swap thrashing at 29,989 pages/s. Primary demo asset.

### `log-health-findings-2026-05-16.md`
All log-related findings across every machine tested today.
7 checks, 5 machines, one pattern: RHEL/SUSE lose logs silently by default.
Debian/Ubuntu are the reference — they get it right.
Includes fix commands, screenshot checklist, and three LinkedIn angles.

### `journald-story-2026-05-16.md`
The focused journald post — "Your logs are lying to you."
LinkedIn, Twitter, and landing page versions ready to publish.
Fresh Oracle Linux 10.1 install → 135 CVEs → patched → rebooted → /boot at 81%.
The story of what a routine patch cycle misses. Distro-aware fix commands.
**LinkedIn angle:** "Patched. Rebooted. Clean. Then dsd found one more thing."

### `macbook-air-2011-story-2026-05-15.md`
2011 MacBook Air running Ubuntu 24.04. Dying SSD (794 bad sectors).
Load-aware thermal check catching dried paste at idle (61°C at 7% load).
94°C under moderate stress. The system balancing on the edge.
**LinkedIn angle:** "The hardware is Apple. The story is universal."

### `debian-story-2026-05-12.txt`
Raw Debian 13 validation data.

## Screenshots

All screenshots in `screenshots/`. Named files are production-ready.
Timestamp-named files need renaming before use.

### Named (production-ready)
- `health-normal-sles16.png` — clean SLES 16 health check
- `cve-top-74-advisories-sles16.png` — CVE scan with 74 advisories
- `cve-bottom-sles16.png` — CVE scan bottom (fix commands)
- `gpu-vram-warn-89pct-sles16.png` — GPU VRAM at 89%
- `hero-thermal-cpu-crit-sles16.png` — CPU thermal CRIT under GPU burn
- `security-clean-sles16.png` — security check clean
- `watch-mode-thermal-warn-sles16.png` — watch mode catching thermal event
- `health-rocky10-full.png` — Rocky Linux 10 full health
- `health-rocky10-hostname.png` — Rocky Linux 10 header
- `disk 81 after patch old kernel is forgoten.png` — Oracle Linux /boot at 81%
- `oracle10-cve-clean-after-patch.png` — Oracle Linux CVE clean after patch
- `ubuntu26-health.png` — Ubuntu 26.04 health
- `ubuntu26-hardware.png` — Ubuntu 26.04 hardware
- `ubuntu26-cve-clean.png` — Ubuntu 26.04 CVE clean
- `kuber.png` — k8s check

## How to use

**For landing page:**
- Lead with: "9 hours. 48 snapshots. Every incident captured." (overnight story)
- Or: "One command. 794 bad sectors. 94°C under load." (MacBook Air story)

**For social media:**
- Oracle Linux: three-panel screenshot sequence (135 CVEs → patched → /boot warn)
- MacBook Air: three-panel (idle thermal warn → stress 94°C → recovery still hot)

**For customer demos:**
- Show overnight story first (immediate understanding of value)
- Then show `dsd health` running live (~1.5 seconds)
- Then show `dsd hardware` on real aging hardware

**For MSP outreach:**
- SLES 16 CVE screenshot (enterprise story)
- Oracle Linux /boot story (patch cycle operational debt)

## Source machines

| Machine | IP | OS | Status |
|---------|----|----|--------|
| RHEL/Rocky stress box | 192.168.1.145 | varies | shared |
| Oracle Linux 10.1 | 192.168.1.145 | OL 10.1 | available |
| MacBook Air 2011 | 192.168.10.10 | Ubuntu 24.04 | permanent |

