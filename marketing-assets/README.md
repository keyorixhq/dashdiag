# DashDiag Marketing Assets

Raw data and ready-to-use content for marketing, demos, and customer conversations.

## Files

### `overnight-story-2026-05-11.md`
The morning story output from 9 hours of overnight stress testing on RHEL.
48 snapshots, every stress event captured. This is the primary demo asset.

### `dashdiag-overnight-2026-05-11.log`
Raw cron log — all 18 `dsd health --terse` outputs from the overnight run.
Source of truth for the story. Use for correlation engine rule design.

## How to use

**For landing page:**
- Take a clean screenshot of the story output
- Lead with: "9 hours. 48 snapshots. Every incident captured."

**For social media:**
- LinkedIn thread → `MARKETING.md` § "The Overnight Story"
- Twitter/X → short version with screenshot

**For customer demos:**
- Show the story output first (3-5 seconds, immediate understanding)
- Then show `dsd health` running live (1.3 seconds)
- Then show `dsd gpu` with process drilldown

**For correlation engine v2 design:**
- The 20:00 cluster (8 simultaneous symptoms) is the canonical "memory
  pressure cascade" pattern — first rule to encode.

## Source machine

- 192.168.1.145 — andrei@localhost.localdomain
- RHEL 10.1, AMD Ryzen 7 5800H, 16GB RAM, RTX 3070, k3s
- Available until ~end of May 2026

## Pattern notes for future demos

- **:00 events** = CPU+memory+IO+network stress signature
- **:30 events** = GPU stress signature
- Recovery happens within 30 minutes for most incidents
- Some incidents (5 OOM kills) persist across multiple snapshots
- The story output is best when there's clear contrast between
  degraded states (↓) and recovery (↑)
