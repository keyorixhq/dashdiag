#!/usr/bin/env bash
# check-nonroot-invariant.sh — guard against the recurring "non-root false verdict"
# bug class (BUG-064/066/067/070, …).
#
# The invariant: on a HEALTHY host, running `dsd health` unprivileged must NEVER
# produce a worse verdict for a check than running it as root. A privileged tool
# (btrfs/nvme/nft/sshd -T/…) emits different output unprivileged — failing, empty,
# or a degraded-looking artifact (e.g. `btrfs filesystem show` prints a present
# device as `MISSING` because it can't open it without root). A correct collector
# degrades that to INFO/"unverified"; a buggy one false-CRITs or false-WARNs. This
# job runs dsd both ways on the same box and fails if any check escalates non-root.
#
# A btrfs loopback filesystem is mounted first so the btrfs collector's non-root
# path is exercised against a real btrfs. NOTE: the specific BUG-070 trigger (an
# unprivileged `btrfs filesystem show` printing a present device as `size 0 ...
# MISSING`) is btrfs-progs-version-specific — it reproduces on Fedora 43 but on a
# stock Ubuntu runner the same command hard-errors instead (which the collector
# already handles safely). So the DETERMINISTIC BUG-070 regression guard is the
# unit test in btrfs_linux_test.go (fed the exact Fedora bytes); this job is the
# broader guard for the whole class, catching any non-root escalation that DOES
# reproduce in the runner environment.
#
# Requires: root/sudo to mount the loopback and to run the privileged pass; a
# non-root user for the unprivileged pass; jq. Intended for CI (GitHub ubuntu
# runner: user `runner` with passwordless sudo).
set -euo pipefail

DSD="${DSD:-}"
if [ -z "$DSD" ]; then
  DSD="$(mktemp -d)/dsd"
  echo "building dsd -> $DSD"
  CGO_ENABLED=0 go build -o "$DSD" ./cmd/dsd
fi

if [ "$(id -u)" -eq 0 ]; then
  echo "FAIL: run this as a NON-root user with sudo (it needs both privilege levels)" >&2
  exit 1
fi

# ── btrfs surface ────────────────────────────────────────────────────────────
# A loopback btrfs so the btrfs collector's non-root path runs against a real
# filesystem (the loop device is root-owned, so an unprivileged read is denied).
# Whether that surfaces as the BUG-070 `MISSING` artifact or a hard error depends
# on the btrfs-progs version; either way the invariant below must hold.
IMG="$(mktemp)"
MNT="$(mktemp -d)"
cleanup() { sudo umount "$MNT" 2>/dev/null || true; rm -f "$IMG"; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT

sudo apt-get update -qq >/dev/null && sudo apt-get install -y -qq btrfs-progs jq >/dev/null
truncate -s 300M "$IMG"
mkfs.btrfs -q "$IMG"
sudo mount -o loop "$IMG" "$MNT"
echo "mounted loopback btrfs at $MNT"

# ── collect both privilege levels ────────────────────────────────────────────
ROOT_JSON="$(mktemp)"; NONROOT_JSON="$(mktemp)"
# dsd health exits non-zero on WARN/CRIT — keep the JSON, ignore the exit code.
# SC2024: the redirect SHOULD run as the invoking (non-root) user — we want the
# temp file owned by us so the comparison step can read it; only dsd needs root.
# shellcheck disable=SC2024
sudo "$DSD" health --json >"$ROOT_JSON" 2>/dev/null || true
"$DSD" health --json >"$NONROOT_JSON" 2>/dev/null || true

# ── compare: no check may raise a WARN/CRIT non-root that root doesn't ────────
# Rank OK<INFO<WARN<CRIT. A non-root run degrading to INFO ("couldn't measure")
# is the CORRECT, honest behavior and is always allowed — even when root is OK.
# The bug class is non-root introducing a WARN/CRIT (or escalating to a higher
# one) that root, with full access, does not. So flag a check only when its
# non-root status is WARN/CRIT (rank >= 2) AND strictly worse than root's.
#
# SKIP volatile, point-in-time checks that read WORLD-READABLE sources (/proc):
# root and non-root read identical data there, so any difference is transient
# load noise between the two sequential runs, NOT a privilege-driven false verdict
# (e.g. Pressure/CPU/IO momentarily spiking during one run). The bug class only
# affects checks reading ROOT-GATED sources (Drives/Firewall/Hardening/OOM/…),
# which this still compares. Without this skip the guard flaked on a PSI blip.
VIOLATIONS="$(jq -n \
  --slurpfile r "$ROOT_JSON" --slurpfile n "$NONROOT_JSON" \
  --argjson skip '["CPU Load","Memory","Swap","IO","Pressure","Processes","Entropy","Clock","FDLimits","Network","Sessions"]' '
  def rank(s): {"OK":0,"INFO":1,"WARN":2,"CRIT":3}[s] // 0;
  ($r[0].checks // []) as $rc | ($n[0].checks // []) as $nc |
  ($rc | map({(.name): .status}) | add) as $rootmap |
  $nc
  | map(select(([.name] | inside($skip) | not)
               and $rootmap[.name] != null
               and rank(.status) >= 2
               and rank(.status) > rank($rootmap[.name]))
        | {check: .name, nonroot: .status, root: $rootmap[.name]})
')"

COUNT="$(echo "$VIOLATIONS" | jq 'length')"
if [ "$COUNT" -gt 0 ]; then
  echo "FAIL: $COUNT check(s) report a WORSE verdict non-root than root (false-verdict bug class):" >&2
  echo "$VIOLATIONS" | jq -r '.[] | "  - \(.check): non-root=\(.nonroot)  root=\(.root)"' >&2
  echo >&2
  echo "A non-root run must degrade to INFO/unverified, never escalate. See BUGS.md BUG-070." >&2
  exit 1
fi
echo "OK: no check escalated on the non-root run (invariant holds)"
