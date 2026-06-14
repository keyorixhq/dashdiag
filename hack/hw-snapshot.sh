#!/usr/bin/env bash
# hw-snapshot.sh — raw real-hardware diagnostic snapshot for DashDiag development.
#
# Captures the RAW system inputs that dsd's collectors read, so AMD (and other)
# collector code can be built and debugged offline against real ground truth.
#
# This is NOT `dsd capture`. capture records what the collectors *produced*;
# this records what they *read* — which is what you need when a collector is
# unfinished or might be silently returning nothing on unfamiliar hardware.
#
# Safe: read-only. Reads sysfs and runs diagnostic commands; changes nothing.
# Run with sudo so SMART / IPMI / dmidecode / journalctl work.
#
# Usage:
#   sudo ./hw-snapshot.sh                 # raw snapshot only
#   sudo ./hw-snapshot.sh /path/to/dsd    # also run dsd + capture its output
#
# Output: one tarball in the current dir:  hwsnap-<host>-<timestamp>.tar.gz
# Send back that single file. NOTE: it is UNREDACTED (hostname, IPs, disk
# serials, VM names). Fine for debugging between trusted parties — just be aware.

set -u

DSD_BIN="${1:-dsd}"
TS="$(date +%Y%m%d-%H%M%S)"
HOST="$(hostname -s 2>/dev/null || echo host)"
OUT="hwsnap-${HOST}-${TS}"
DIR="$(mktemp -d)/${OUT}"
mkdir -p "$DIR"

log() { echo "[hwsnap] $*"; }

# run <name> <cmd> [args...] : capture stdout, stderr, exit code.
# A missing tool leaves a .missing marker so "tool absent" is never confused
# with "ran but produced nothing".
run() {
  local name="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "tool not found: $1" > "$DIR/${name}.missing"
    return
  fi
  "$@" > "$DIR/${name}.txt" 2> "$DIR/${name}.err"
  echo "$?" > "$DIR/${name}.exit"
  [ -s "$DIR/${name}.err" ] || rm -f "$DIR/${name}.err"
}

# dumptree <name> <dir> : snapshot a sysfs/proc subtree, one file per line with a
# header, guarded by timeout so a blocking sysfs node can't hang the run.
dumptree() {
  local name="$1" root="$2"
  if [ ! -d "$root" ]; then
    echo "absent: $root" > "$DIR/${name}.missing"
    return
  fi
  {
    find "$root" -type f 2>/dev/null | sort | while read -r f; do
      echo "===== $f ====="
      timeout 1 cat "$f" 2>/dev/null
      echo
    done
  } > "$DIR/${name}.txt"
}

log "writing to $DIR"

# ---- System identity / base ------------------------------------------------
run  uname            uname -a
cp /etc/os-release          "$DIR/os-release.txt"   2>/dev/null
cp /proc/cmdline            "$DIR/proc-cmdline.txt"  2>/dev/null
run  uptime           uptime
run  dmidecode_sys    dmidecode -t system -t bios -t baseboard -t processor -t memory

# ---- CPU (AMD: amd-pstate, topology) ---------------------------------------
cp /proc/cpuinfo            "$DIR/proc-cpuinfo.txt"  2>/dev/null
run  lscpu            lscpu
run  lscpu_json       lscpu -J
dumptree cpufreq       /sys/devices/system/cpu/cpu0/cpufreq
dumptree cpu_topology  /sys/devices/system/cpu/cpu0/topology

# ---- Thermal (k10temp — the key AMD divergence) ----------------------------
dumptree hwmon         /sys/class/hwmon
dumptree thermal_zone  /sys/class/thermal
run  sensors          sensors
run  sensors_json     sensors -j

# ---- GPU (amdgpu sysfs + PCI) ----------------------------------------------
run  lspci_nnk        lspci -nnk
run  lspci_vga        sh -c 'lspci -nnvv -d ::0300 -d ::0302 -d ::0380'
dumptree drm           /sys/class/drm
# driver symlinks (amdgpu vs nvidia vs ast) — targets matter, dump them explicitly
ls -l /sys/class/drm/card*/device/driver 2>/dev/null > "$DIR/drm-driver-links.txt"

# ---- Memory / ECC (EDAC — AMD memory errors surface here) ------------------
dumptree edac          /sys/devices/system/edac
run  ras_summary      ras-mc-ctl --summary
run  ras_errors       ras-mc-ctl --error-count

# ---- MCE / kernel hardware errors ------------------------------------------
dumptree machinecheck  /sys/devices/system/machinecheck
run  kmsg_warn        journalctl -k -p warning..emerg --no-pager -b
run  dmesg_hw         sh -c 'dmesg -T 2>/dev/null | grep -iE "mce|edac|hardware error|thermal|throttl" '

# ---- Disk / SMART / NVMe ---------------------------------------------------
run  lsblk            lsblk -O -J
run  smartctl_scan    smartctl --scan
# per-device SMART (SATA/SAS) — iterate whatever --scan finds
if command -v smartctl >/dev/null 2>&1; then
  smartctl --scan 2>/dev/null | awk '{print $1}' | while read -r dev; do
    [ -n "$dev" ] || continue
    safe="$(echo "$dev" | tr '/' '_')"
    smartctl -x "$dev" > "$DIR/smartctl${safe}.txt" 2>&1
  done
fi
run  nvme_list        nvme list
if command -v nvme >/dev/null 2>&1; then
  nvme list 2>/dev/null | awk '/^\/dev/{print $1}' | while read -r dev; do
    safe="$(echo "$dev" | tr '/' '_')"
    nvme smart-log "$dev" > "$DIR/nvme-smartlog${safe}.txt" 2>&1
    nvme id-ctrl   "$dev" > "$DIR/nvme-idctrl${safe}.txt"  2>&1
  done
fi

# ---- IPMI / BMC ------------------------------------------------------------
run  ipmi_mc          ipmitool mc info
run  ipmi_sensor      ipmitool sensor
run  ipmi_sdr         ipmitool sdr elist
run  ipmi_sel         ipmitool sel list
run  dmidecode_ipmi   dmidecode -t 38

# ---- Storage stack ---------------------------------------------------------
run  zpool_status     zpool status -v
run  zpool_list       zpool list
run  zfs_list         zfs list
run  pvs              pvs
run  vgs              vgs
run  lvs              lvs
cp /proc/mdstat             "$DIR/proc-mdstat.txt"   2>/dev/null
run  multipath        multipath -ll

# ---- Proxmox ---------------------------------------------------------------
run  pveversion       pveversion -v
run  qm_list          qm list
run  pct_list         pct list
run  pve_resources    pvesh get /cluster/resources --output-format json

# ---- Layer 2: what dsd currently produces (for diffing against the raw data) ----
if command -v "$DSD_BIN" >/dev/null 2>&1 || [ -x "$DSD_BIN" ]; then
  log "running dsd ($DSD_BIN)"
  "$DSD_BIN" version            > "$DIR/dsd-version.txt"     2>&1
  "$DSD_BIN" health --gpu --json > "$DIR/dsd-health.json"    2>"$DIR/dsd-health.err"
  "$DSD_BIN" health --gpu        > "$DIR/dsd-health.txt"     2>&1
  if [ -s "$DIR/dsd-health.json" ]; then
    "$DSD_BIN" capture < "$DIR/dsd-health.json" > "$DIR/dsd-capture.yaml" 2>&1
  fi
else
  echo "dsd binary not found at: $DSD_BIN" > "$DIR/dsd.missing"
  log "no dsd binary — Layer 2 skipped (raw snapshot still captured)"
fi

# ---- Manifest --------------------------------------------------------------
{
  echo "DashDiag raw hardware snapshot"
  echo "host:    $HOST"
  echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel:  $(uname -r)"
  echo
  echo "Layout:"
  echo "  *.txt       command output / sysfs dump"
  echo "  *.err       stderr (only present if non-empty)"
  echo "  *.exit      exit code of the command"
  echo "  *.missing   tool or path was absent (NOT the same as empty output)"
  echo "  dsd-*.json  current dsd collector output (Layer 2)"
  echo
  echo "UNREDACTED: contains hostname, IPs, disk serials, VM names."
} > "$DIR/MANIFEST.txt"

# ---- Pack ------------------------------------------------------------------
TARBALL="${PWD}/${OUT}.tar.gz"
tar -czf "$TARBALL" -C "$(dirname "$DIR")" "$OUT"
rm -rf "$(dirname "$DIR")"

log "done -> $TARBALL"
log "send that one file back."
