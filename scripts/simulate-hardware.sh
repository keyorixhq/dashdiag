#!/usr/bin/env bash
# scripts/simulate-hardware.sh
#
# Creates fake hardware on a Linux host using kernel modules.
# Lets you test collectors that need bonds, OOM events, FC HBAs, etc.
# Run as root on the Legion or any Linux VM.
#
# Usage:
#   sudo bash scripts/simulate-hardware.sh bond     # create bond0 with dummy slaves
#   sudo bash scripts/simulate-hardware.sh oom      # inject OOM events into journal
#   sudo bash scripts/simulate-hardware.sh pressure # stress memory to trigger PSI
#   sudo bash scripts/simulate-hardware.sh clean    # tear everything down
#
# After setup: sudo dsd health (bond/OOM/pressure collectors will fire)

set -euo pipefail

action="${1:-help}"

simulate_launchd() {
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "❌ launchd simulation only works on macOS"
        exit 1
    fi
    PLIST=~/Library/LaunchAgents/com.dashdiag.test.plist
    cat > "$PLIST" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dashdiag.test</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>exit 1</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST_EOF
    launchctl load "$PLIST"
    echo ""
    echo "✅ Failing LaunchAgent loaded — now run: dsd health"
    echo "   Expected: Launchd ⚠️  1 launchd service(s) failed: com.dashdiag.test"
    echo ""
    echo "→ To clean up: bash scripts/simulate-hardware.sh clean"
}

simulate_launchd_clean() {
    PLIST=~/Library/LaunchAgents/com.dashdiag.test.plist
    if [[ -f "$PLIST" ]]; then
        launchctl unload "$PLIST" 2>/dev/null || true
        rm "$PLIST"
        echo "✅ com.dashdiag.test removed"
    else
        echo "nothing to clean"
    fi
}

simulate_bond() {
    echo "→ Loading kernel modules..."
    modprobe bonding || { echo "❌ bonding module not available"; exit 1; }
    modprobe dummy  || { echo "❌ dummy module not available"; exit 1; }

    echo "→ Creating bond0 in 802.3ad mode..."
    ip link add bond0 type bond 2>/dev/null || true
    ip link set bond0 type bond mode 802.3ad
    ip link set bond0 type bond miimon 100

    echo "→ Adding dummy slave interfaces..."
    ip link add dummy0 type dummy 2>/dev/null || true
    ip link add dummy1 type dummy 2>/dev/null || true
    ip link set dummy0 master bond0
    ip link set dummy1 master bond0
    ip link set bond0 up

    echo "→ Verifying /proc/net/bonding/bond0 exists..."
    cat /proc/net/bonding/bond0 | head -5

    echo ""
    echo "✅ bond0 created — now run: sudo dsd health"
    echo "   Expected: Bonding ✅  bond0  2/2 slaves up  802.3ad"
    echo ""
    echo "→ To simulate a degraded bond (one slave down):"
    echo "   ip link set dummy1 down"
    echo "   Expected: Bonding ⚠️  bond0: 1/2 slave(s) down — running degraded"
}

simulate_oom() {
    echo "→ Injecting fake OOM kill events into system journal..."
    # systemd-cat writes to the journal as if it were a kernel message
    echo "Out of memory: Kill process 99901 (nginx) score 900 or sacrifice child" \
        | systemd-cat -t kernel -p warning
    echo "Killed process 99901 (nginx) total-vm:4096kB, anon-rss:2048kB" \
        | systemd-cat -t kernel -p warning
    echo "Out of memory: Kill process 99902 (php-fpm) score 750 or sacrifice child" \
        | systemd-cat -t kernel -p warning
    echo "Killed process 99902 (php-fpm) total-vm:8192kB, anon-rss:6144kB" \
        | systemd-cat -t kernel -p warning

    echo ""
    echo "✅ OOM events injected — now run: sudo dsd health"
    echo "   Expected: OOM ⚠️  2 OOM kill event(s) in the last 24h — killed: nginx, php-fpm"
}

simulate_pressure() {
    if ! [ -f /proc/pressure/memory ]; then
        echo "❌ PSI not available on this kernel (need Linux 4.20+ with CONFIG_PSI=y)"
        exit 1
    fi
    echo "→ Current memory pressure (before stress):"
    cat /proc/pressure/memory

    if ! command -v stress-ng &>/dev/null; then
        echo "→ Installing stress-ng..."
        apt-get install -y stress-ng 2>/dev/null || yum install -y stress-ng 2>/dev/null || {
            echo "❌ stress-ng not available — install manually"
            exit 1
        }
    fi

    FREE_MB=$(free -m | awk '/^Mem:/{print $4}')
    STRESS_MB=$(( FREE_MB * 90 / 100 ))
    echo "→ Stressing ${STRESS_MB}MB of memory for 15s..."
    echo "   Watch: watch -n1 'cat /proc/pressure/memory'"
    echo ""
    stress-ng --vm 1 --vm-bytes "${STRESS_MB}M" --timeout 15s --quiet &

    sleep 5
    echo "→ Memory pressure during stress:"
    cat /proc/pressure/memory
    echo ""
    echo "   Now run in another terminal: sudo dsd health"
    echo "   Expected: Pressure ⚠️  memory pressure X.X%% avg60"
    wait
}

clean() {
    echo "→ Cleaning up simulated hardware..."
    ip link del bond0 2>/dev/null && echo "  removed bond0" || true
    ip link del dummy0 2>/dev/null && echo "  removed dummy0" || true
    ip link del dummy1 2>/dev/null && echo "  removed dummy1" || true
    rmmod dummy 2>/dev/null && echo "  unloaded dummy module" || true
    echo "✅ Done"
}

case "$action" in
    launchd)  simulate_launchd ;;
    bond)     simulate_bond ;;
    oom)      simulate_oom ;;
    pressure) simulate_pressure ;;
    clean)    clean; simulate_launchd_clean ;;
    *)
        echo "Usage: bash scripts/simulate-hardware.sh <action>"
        echo ""
        echo "Actions:"
        echo "  launchd   macOS: create a failing LaunchAgent (com.dashdiag.test)"
        echo "  bond      Linux: create bond0 with 2 dummy slave NICs"
        echo "  oom       Linux: inject fake OOM kill events into journal"
        echo "  pressure  Linux: stress memory to trigger PSI alerts"
        echo "  clean     tear down all simulated hardware"
        echo ""
        echo "HBA and multipath require real hardware or a full VM with scsi_debug."
        echo "IPMI requires ipmisim or a real BMC — no easy simulation available."
        ;;
esac
