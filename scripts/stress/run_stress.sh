#!/bin/bash
# DashDiag — Run stress suite
# Copies latest stress.sh from project and runs it with --physical flag
#
# Usage: bash run_stress.sh [test]
# Tests: all | memory | cpu | io | swap | zombie | fd | disk
#        systemd | clock | sysctl
#        net_closewait | net_latency | net_loss
#        net_down | net_dns | net_gateway  (physical only)
#
# Examples:
#   bash run_stress.sh           → runs all tests
#   bash run_stress.sh zombie    → runs single test
#   bash run_stress.sh net_down  → physical network test

set -euo pipefail

DSD_BIN="${DSD_BIN:-/tmp/dsd}"
STRESS="${STRESS_SCRIPT:-/tmp/stress.sh}"
TEST="${1:-all}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║   DashDiag Stress Suite Runner               ║"
echo "║   Physical mode: --physical flag enabled     ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# Verify binary
if [ ! -x "$DSD_BIN" ]; then
    echo -e "${RED}ERROR: dsd binary not found at $DSD_BIN${RESET}"
    echo "Copy binary first: scp dist/dsd-linux-amd64 user@host:/tmp/dsd"
    exit 1
fi

# Verify stress script
if [ ! -f "$STRESS" ]; then
    echo -e "${RED}ERROR: stress script not found at $STRESS${RESET}"
    echo "Copy script first: scp scripts/stress/stress.sh user@host:/tmp/stress.sh"
    exit 1
fi

echo -e "${CYAN}[INFO]${RESET} Binary:  $DSD_BIN ($("$DSD_BIN" --version 2>/dev/null || echo unknown))"
echo -e "${CYAN}[INFO]${RESET} Script:  $STRESS"
echo -e "${CYAN}[INFO]${RESET} Test:    $TEST"
echo -e "${CYAN}[INFO]${RESET} Mode:    --physical (NIC/DNS/gateway tests enabled)"
echo ""

# Must run as root for physical tests
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: must run as root for physical tests${RESET}"
    echo "Run: sudo bash /tmp/run_stress.sh $TEST"
    exit 1
fi

chmod +x "$STRESS"
chmod +x "$DSD_BIN"
DSD_BIN="$DSD_BIN" bash "$STRESS" --physical "$TEST"
