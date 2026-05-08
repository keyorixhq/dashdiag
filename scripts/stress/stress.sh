#!/bin/bash
# DashDiag Stress Test Suite
#
# Default mode: SSH-safe — no test will disconnect you from a remote machine.
# Physical mode: --physical — enables destructive network tests (NIC down,
#                gateway blackhole, DNS corruption). Only use with physical
#                access or an out-of-band console (IPMI, iDRAC, Proxmox console).
#
# USAGE:
#   DSD_BIN=/tmp/dsd-linux-amd64 sudo bash stress.sh [--physical] [test]
#
# TESTS (always available):
#   all           run all SSH-safe tests
#   memory        allocate 85% RAM
#   cpu           saturate all cores
#   io            disk write saturation
#   swap          force paging into swap
#   zombie        create zombie processes
#   fd            file descriptor exhaustion
#   disk          fill filesystem to 83%
#   systemd       create a failing systemd unit
#   clock         NTP check (read-only)
#   net_closewait 150 CLOSE_WAIT connections (localhost only)
#   net_latency   500ms artificial latency via tc netem
#   net_loss      50% packet loss via tc netem
#   sysctl        lower somaxconn below threshold
#
# TESTS (--physical only — will disconnect SSH):
#   net_down      take NIC fully down for 15s
#   net_dns       corrupt /etc/resolv.conf for 15s
#   net_gateway   delete default gateway for 15s
#
# EXAMPLES:
#   sudo bash stress.sh all
#   sudo bash stress.sh --physical all
#   sudo bash stress.sh zombie
#   sudo bash stress.sh --physical net_down
#   sudo bash stress.sh --physical net_gateway

set -euo pipefail

# ── Parse --physical flag ─────────────────────────────────────────────────────
PHYSICAL=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --physical) PHYSICAL=true ;;
        *)          ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]:-}"

DSD="${DSD_BIN:-/tmp/dsd}"
LOG="/tmp/dsd_stress_results.txt"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

CLEANUP_PIDS=()
CLEANUP_FILES=()
CLEANUP_SERVICES=()
CLEANUP_TC_IFACE=""
CLEANUP_RESOLV_BACKUP=""
CLEANUP_GATEWAY_RESTORE=""

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
pass()  { echo -e "${GREEN}[PASS]${RESET}  $*"; (( PASS_COUNT++ )) || true; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; (( FAIL_COUNT++ )) || true; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
skip()  { echo -e "${DIM}[SKIP]${RESET}  $* (requires --physical)"; (( SKIP_COUNT++ )) || true; }
hdr()   { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

# ── Network helpers ───────────────────────────────────────────────────────────
get_primary_iface() {
    ip route show default 2>/dev/null | awk '/default/{print $5}' | head -1
}

get_default_gateway() {
    ip route show default 2>/dev/null | awk '/default/{print $3}' | head -1
}

# ── Guard for physical-only tests ─────────────────────────────────────────────
require_physical() {
    local test_name="$1"
    if [ "$PHYSICAL" = false ]; then
        skip "$test_name — run with --physical to enable (will disconnect SSH)"
        return 1
    fi
    warn "PHYSICAL MODE: $test_name — network will be disrupted"
    warn "You need physical or out-of-band console access to recover if something goes wrong"
    return 0
}

# ── Global cleanup ────────────────────────────────────────────────────────────
cleanup_all() {
    echo -e "\n${YELLOW}→ Restoring system state...${RESET}"

    for pid in "${CLEANUP_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Give processes a moment to die gracefully then force kill
    sleep 2
    for pid in "${CLEANUP_PIDS[@]:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done

    # Wait for all background jobs to fully exit
    wait 2>/dev/null || true

    for f in "${CLEANUP_FILES[@]:-}"; do
        rm -f "$f" 2>/dev/null || true
    done
    rm -rf /tmp/dsd_disk_test /tmp/dsd_fd_test 2>/dev/null || true

    for svc in "${CLEANUP_SERVICES[@]:-}"; do
        [ -z "$svc" ] && continue
        systemctl stop    "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/$svc"
        systemctl daemon-reload 2>/dev/null || true
        info "Removed $svc"
    done

    if [ -n "$CLEANUP_TC_IFACE" ]; then
        tc qdisc del dev "$CLEANUP_TC_IFACE" root 2>/dev/null && \
            info "tc rules removed from $CLEANUP_TC_IFACE" || true
        CLEANUP_TC_IFACE=""
    fi

    if [ -n "$CLEANUP_RESOLV_BACKUP" ] && [ -f "$CLEANUP_RESOLV_BACKUP" ]; then
        cp "$CLEANUP_RESOLV_BACKUP" /etc/resolv.conf
        rm -f "$CLEANUP_RESOLV_BACKUP"
        info "resolv.conf restored"
        CLEANUP_RESOLV_BACKUP=""
    fi

    if [ -n "$CLEANUP_GATEWAY_RESTORE" ]; then
        eval "$CLEANUP_GATEWAY_RESTORE" 2>/dev/null && \
            info "Default gateway restored" || true
        CLEANUP_GATEWAY_RESTORE=""
    fi

    # Bring interface back up if it was taken down
    local iface; iface=$(get_primary_iface || true)
    if [ -n "${iface:-}" ]; then
        ip link set "$iface" up 2>/dev/null || true
    fi

    echo -e "\n${BOLD}━━━ RESULTS ━━━${RESET}"
    echo -e "  ${GREEN}Passed:${RESET}  $PASS_COUNT"
    echo -e "  ${RED}Failed:${RESET}  $FAIL_COUNT"
    echo -e "  ${DIM}Skipped:${RESET} $SKIP_COUNT"
    echo -e "  Log: $LOG"
    echo ""
}
trap cleanup_all EXIT INT TERM

# ── Health helpers ────────────────────────────────────────────────────────────
get_check_status() {
    local name="$1"
    local json
    json=$("$DSD" health --json 2>/dev/null) || true
    echo "$json" | python3 -c "
import sys, json as j
data = j.load(sys.stdin)
for c in data.get('checks', []):
    if '$name' in c.get('name', ''):
        print(c.get('status', 'UNKNOWN'))
        sys.exit(0)
print('NOT_FOUND')
" 2>/dev/null || echo "ERROR"
}

assert_status() {
    local label="$1" check="$2" expected="$3"
    local actual; actual=$(get_check_status "$check")
    if [ "$expected" = "WARN_OR_CRIT" ]; then
        if [ "$actual" = "WARN" ] || [ "$actual" = "CRIT" ]; then
            pass "$label — $check=$actual ✓"
        else
            fail "$label — $check=$actual (expected WARN or CRIT)"
        fi
    elif [ "$actual" = "$expected" ]; then
        pass "$label — $check=$actual ✓"
    else
        fail "$label — $check=$actual (expected $expected)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# SSH-SAFE TESTS
# ─────────────────────────────────────────────────────────────────────────────

test_baseline() {
    hdr "BASELINE — system at rest"
    if [ ! -x "$DSD" ]; then
        fail "Binary not found: $DSD"
        echo "  Set DSD_BIN=/path/to/binary"
        exit 1
    fi
    info "Version: $("$DSD" --version 2>/dev/null || echo unknown)"
    if [ "$PHYSICAL" = true ]; then
        warn "Running in PHYSICAL MODE — destructive network tests enabled"
    else
        info "Running in SSH-SAFE MODE — use --physical to enable NIC/gateway/DNS tests"
    fi
    echo ""
    "$DSD" health --plain 2>/dev/null || true
    echo ""
}

test_memory() {
    hdr "TEST: Memory pressure (85% RAM)"
    local total alloc
    total=$(free -m | awk '/^Mem:/{print $2}')
    alloc=$(( total * 85 / 100 ))
    info "Allocating ${alloc}MB of ${total}MB total"
    python3 -c "
import time
data = bytearray($alloc * 1024 * 1024)
for i in range(0, len(data), 4096): data[i] = 1
print('Allocated. Holding 30s...', flush=True)
time.sleep(30)
" &
    CLEANUP_PIDS+=($!)
    sleep 5
    info "RAM: $(free -h | awk '/^Mem:/{print $3 "/" $2}')"
    assert_status "85% RAM triggers WARN" "Memory" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
    sleep 2
}

test_cpu() {
    hdr "TEST: CPU saturation"
    local cores=$(nproc)
    info "Spawning $((cores + 2)) spinners on $cores cores"
    for i in $(seq 1 $((cores + 2))); do
        python3 -c "
while True: _ = sum(range(100000))
" &
        CLEANUP_PIDS+=($!)
    done
    info "Waiting 30s for load average to rise (1-min rolling avg)..."
    sleep 30
    info "Load: $(cat /proc/loadavg)"
    assert_status "Load > cores*0.7" "CPU" "WARN_OR_CRIT"
}

test_io() {
    hdr "TEST: IO saturation"
    local dev; dev=$(lsblk -dno NAME,TYPE | awk '$2=="disk"{print $1}' | head -1)
    [ -z "$dev" ] && { warn "No disk found — skipping"; return; }
    info "Stressing /dev/$dev"
    mkdir -p /tmp/dsd_disk_test
    (while true; do
        dd if=/dev/urandom of=/tmp/dsd_disk_test/s bs=1M count=256 oflag=direct 2>/dev/null
        rm -f /tmp/dsd_disk_test/s
    done) &
    CLEANUP_PIDS+=($!)
    sleep 8
    assert_status "IO utilization" "IO" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
    rm -rf /tmp/dsd_disk_test
}

test_swap() {
    hdr "TEST: Swap pressure"
    swapon --show 2>/dev/null | grep -q . || {
        warn "No swap — skipping"
        info "Enable: fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
        return
    }
    local total=$(free -m | awk '/^Mem:/{print $2}')
    local swap=$(free -m | awk '/^Swap:/{print $2}')
    local alloc=$(( total + swap / 3 ))
    info "Allocating ${alloc}MB to force paging"
    python3 -c "
import time
data, n = [], 0
while n < $alloc:
    try:
        b = bytearray(50*1024*1024)
        for i in range(0, len(b), 4096): b[i] = 1
        data.append(b); n += 50
    except MemoryError: break
print(f'Holding {n}MB for 20s', flush=True); time.sleep(20)
" &
    CLEANUP_PIDS+=($!)
    sleep 10
    vmstat 1 3 2>/dev/null || true
    assert_status "Swap paging" "Swap" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
}

test_zombie() {
    hdr "TEST: Zombie processes"
    info "Creating 8 zombie processes"
    python3 << 'PYEOF' &
import os, time
for i in range(8):
    if os.fork() == 0: os._exit(0)
print("8 zombies — parent not reaping", flush=True)
time.sleep(30)
PYEOF
    CLEANUP_PIDS+=($!)
    sleep 3
    info "Zombie count: $(ps aux | awk '$8=="Z"' | wc -l)"
    assert_status "Zombie detection" "Processes" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
    sleep 2
}

test_fd() {
    hdr "TEST: File descriptor exhaustion"
    local limit=$(ulimit -n)
    local target=$(( limit * 85 / 100 ))
    info "Opening $target / $limit FDs"
    mkdir -p /tmp/dsd_fd_test
    python3 << PYEOF &
import time
fds = []
for i in range($target):
    try: fds.append(open(f'/tmp/dsd_fd_test/f{i}', 'w'))
    except OSError: break
print(f'Opened {len(fds)} FDs', flush=True)
time.sleep(20)
for f in fds: f.close()
PYEOF
    CLEANUP_PIDS+=($!)
    sleep 3
    info "System FD usage: $(cat /proc/sys/fs/file-nr)"
    assert_status "FD exhaustion" "FDLimits" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
    rm -rf /tmp/dsd_fd_test
}

test_disk() {
    hdr "TEST: Disk space (fill to 83%)"
    local pct=$(df / | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    local total=$(df -m / | awk 'NR==2{print $2}')
    local avail=$(df -m / | awk 'NR==2{print $4}')
    info "Currently ${pct}% used, ${avail}MB free"
    if [ "$pct" -ge 82 ]; then
        assert_status "Already at ${pct}%" "Disk" "WARN_OR_CRIT"; return
    fi
    local fill=$(( (total * 83 / 100) - (total - avail) ))
    [ "$fill" -lt 50 ] && { warn "Not enough space — skipping"; return; }
    local f="/tmp/dsd_fill_$$"; CLEANUP_FILES+=("$f")
    info "Writing ${fill}MB fill file..."
    dd if=/dev/zero of="$f" bs=1M count="$fill" 2>/dev/null; sync
    info "Disk now: $(df -h / | awk 'NR==2{print $5}')"
    assert_status "Disk > 80%" "Disk" "WARN_OR_CRIT"
    rm -f "$f"; sync
}

test_systemd() {
    hdr "TEST: Systemd failed unit"
    command -v systemctl &>/dev/null || { warn "No systemd — skipping"; return; }
    [ "$(id -u)" -eq 0 ]    || { warn "Needs root — skipping"; return; }
    local svc="dsd-stress-test.service"
    cat > "/etc/systemd/system/$svc" << 'EOF'
[Unit]
Description=DashDiag stress test — deliberately fails
[Service]
Type=oneshot
ExecStart=/bin/false
EOF
    CLEANUP_SERVICES+=("$svc")
    systemctl daemon-reload
    systemctl start "$svc" 2>/dev/null || true
    sleep 2
    info "State: $(systemctl is-failed $svc 2>/dev/null || echo unknown)"
    assert_status "Failed unit detected" "Systemd" "CRIT"
    systemctl reset-failed "$svc" 2>/dev/null || true
}

test_clock() {
    hdr "TEST: NTP clock (read-only)"
    local s; s=$(get_check_status "Clock")
    case "$s" in
        OK)   pass "Clock synced — collector OK" ;;
        WARN) warn "Clock WARN — real offset detected" ;;
        CRIT) fail "Clock CRIT — NTP not synced" ;;
        *)    fail "Clock returned: $s" ;;
    esac
}

test_net_closewait() {
    hdr "TEST: Network — CLOSE_WAIT buildup (localhost)"
    info "Creating 150 half-closed connections"
    python3 << 'PYEOF' &
import socket, threading, time
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 19877)); srv.listen(200)
def accept():
    while True:
        try: conn, _ = srv.accept(); conn.close()
        except: break
threading.Thread(target=accept, daemon=True).start()
time.sleep(0.3)
clients = []
for i in range(150):
    try: c = socket.socket(); c.connect(('127.0.0.1', 19877)); clients.append(c)
    except: pass
print(f'Created {len(clients)} CLOSE_WAIT connections', flush=True)
time.sleep(20)
PYEOF
    CLEANUP_PIDS+=($!)
    sleep 5
    info "CLOSE_WAIT: $(ss -tan state close-wait 2>/dev/null | grep -c 19877 || echo 0)"
    assert_status "CLOSE_WAIT buildup" "Network" "WARN_OR_CRIT"
    kill "${CLEANUP_PIDS[-1]}" 2>/dev/null || true
}

test_net_latency() {
    hdr "TEST: Network — artificial latency (tc netem)"
    command -v tc &>/dev/null || { warn "tc not installed (apt install iproute2) — skipping"; return; }
    [ "$(id -u)" -eq 0 ]    || { warn "Needs root — skipping"; return; }
    local iface; iface=$(get_primary_iface)
    [ -z "$iface" ] && { warn "No primary interface — skipping"; return; }
    info "Adding 500ms latency + 50ms jitter to $iface"
    tc qdisc add dev "$iface" root netem delay 500ms 50ms
    CLEANUP_TC_IFACE="$iface"
    info "Ping test:"
    ping -c 3 8.8.8.8 2>/dev/null || true
    assert_status "High latency detected" "Network" "WARN_OR_CRIT"
    tc qdisc del dev "$iface" root 2>/dev/null || true
    CLEANUP_TC_IFACE=""
    info "Latency removed"
}

test_net_loss() {
    hdr "TEST: Network — 50% packet loss (tc netem)"
    command -v tc &>/dev/null || { warn "tc not installed — skipping"; return; }
    [ "$(id -u)" -eq 0 ]    || { warn "Needs root — skipping"; return; }
    local iface; iface=$(get_primary_iface)
    [ -z "$iface" ] && { warn "No primary interface — skipping"; return; }
    info "Adding 50% packet loss to $iface"
    tc qdisc add dev "$iface" root netem loss 50%
    CLEANUP_TC_IFACE="$iface"
    info "Ping test (expect ~50% loss):"
    ping -c 10 8.8.8.8 2>/dev/null | tail -2 || true
    assert_status "Packet loss detected" "Network" "WARN_OR_CRIT"
    tc qdisc del dev "$iface" root 2>/dev/null || true
    CLEANUP_TC_IFACE=""
    info "Packet loss removed"
}

test_sysctl() {
    hdr "TEST: Sysctl — somaxconn below threshold"
    [ "$(id -u)" -eq 0 ] || { warn "Needs root — skipping"; return; }
    local orig; orig=$(cat /proc/sys/net/core/somaxconn)
    info "somaxconn: $orig → 256 (WARN < 1024, CRIT < 512)"
    echo 256 > /proc/sys/net/core/somaxconn
    assert_status "Low somaxconn" "Sysctl" "WARN_OR_CRIT"
    echo "$orig" > /proc/sys/net/core/somaxconn
    info "Restored somaxconn to $orig"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHYSICAL-ONLY TESTS — will disconnect SSH
# ─────────────────────────────────────────────────────────────────────────────

test_net_down() {
    require_physical "net_down (NIC takedown)" || return 0
    hdr "TEST: Network — full interface takedown [PHYSICAL]"
    [ "$(id -u)" -eq 0 ] || { warn "Needs root — skipping"; return; }
    local iface; iface=$(get_primary_iface)
    [ -z "$iface" ] && { warn "No primary interface — skipping"; return; }
    info "Taking $iface DOWN for 15 seconds..."
    ip link set "$iface" down
    sleep 2
    info "Interface state: $(ip link show "$iface" | grep -o 'state [A-Z]*')"
    assert_status "Interface down" "Network" "WARN_OR_CRIT"
    info "Bringing $iface back UP..."
    ip link set "$iface" up
    sleep 3
    # Re-acquire DHCP lease
    if   command -v dhclient &>/dev/null; then dhclient "$iface" 2>/dev/null & sleep 4
    elif command -v dhcpcd   &>/dev/null; then dhcpcd   "$iface" 2>/dev/null & sleep 4
    fi
    info "Interface restored: $(ip link show "$iface" | grep -o 'state [A-Z]*')"
}

test_net_dns() {
    require_physical "net_dns (resolv.conf corruption)" || return 0
    hdr "TEST: Network — DNS failure [PHYSICAL]"
    [ "$(id -u)" -eq 0 ] || { warn "Needs root — skipping"; return; }
    local backup="/tmp/resolv.conf.dsd.$$"
    cp /etc/resolv.conf "$backup"
    CLEANUP_RESOLV_BACKUP="$backup"
    info "Replacing resolv.conf with RFC 5737 test IP (192.0.2.1 — guaranteed unreachable)"
    echo "nameserver 192.0.2.1" > /etc/resolv.conf
    info "DNS will time out — running dsd health..."
    assert_status "DNS failure" "Network" "WARN_OR_CRIT"
    cp "$backup" /etc/resolv.conf
    rm -f "$backup"; CLEANUP_RESOLV_BACKUP=""
    info "resolv.conf restored"
}

test_net_gateway() {
    require_physical "net_gateway (gateway blackhole)" || return 0
    hdr "TEST: Network — default gateway blackhole [PHYSICAL]"
    [ "$(id -u)" -eq 0 ] || { warn "Needs root — skipping"; return; }
    local gw iface
    gw=$(get_default_gateway)
    iface=$(get_primary_iface)
    [ -z "$gw" ] && { warn "No default gateway — skipping"; return; }
    info "Gateway: $gw via $iface — deleting default route for 15s"
    CLEANUP_GATEWAY_RESTORE="ip route add default via $gw dev $iface"
    ip route del default 2>/dev/null || true
    sleep 2
    info "Routes: $(ip route show 2>/dev/null || echo none)"
    assert_status "Gateway unreachable" "Network" "WARN_OR_CRIT"
    info "Restoring default route via $gw..."
    ip route add default via "$gw" dev "$iface" 2>/dev/null || true
    CLEANUP_GATEWAY_RESTORE=""
    sleep 2
    info "Connectivity: $(ping -c 1 -W 2 8.8.8.8 2>/dev/null | grep -o '[0-9]* received' || echo checking)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
show_report() {
    hdr "FINAL HEALTH SNAPSHOT (post-cleanup)"
    sleep 3
    "$DSD" health --plain 2>/dev/null || true
}

SSH_SAFE_TESTS=(
    test_memory test_cpu test_io test_swap test_zombie
    test_fd test_disk test_systemd test_clock
    test_net_closewait test_net_latency test_net_loss test_sysctl
)

PHYSICAL_TESTS=(
    test_net_down test_net_dns test_net_gateway
)

main() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   DashDiag Stress Test Suite                         ║"
    if [ "$PHYSICAL" = true ]; then
    echo "║   Mode: PHYSICAL — destructive network tests enabled  ║"
    else
    echo "║   Mode: SSH-SAFE  — use --physical for NIC/DNS/GW     ║"
    fi
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    [ -x "$DSD" ] || { fail "Binary not found: $DSD"; exit 1; }

    local t="${1:-all}"

    case "$t" in
        all)
            test_baseline
            for fn in "${SSH_SAFE_TESTS[@]}"; do $fn; done
            if [ "$PHYSICAL" = true ]; then
                for fn in "${PHYSICAL_TESTS[@]}"; do $fn; done
            fi
            show_report
            ;;
        # Individual SSH-safe tests
        memory)        test_baseline; test_memory ;;
        cpu)           test_baseline; test_cpu ;;
        io)            test_baseline; test_io ;;
        swap)          test_baseline; test_swap ;;
        zombie)        test_baseline; test_zombie ;;
        fd)            test_baseline; test_fd ;;
        disk)          test_baseline; test_disk ;;
        systemd)       test_baseline; test_systemd ;;
        clock)         test_baseline; test_clock ;;
        net_closewait) test_baseline; test_net_closewait ;;
        net_latency)   test_baseline; test_net_latency ;;
        net_loss)      test_baseline; test_net_loss ;;
        sysctl)        test_baseline; test_sysctl ;;
        # Physical-only tests
        net_down)      test_baseline; test_net_down ;;
        net_dns)       test_baseline; test_net_dns ;;
        net_gateway)   test_baseline; test_net_gateway ;;
        help|--help|-h)
            echo "Usage: [DSD_BIN=/path] sudo bash stress.sh [--physical] [test]"
            echo ""
            echo "SSH-SAFE tests (default mode):"
            echo "  all net_closewait net_latency net_loss"
            echo "  memory cpu io swap zombie fd disk systemd clock sysctl"
            echo ""
            echo "PHYSICAL tests (--physical flag required):"
            echo "  net_down    take NIC fully down then restore"
            echo "  net_dns     corrupt resolv.conf then restore"
            echo "  net_gateway blackhole default route then restore"
            exit 0
            ;;
        *)
            fail "Unknown test: $t"
            echo "Run with 'help' to see all tests"
            exit 1
            ;;
    esac
}

main "${1:-all}" 2>&1 | tee "$LOG"
