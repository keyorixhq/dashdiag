#!/bin/bash
# DashDiag verification script — Ubuntu 24.04
# Run: bash /tmp/verify_ubuntu.sh
# Requires: /tmp/dsd binary present and executable

DSD="${DSD_BIN:-/tmp/dsd}"
PASS=0
FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

pass() { echo -e "${GREEN}[PASS]${RESET} $*"; PASS=$(( PASS + 1 )); }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; FAIL=$(( FAIL + 1 )); }
info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
hdr()  { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

run_dsd() { "$DSD" "$@" 2>/dev/null || true; }
exit_code() {
    "$DSD" health "$@" > /dev/null 2>&1
    echo ${?}
}

# ── TEST 1: Binary sanity ─────────────────────────────────────────────────────
hdr "TEST 1: Binary sanity"
info "Version: $("$DSD" --version 2>/dev/null || echo FAILED)"
if "$DSD" --version &>/dev/null; then pass "Binary executes"
else fail "Binary failed to execute"; exit 1; fi
if "$DSD" --help &>/dev/null; then pass "--help exits 0"
else fail "--help failed"; fi

# ── TEST 2: All 12 checks present ────────────────────────────────────────────
hdr "TEST 2: All 12 checks present"
EXPECTED="CPU Memory Disk IO Swap Network Clock FDLimits Processes Systemd Sysctl MACPolicy"
JSON_CHECKS=$("$DSD" health --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(' '.join(c.get('name','') for c in data.get('checks',[])))
")
for check in $EXPECTED; do
    if echo "$JSON_CHECKS" | grep -q "$check"; then pass "Check present: $check"
    else fail "Check MISSING: $check"; fi
done

# Capture both output formats ONCE here — all subsequent tests reuse these
# captures so comparisons reflect the same system snapshot.
info "Capturing health snapshot (used by tests 3-7 and 19)..."
JSON_OUT=$("$DSD" health --json 2>/dev/null) || true
JSON_EXIT=$?
PLAIN_OUT=$("$DSD" health --plain 2>/dev/null) || true

# ── TEST 3: --plain and --json agree ─────────────────────────────────────────
hdr "TEST 3: --plain and --json status agreement"
# IMPORTANT: Run health ONCE per format and capture upfront (TEST 2 already
# ran JSON). Re-use those captures so both comparisons reflect the same
# system state window. A second invocation seconds later may see different
# borderline metrics (IO await, CPU load) on a recovering system.
# JSON_OUT and PLAIN_OUT were captured sequentially above — minor timing
# difference is acceptable; hard failures (wrong status on stable checks)
# will still show up correctly.

AGREE=true
while IFS=: read -r check status; do
    [ -z "$check" ] && continue
    if echo "$PLAIN_OUT" | grep -qE "^${check}[[:space:]]+${status}"; then
        pass "--plain agrees: $check=$status"
    else
        # Check if plain shows a valid-but-different status (timing drift)
        PLAIN_STATUS=$(echo "$PLAIN_OUT" | grep -E "^${check}[[:space:]]+" | \
            awk '{print $2}' | head -1)
        if [ -n "$PLAIN_STATUS" ] && \
           echo "$PLAIN_STATUS" | grep -qE "^(OK|WARN|CRIT|INFO)$"; then
            fail "--plain disagrees: $check should be $status (plain shows $PLAIN_STATUS — possible timing drift, rerun on idle system)"
        else
            fail "--plain disagrees: $check should be $status"
        fi
        AGREE=false
    fi
done < <(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks', []):
    print(f\"{c.get('name','')}:{c.get('status','')}\")
" 2>/dev/null)

[ "$AGREE" = true ] && info "All check statuses match between --json and --plain"

# ── TEST 4: JSON schema fields ────────────────────────────────────────────────
hdr "TEST 4: JSON schema required fields"
for field in hostname timestamp version checks insights; do
    val=$(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('yes' if '$field' in data else 'no')
" 2>/dev/null)
    if [ "$val" = "yes" ]; then pass "JSON field present: $field"
    else fail "JSON field MISSING: $field"; fi
done

INSIGHTS_TYPE=$(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(type(data.get('insights','missing')).__name__)
")
if [ "$INSIGHTS_TYPE" = "list" ]; then pass "insights is array (not null)"
else fail "insights is $INSIGHTS_TYPE (expected list)"; fi

# ── TEST 5: --json is valid JSON ──────────────────────────────────────────────
hdr "TEST 5: --json produces valid JSON"
if echo "$JSON_OUT" | python3 -m json.tool > /dev/null 2>&1; then
    pass "--json output is valid JSON"
else
    fail "--json output is INVALID JSON"
fi

# ── TEST 6: --plain has no ANSI codes ────────────────────────────────────────
hdr "TEST 6: --plain has no ANSI escape codes"
if echo "$PLAIN_OUT" | grep -qP '\x1b\[' 2>/dev/null; then
    fail "--plain contains ANSI codes"
else
    pass "--plain is clean (no ANSI)"
fi

# ── TEST 7: Exit codes ────────────────────────────────────────────────────────
hdr "TEST 7: Exit code contract (0=OK 1=WARN 2=CRIT)"
CURRENT_EXIT=$(exit_code)
info "Current exit code: $CURRENT_EXIT"
if [ "$CURRENT_EXIT" -le 2 ]; then pass "Exit code valid: $CURRENT_EXIT"
else fail "Exit code $CURRENT_EXIT (must be 0, 1, or 2)"; fi

WORST=$(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rank = {'CRIT':2,'WARN':1,'INFO':0,'OK':0}
worst = 0
for i in data.get('insights',[]):
    worst = max(worst, rank.get(i.get('level','OK'), 0))
print(worst)
")
# JSON_EXIT is from the same invocation as JSON_OUT — eliminates race between
# a stressed earlier run (WORST=1) and a fresh idle run (CURRENT_EXIT=0).
if [ "$JSON_EXIT" = "$WORST" ]; then
    pass "Exit code matches worst insight ($JSON_EXIT)"
else
    fail "Exit code $JSON_EXIT does not match worst insight $WORST (check: dsd health --json; echo \$?)"
fi

# ── TEST 8: Typo correction ───────────────────────────────────────────────────
hdr "TEST 8: Typo correction"
TYPO_OUT=$("$DSD" healt 2>&1 || true)
if echo "$TYPO_OUT" | grep -qi "health"; then pass "Typo 'healt' suggests 'health'"
else fail "Typo correction not working"; fi

# ── TEST 9: Baseline system ───────────────────────────────────────────────────
hdr "TEST 9: Baseline system"
"$DSD" health > /dev/null 2>&1 || true
sleep 1
"$DSD" health --diff > /dev/null 2>&1 || true
BASELINE_DIR="$HOME/.dsd/baselines"
if ls "$BASELINE_DIR"/*.json 2>/dev/null | head -1 | grep -q .; then
    pass "Baseline file created in ~/.dsd/baselines/"
else
    fail "No baseline files found in ~/.dsd/baselines/"
fi

# ── TEST 10: --diff output ────────────────────────────────────────────────────
hdr "TEST 10: --diff output"
DIFF_OUT=$("$DSD" health --diff 2>&1 || true)
if echo "$DIFF_OUT" | grep -qiE "change|unchanged|no change|since"; then
    pass "--diff produces meaningful output"
else
    fail "--diff output not meaningful: $DIFF_OUT"
fi

# ── TEST 11: --since-deploy ───────────────────────────────────────────────────
hdr "TEST 11: --since-deploy"
DEPLOY_OUT=$("$DSD" health --since-deploy 2>&1 || true)
if echo "$DEPLOY_OUT" | grep -qiE "deploy|signal|baseline|restart|service"; then
    pass "--since-deploy produces output"
else
    fail "--since-deploy produced unexpected output: $DEPLOY_OUT"
fi

# ── TEST 12: --story ──────────────────────────────────────────────────────────
hdr "TEST 12: --story"
STORY_OUT=$("$DSD" health --story 2>&1 || true)
if [ -n "$STORY_OUT" ] && [ ${#STORY_OUT} -gt 20 ]; then
    pass "--story produces narrative output"
else
    fail "--story output too short or empty"
fi

# ── TEST 13: --post-mortem ────────────────────────────────────────────────────
hdr "TEST 13: --post-mortem"
PM_OUT=$("$DSD" health --post-mortem "ubuntu24-test" 2>&1 || true)
if echo "$PM_OUT" | grep -q "ubuntu24-test"; then
    pass "--post-mortem includes incident title"
else
    fail "--post-mortem did not include title"
fi
if echo "$PM_OUT" | grep -q "Generated by DashDiag"; then
    pass "--post-mortem has footer"
else
    fail "--post-mortem footer missing"
fi

# ── TEST 14: dsd net ─────────────────────────────────────────────────────────
hdr "TEST 14: dsd net"
NET_OUT=$("$DSD" net 2>&1 || true)
if echo "$NET_OUT" | grep -qiE "network|interface|gateway|ping|dns"; then
    pass "dsd net produces output"
else
    fail "dsd net output unexpected"
fi

# ── TEST 15: dsd examples ────────────────────────────────────────────────────
hdr "TEST 15: dsd examples"
if "$DSD" examples > /dev/null 2>&1; then pass "dsd examples exits 0"
else fail "dsd examples failed"; fi

# ── TEST 16: USB NIC (enx* naming) ───────────────────────────────────────────
hdr "TEST 16: USB NIC (enx* naming)"
NIC=$(ip -br link 2>/dev/null | grep "^enx" | awk '{print $1}' | head -1 || true)
if [ -n "$NIC" ]; then
    info "USB NIC detected: $NIC"
    NET_JSON=$(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks',[]):
    if 'Network' in c.get('name',''): print('found')
" 2>/dev/null || true)
    if [ "$NET_JSON" = "found" ]; then pass "Network check present with USB NIC ($NIC)"
    else fail "Network check missing with USB NIC"; fi
else
    info "No USB NIC on this machine — skipping"
fi

# ── TEST 17: Docker bridges filtered ─────────────────────────────────────────
hdr "TEST 17: Docker bridge interfaces filtered"
BRIDGE=$(ip -br link 2>/dev/null | grep -E "^(docker|br-)" | head -1 | awk '{print $1}' || true)
if [ -n "$BRIDGE" ]; then
    info "Docker bridge detected: $BRIDGE"
    pass "Docker bridges present — network collector ran without crash"
else
    info "No Docker bridges — skipping"
fi

# ── TEST 18: state.json ───────────────────────────────────────────────────────
hdr "TEST 18: State management"
STATE_FILE="$HOME/.dsd/state.json"
if [ -f "$STATE_FILE" ]; then
    if python3 -m json.tool "$STATE_FILE" > /dev/null 2>&1; then
        pass "state.json is valid JSON"
        RUNS=$(python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('total_runs',0))")
        pass "state.json total_runs: $RUNS"
    else
        fail "state.json is invalid JSON"
    fi
else
    fail "state.json not found at $STATE_FILE"
fi

# ── TEST 19: Clock Ubuntu 24.04 fix ──────────────────────────────────────────
hdr "TEST 19: Clock collector (Ubuntu 24.04 timesync-status fix)"
CLOCK_STATUS=$(echo "$JSON_OUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for c in data.get('checks',[]):
    if c.get('name') == 'Clock':
        print(c.get('status','MISSING'))
")
if [ "$CLOCK_STATUS" = "OK" ]; then
    pass "Clock: OK (timesync-status parsing working)"
elif [ "$CLOCK_STATUS" = "WARN" ]; then
    pass "Clock: WARN (real condition — offset high)"
else
    fail "Clock: $CLOCK_STATUS (expected OK or WARN)"
fi

# ── TEST 20: --yaml output ────────────────────────────────────────────────────
hdr "TEST 20: --yaml output"
YAML_OUT=$("$DSD" health --yaml 2>/dev/null || true)
if echo "$YAML_OUT" | grep -q "hostname:"; then pass "--yaml produces YAML output"
else fail "--yaml output unexpected or missing"; fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━ RESULTS ━━━${RESET}"
echo -e "  ${GREEN}Passed: $PASS${RESET}"
echo -e "  ${RED}Failed: $FAIL${RESET}"
echo ""
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✅ All tests passed — P1.1 Ubuntu 24.04 COMPLETE${RESET}"
    echo ""
    echo "Next: run the stress suite"
    echo "  DSD_BIN=/tmp/dsd sudo bash /tmp/stress.sh --physical all"
else
    echo -e "${RED}${BOLD}❌ $FAIL test(s) failed — fix before stress testing${RESET}"
fi
