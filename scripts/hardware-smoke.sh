#!/usr/bin/env bash
# scripts/hardware-smoke.sh — pre-release HARDWARE smoke test on a real machine.
#
# Unlike scripts/smoke-test.sh (which checks dsd *runs* — exit codes, valid JSON
# — and can run anywhere), this asserts the hardware-collector OUTPUTS are SANE
# on genuine hardware: SMART wear% in range, temps plausible, battery% in range,
# SMART health present. These paths return absent/virtual data in containers and
# CI, so they can only be validated on a real node. This is the test that would
# have caught the 3491877946276% wear-garbage (#J): it exits 0 and is valid JSON
# — only a range check flags it.
#
# Runs over SSH against the bare-metal testbed (PLATFORM_COVERAGE row 19) — pve01,
# the always-on HP ProDesk (i7-6700, real SATA SMART + coretemp). The old default
# (.7) pointed at a host that no longer exists, so the smoke test silently
# "couldn't reach the testbed" and got skipped at release time; pve01 is reachable
# from the dev Mac on the LAN.
# Override host: HW_HOST=root@192.168.10.x bash scripts/hardware-smoke.sh
# Build+push a fresh binary first with: PUSH=1 bash scripts/hardware-smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

HW_HOST="${HW_HOST:-root@192.168.10.20}"
REMOTE_BIN="${REMOTE_BIN:-/usr/local/bin/dsd}"
PASS=0; FAIL=0; SKIP=0

# Ensure the agent socket is available (matches the repo's SSH convention).
if [ -z "${SSH_AUTH_SOCK:-}" ]; then
  SSH_AUTH_SOCK="$(launchctl getenv SSH_AUTH_SOCK 2>/dev/null || true)"
  export SSH_AUTH_SOCK
fi

ssh_run() { ssh -o ConnectTimeout=10 -o BatchMode=yes "$HW_HOST" "$@"; }

# pass/fail/skip helpers. ok = assertion held; bad = regression; skip = surface
# not present on this hardware (e.g. no battery) — NOT a failure, but reported so
# absence is never silently read as success (the project's false-OK rule).
ok()   { echo "✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "❌ $1"; FAIL=$((FAIL+1)); }
skip() { echo "⏭️  $1 (not present on this host)"; SKIP=$((SKIP+1)); }

# num_in_range NAME VALUE MIN MAX — assert VALUE is numeric and within [MIN,MAX].
# Empty/non-numeric is a FAIL, not a skip: "couldn't measure" must not pass.
num_in_range() {
  local name=$1 val=$2 min=$3 max=$4
  if ! [[ "$val" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
    bad "$name: non-numeric or empty ('$val') — couldn't-measure must not read as OK"
    return
  fi
  if awk -v v="$val" -v lo="$min" -v hi="$max" 'BEGIN{exit !(v>=lo && v<=hi)}'; then
    ok "$name = $val (in [$min,$max])"
  else
    bad "$name = $val OUT OF RANGE [$min,$max]  ← garbage-value regression"
  fi
}

echo "→ DashDiag HARDWARE smoke test against $HW_HOST"

# Optionally build + push a fresh binary so we test the current tree, not a
# stale deploy. Off by default (CI/release can set PUSH=1).
if [ "${PUSH:-0}" = "1" ]; then
  echo "→ building linux/amd64 and pushing to $HW_HOST:$REMOTE_BIN"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/dsd-hwsmoke ./cmd/dsd
  scp -q /tmp/dsd-hwsmoke "$HW_HOST:/tmp/dsd-hwsmoke"
  ssh_run "install -m755 /tmp/dsd-hwsmoke $REMOTE_BIN && rm -f /tmp/dsd-hwsmoke"
  rm -f /tmp/dsd-hwsmoke
fi

# Reachability gate — hard fail, don't silently "pass" an unrunnable test.
if ! ssh_run "test -x $REMOTE_BIN"; then
  echo "❌ cannot reach $HW_HOST or $REMOTE_BIN missing — aborting"
  exit 2
fi
echo "   version: $(ssh_run "$REMOTE_BIN --version" 2>/dev/null | head -1)"
echo ""

# Pull hardware + health JSON once each (network-light: two calls total).
HW_JSON="$(ssh_run "$REMOTE_BIN hardware --json 2>/dev/null" || true)"
HEALTH_JSON="$(ssh_run "$REMOTE_BIN health --json 2>/dev/null" || true)"

if [ -z "$HW_JSON" ]; then
  echo "❌ 'dsd hardware --json' returned nothing — aborting"; exit 2
fi

# jq if available locally, else python3. j '<filter>' reads from $HW_JSON.
if command -v jq >/dev/null 2>&1; then
  j() { printf '%s' "$HW_JSON" | jq -r "$1" 2>/dev/null; }
  jh(){ printf '%s' "$HEALTH_JSON" | jq -r "$1" 2>/dev/null; }
else
  j() { printf '%s' "$HW_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
  jh(){ printf '%s' "$HEALTH_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
fi

# ── DRIVES / SMART ────────────────────────────────────────────────────────────
# The wear% range check is the whole reason this script exists.
DRIVE_COUNT="$(j '.drives | length')"
if [ "${DRIVE_COUNT:-0}" = "0" ] || [ -z "$DRIVE_COUNT" ]; then
  bad "drives: none reported on a physical host — collector regression?"
else
  ok "drives: $DRIVE_COUNT reported"
  # Per-drive wear% must be 0..100 (the garbage value was ~3.4e12).
  while IFS= read -r w; do
    [ -z "$w" ] && continue
    num_in_range "drive wear%" "$w" 0 100
  done < <(j '.drives[].wear_pct')
  # SMART must report a boolean health on a smartctl-capable drive (not absent).
  SMART_PRESENT="$(j '[.drives[] | select(.smartctl_available == true) | .smart_ok] | length')"
  if [ "${SMART_PRESENT:-0}" -ge 1 ]; then
    ok "SMART smart_ok present on >=1 smartctl-capable drive"
  else
    skip "SMART health (no smartctl-capable drive)"
  fi
fi

# ── THERMAL ───────────────────────────────────────────────────────────────────
# .thermals[] = [{sensor,label,temp_c}, ...]. Take the hottest; must be a
# plausible CPU temp (above freezing, below 100°C Tjmax). 0/empty/absurd = bad.
CPU_TEMP="$(j '[.thermals[].temp_c] | max // empty')"
if [ -n "$CPU_TEMP" ] && [ "$CPU_TEMP" != "0" ]; then
  num_in_range "CPU temp °C (max sensor)" "$CPU_TEMP" 1 99
else
  skip "CPU thermal (no sensor reported)"
fi

# ── BATTERY (present-path) ────────────────────────────────────────────────────
# Battery lives in `health --json` as a check named "Battery", not in `hardware`.
BATT_PRESENT="$(jh '[.checks[] | select(.name=="Battery") | .raw.present] | first // false')"
if [ "$BATT_PRESENT" = "true" ] || [ "$BATT_PRESENT" = "True" ]; then
  num_in_range "battery capacity%" \
    "$(jh '[.checks[] | select(.name=="Battery") | .raw.capacity_pct] | first')" 0 100
else
  skip "battery (no battery present)"
fi

# ── HEALTH EXIT CONTRACT ──────────────────────────────────────────────────────
if ssh_run "$REMOTE_BIN health >/dev/null 2>&1; ec=\$?; [ \$ec -le 2 ]"; then
  ok "dsd health exit code in 0-2"
else
  bad "dsd health exit code out of contract"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
