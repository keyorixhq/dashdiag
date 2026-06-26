#!/bin/sh
# scripts/alpine-smoke.sh — runs INSIDE an alpine:latest container (busybox ash).
#
# CI otherwise has ZERO non-systemd / musl coverage (every job is ubuntu/debian/
# macOS — systemd + glibc), yet dsd keeps hitting bugs on that surface:
#   BUG-051 — DBus/journald phantom warnings on non-systemd hosts
#   BUG-054 — systemctl / journald fix-hints on OpenRC
#   BUG-071 — OOM `dmesg --time-format` rejected by busybox dmesg (this session)
# This asserts `dsd health` runs HONESTLY on musl + busybox: it doesn't crash,
# emits valid JSON, and the non-root run never escalates a verdict beyond the root
# run (the privilege false-verdict invariant, on this surface). It also naturally
# exercises the busybox `dmesg` path (BUG-071) — bare alpine has busybox dmesg.
#
# Expects a STATIC dsd at $DSD (built CGO_ENABLED=0, so it runs on musl).
set -eu

DSD="${DSD:-/usr/local/bin/dsd}"
apk add --no-cache jq >/dev/null
adduser -D tester 2>/dev/null || true

PASS=0
FAIL=0
ok()  { echo "✅ $1"; PASS=$((PASS + 1)); }
bad() { echo "❌ $1"; FAIL=$((FAIL + 1)); }

# Capture json + stderr; tolerate dsd's non-zero exit on WARN/CRIT (1/2).
run_health() { # <outfile> <errfile> [user]
  if [ -n "${3:-}" ]; then
    su "$3" -c "$DSD health --json" >"$1" 2>"$2" || true
  else
    "$DSD" health --json >"$1" 2>"$2" || true
  fi
}

run_health /tmp/root.json /tmp/root.err
run_health /tmp/nr.json   /tmp/nr.err   tester

# 1. No crash — a panic/runtime error on the musl/busybox surface is the failure
#    this whole job exists to catch.
for f in /tmp/root.err /tmp/nr.err; do
  if grep -qiE "panic:|runtime error|goroutine [0-9]+ \[" "$f"; then
    bad "dsd crashed on musl/busybox ($f):"; cat "$f"
  else
    ok "no panic ($f)"
  fi
done

# 2. Valid JSON both privilege levels.
for f in /tmp/root.json /tmp/nr.json; do
  if jq -e . "$f" >/dev/null 2>&1; then ok "valid JSON ($f)"; else bad "invalid/empty JSON ($f)"; fi
done

# 3. Non-root must not raise a WARN/CRIT that root doesn't (degrading to INFO is
#    fine). Volatile, world-readable point-in-time checks are skipped — they read
#    identical /proc for both, so a difference is transient noise, not privilege.
#    KEEP THIS SKIP LIST IN SYNC with scripts/check-nonroot-invariant.sh.
VIOL=$(jq -n --slurpfile r /tmp/root.json --slurpfile n /tmp/nr.json \
  --argjson skip '["CPU Load","Memory","Swap","IO","Pressure","Processes","Entropy","Clock","FDLimits","Network","Sessions"]' '
  def rank(s): {"OK":0,"INFO":1,"WARN":2,"CRIT":3}[s] // 0;
  ($r[0].checks // []) as $rc | ($n[0].checks // []) as $nc |
  ($rc | map({(.name): .status}) | add) as $rootmap |
  $nc | map(select(([.name] | inside($skip) | not)
                   and $rootmap[.name] != null
                   and rank(.status) >= 2
                   and rank(.status) > rank($rootmap[.name]))
            | {check: .name, nonroot: .status, root: $rootmap[.name]})' 2>/dev/null || echo '[]')
if [ "$(echo "$VIOL" | jq 'length')" -gt 0 ]; then
  bad "non-root escalates a verdict beyond root (musl/busybox):"
  echo "$VIOL" | jq -r '.[] | "  - \(.check): non-root=\(.nonroot)  root=\(.root)"'
else
  ok "no non-root verdict escalation"
fi

echo ""
echo "Alpine (musl/busybox) honesty smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
