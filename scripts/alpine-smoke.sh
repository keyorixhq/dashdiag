#!/bin/sh
# shellcheck disable=SC3043  # local is supported by busybox ash (the actual runtime)
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
# openrc installs /sbin/openrc, the marker dsd uses to detect the init system.
# Without it a bare alpine container has pid1=sh → init detected as "unknown" → the
# hint adapter is (correctly) a no-op, so the OpenRC hint rewriting this job means
# to cover never actually runs. Installing openrc makes this a real OpenRC surface.
apk add --no-cache jq openrc >/dev/null
adduser -D tester 2>/dev/null || true

PASS=0
FAIL=0
ok()  { local msg="$1"; echo "✅ $msg"; PASS=$((PASS + 1)); }
bad() { local msg="$1"; echo "❌ $msg"; FAIL=$((FAIL + 1)); }

# Capture json + stderr; tolerate dsd's non-zero exit on WARN/CRIT (1/2).
run_health() { # <outfile> <errfile> [user]
  local outfile="$1" errfile="$2" user="${3:-}"
  if [ -n "$user" ]; then
    su "$user" -c "$DSD health --json" >"$outfile" 2>"$errfile" || true
  else
    "$DSD" health --json >"$outfile" 2>"$errfile" || true
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

# 4. No systemd-only command leaked into a remediation hint (BUG-054 class — the
#    recurring non-systemd hint gap: Gentoo, Artix #644, Devuan #646). On this
#    OpenRC host the adapter rewrites `systemctl <verb>`→rc-service and drops
#    timedatectl/journalctl, so any `to fix:`/`to inspect:` line still naming one of
#    them is a hint FORM the adapter does not yet handle — a leak. (Prose `note:`
#    lines that merely mention these are not commands, so they are not checked.)
LEAK=$(jq -r '[.insights[]?.hints[]?
               | select(test("^to (fix|inspect):"))
               | select(test("\\b(systemctl|timedatectl|journalctl)\\b"))]
              | unique | .[]' /tmp/root.json 2>/dev/null || true)
if [ -n "$LEAK" ]; then
  bad "systemd-only command leaked into a hint on OpenRC (adapter missed this form — add a rewrite in adaptHint):"
  echo "$LEAK" | sed 's/^/    /'
else
  ok "no systemd-only command leaked into hints"
fi

echo ""
echo "Alpine (musl/busybox) honesty smoke: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
