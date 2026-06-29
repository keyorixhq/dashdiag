#!/bin/sh
# scripts/container-honesty-smoke.sh — runs INSIDE a `--cgroupns=host --cpus=<frac>`
# container. Guards the cgroup-v2 self-dir read (#585): under --cgroupns=host the bare
# /sys/fs/cgroup is the HOST ROOT cgroup, so a regression that reads dynamic counters
# (cpu.stat / memory.events) from the base instead of the container's own sub-path sees
# 0 throttled periods — a throttled/OOM-killed container then falsely reads healthy
# (a false-OK). CI otherwise never exercises the --cgroupns=host path. This saturates
# the CPU past the fractional quota and asserts `dsd guest` DETECTS the throttling,
# i.e. the self-cgroup-dir resolution still works.
#
# Expects a static dsd at $DSD (CGO_ENABLED=0). The container must be started with
# --cgroupns=host and a sub-1.0 --cpus quota.
set -u
DSD="${DSD:-/usr/local/bin/dsd}"

# Saturate well past the fractional quota so the cgroup throttles within the window.
i=0
while [ "$i" -lt 4 ]; do (while :; do :; done) & i=$((i + 1)); done
sleep 3
"$DSD" guest 2>/dev/null >/tmp/out.txt || true
# No need to reap the busy loops — the --rm container exits right after this script,
# tearing them down.

echo "--- dsd guest (--cgroupns=host, CPU saturated past quota) ---"
cat /tmp/out.txt
echo "---"

if grep -qi "throttl" /tmp/out.txt; then
	echo "✅ cgroup throttle detected under --cgroupns=host (self-cgroup-dir read OK, #585)"
	exit 0
fi
echo "❌ throttle NOT detected — the --cgroupns=host self-cgroup read may have regressed"
echo "   (#585): a CPU-throttled container read as healthy. dsd guest must read cpu.stat"
echo "   from the container's own cgroup sub-path, not the bare /sys/fs/cgroup host root."
exit 1
