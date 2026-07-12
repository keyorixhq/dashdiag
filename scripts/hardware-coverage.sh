#!/usr/bin/env bash
# scripts/hardware-coverage.sh — real-hardware branch coverage validation.
#
# Unlike unit-test coverage (go test -cover, tracked in CI), this instruments
# the actual dsd binary (go build -cover) and runs it for real against guests
# on the pve01 fleet, to confirm that branches gated on real infrastructure
# (PVE, KVM/libvirt, Docker, RHEL/SUSE package managers, NixOS, Postgres)
# actually execute correctly — not just that a unit test faked the gate.
#
# This can NEVER feed the CI-tracked coverage %: GitHub Actions cannot reach
# the homelab. Treat this as a periodic, manual validation pass (same
# category as hardware-smoke.sh) — run before a release or after touching
# cmd/'s real-infra-gated functions, not per-commit. Output is a *separate*
# report, never merged into coverage.out.
#
# Mechanism: pve01 holds its own SSH trust relationship to the VM guests
# (guests trust pve01's key, not any key from elsewhere) and direct API
# access to the LXC guests via pct exec/push/pull. So the actual per-guest
# work happens in a companion script (hardware-coverage-remote.sh) executed
# ON pve01, not from here — this script just builds, ships both over, and
# merges the results back.
#
# Usage: bash scripts/hardware-coverage.sh
# Override pve01 host: PVE_HOST=root@192.168.10.x bash scripts/hardware-coverage.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PVE_HOST="${PVE_HOST:-root@192.168.10.20}"
REMOTE_WORKDIR="/root/dsd-hwcov"
LOCAL_COVDIR=".scratch/hwcov"

ssh_pve() { ssh -o ConnectTimeout=10 -o BatchMode=yes "$PVE_HOST" "$@"; }

echo "→ building coverage-instrumented linux/amd64 binary"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -cover -trimpath -o .scratch/dsd-cov ./cmd/dsd

echo "→ pushing binary + remote orchestrator to $PVE_HOST"
ssh_pve "mkdir -p $REMOTE_WORKDIR/data && rm -rf $REMOTE_WORKDIR/data/*"
scp -q .scratch/dsd-cov "$PVE_HOST:$REMOTE_WORKDIR/dsd-cov"
scp -q scripts/hardware-coverage-remote.sh "$PVE_HOST:$REMOTE_WORKDIR/run.sh"
ssh_pve "chmod +x $REMOTE_WORKDIR/dsd-cov $REMOTE_WORKDIR/run.sh"

echo "→ running the real-hardware sweep on pve01 (starts/stops guests as needed — this takes a while)"
ssh_pve "bash $REMOTE_WORKDIR/run.sh"

echo "→ pulling collected coverage data back"
rm -rf "$LOCAL_COVDIR"
mkdir -p "$LOCAL_COVDIR"
scp -q -r "$PVE_HOST:$REMOTE_WORKDIR/data/*" "$LOCAL_COVDIR/" 2>/dev/null || {
	echo "❌ no coverage data came back — aborting"
	exit 2
}

echo "→ merging coverage data from all guests"
DIRS=""
for d in "$LOCAL_COVDIR"/*/; do
	[ -n "$(ls -A "$d" 2>/dev/null)" ] || continue
	DIRS="${DIRS:+$DIRS,}${d%/}"
done
if [ -z "$DIRS" ]; then
	echo "❌ every guest's coverage directory was empty — aborting"
	exit 2
fi
mkdir -p "$LOCAL_COVDIR-merged"
go tool covdata merge -i="$DIRS" -o="$LOCAL_COVDIR-merged"

echo ""
echo "=== real-hardware coverage summary (NOT part of the tracked CI %) ==="
go tool covdata percent -i="$LOCAL_COVDIR-merged"

go tool covdata textfmt -i="$LOCAL_COVDIR-merged" -o="$LOCAL_COVDIR-merged.out"
echo ""
echo "Legacy-format profile: $LOCAL_COVDIR-merged.out"
echo "Inspect specific lines: go tool cover -func=$LOCAL_COVDIR-merged.out | grep <package>"
echo "Visual: go tool cover -html=$LOCAL_COVDIR-merged.out"
