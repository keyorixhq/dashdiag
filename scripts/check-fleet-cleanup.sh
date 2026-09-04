#!/usr/bin/env bash
# check-fleet-cleanup.sh — proves `dsd fleet --bin` removes the remote binary
# it uploads, under the shipped configuration: a real SSH connection to a real
# container, not a unit test asserting on a command string.
#
# GAP-1 (docs/product-claim-gaps-2026-09-02.md): "no persistent agent" is only
# true if the binary `dsd fleet --bin` scp's to a target doesn't outlive the
# run that put it there. internal/fleet's own unit tests (sshexec_test.go)
# mock ssh/scp with a fake shell script on PATH — good for wiring, but a fake
# `ssh` that always exits 0 can't tell you whether the REAL remote file is
# actually gone afterward. This script does that: it runs a real sshd
# container, does a real `dsd fleet --bin` deploy against it over a real SSH
# connection (through an ~/.ssh/config Host entry, exactly how a real operator
# would point fleet at a nonstandard port), then `docker exec`s into the same
# container and asserts the uploaded binary is gone.
#
# WHY THIS WRITES TO THE REAL ~/.ssh/config (backed up and restored), NOT a
# faked $HOME: fleet's own design deliberately has no --port/--identity flags
# — it inherits the operator's own ~/.ssh/config (internal/fleet's package doc
# comment). The first version of this script pointed the HOME env var at a
# throwaway directory instead of touching the real one — plausible, but wrong:
# OpenSSH resolves its DEFAULT config path via the real passwd-database home
# directory (getpwuid), not the $HOME environment variable, specifically so an
# attacker-controlled $HOME can't redirect config/key lookups. A HOME override
# is silently ignored for this purpose (confirmed: `ssh -vv` under an
# overridden HOME still logs "Reading configuration data <real-home>/.ssh/
# config"), so the faked-HOME version of this script wasn't testing what it
# claimed to — it was silently falling through to "no matching Host alias" on
# every run, which reads as an unreachable host and could look like cleanup
# never even got exercised. Caught by actually reading dsd fleet's own error
# output rather than trusting the script's green exit.
#
# Safety: run this in a disposable environment (its own container/VM, or CI) —
# it backs up any existing ~/.ssh/config and restores it in the EXIT trap, but
# "back up and restore" is a mitigation, not a substitute for not touching a
# real developer's ~/.ssh at all. It never touches ~/.ssh/id_ed25519 or any
# other existing key (it generates and cleans up its own, uniquely named).
#
# Requires: docker, ssh-keygen, go (only if $DSD_LOCAL/$DSD_REMOTE aren't prebuilt).
set -euo pipefail

IMAGE="lscr.io/linuxserver/openssh-server:latest"
CONTAINER="dsd-fleet-cleanup-check"
SSH_USER="linuxserver.io"
HOST_ALIAS="dsd-fleet-cleanup-target"
REMOTE_BIN="/tmp/dsd-fleet"

SSH_DIR="$HOME/.ssh"
KEY_PATH="$SSH_DIR/dsd-fleet-cleanup-check.id_ed25519"
CONFIG_PATH="$SSH_DIR/config"

WORKDIR="$(mktemp -d)"
CONFIG_BACKUP="$WORKDIR/config.orig"
HAD_CONFIG=0
HAD_SSH_DIR=1

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -f "$KEY_PATH" "$KEY_PATH.pub"
  if [ "$HAD_CONFIG" -eq 1 ]; then
    cp "$CONFIG_BACKUP" "$CONFIG_PATH"
  else
    rm -f "$CONFIG_PATH"
  fi
  if [ "$HAD_SSH_DIR" -eq 0 ]; then
    rmdir "$SSH_DIR" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "FAIL: docker is required" >&2; exit 1; }
command -v ssh-keygen >/dev/null || { echo "FAIL: ssh-keygen is required" >&2; exit 1; }

if [ ! -d "$SSH_DIR" ]; then
  HAD_SSH_DIR=0
  mkdir -m 700 "$SSH_DIR"
fi
if [ -f "$CONFIG_PATH" ]; then
  HAD_CONFIG=1
  cp "$CONFIG_PATH" "$CONFIG_BACKUP"
fi

echo "generating throwaway SSH keypair"
ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -q -C "dsd-fleet-cleanup-check"
PUBKEY="$(cat "$KEY_PATH.pub")"

echo "starting sshd container ($IMAGE)"
docker run --rm -d --name "$CONTAINER" -P -e "PUBLIC_KEY=$PUBKEY" "$IMAGE" >/dev/null

# -P (publish all) picked a random host port for the container's internal
# 2222 — resolve it rather than hardcoding, so a busy fixed port can't flake.
PORT="$(docker port "$CONTAINER" 2222/tcp | head -1 | sed -E 's/.*:([0-9]+)$/\1/')"
[ -n "$PORT" ] || { echo "FAIL: could not resolve mapped sshd port" >&2; exit 1; }

echo "waiting for sshd to accept connections on 127.0.0.1:$PORT"
for _ in $(seq 1 30); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=2 -o BatchMode=yes \
         -i "$KEY_PATH" -p "$PORT" "$SSH_USER@127.0.0.1" true 2>/dev/null; then
    break
  fi
  sleep 1
done
if ! ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=2 -o BatchMode=yes \
         -i "$KEY_PATH" -p "$PORT" "$SSH_USER@127.0.0.1" true 2>/dev/null; then
  echo "FAIL: sshd never came up" >&2
  docker logs "$CONTAINER" >&2 || true
  exit 1
fi
echo "OK: sshd reachable"

# Appended, not written wholesale — an existing ~/.ssh/config keeps every
# other Host block; ours adds one new, uniquely-named alias. Restored exactly
# in the cleanup trap above regardless of how this script exits.
{
  echo ""
  echo "Host $HOST_ALIAS"
  echo "  HostName 127.0.0.1"
  echo "  Port $PORT"
  echo "  User $SSH_USER"
  echo "  IdentityFile $KEY_PATH"
  echo "  StrictHostKeyChecking no"
  echo "  UserKnownHostsFile /dev/null"
  echo "  BatchMode yes"
} >> "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"

# Two DIFFERENT binaries: DSD_LOCAL runs on THIS machine to orchestrate ssh/scp
# (must match the host's own GOOS/GOARCH so it can actually execute here);
# DSD_REMOTE is the file --bin uploads, which then executes AS `dsd health` on
# the linux/amd64 container — cross-compiled unconditionally, even when the
# orchestrator happens to already be linux/amd64 (e.g. the ubuntu CI runner),
# so this script behaves identically everywhere rather than depending on the
# host arch matching the target by coincidence.
DSD_LOCAL="${DSD_LOCAL:-}"
if [ -z "$DSD_LOCAL" ]; then
  DSD_LOCAL="$WORKDIR/dsd-local"
  echo "building dsd for the orchestrating host -> $DSD_LOCAL"
  go build -o "$DSD_LOCAL" ./cmd/dsd
fi
DSD_REMOTE="${DSD_REMOTE:-}"
if [ -z "$DSD_REMOTE" ]; then
  DSD_REMOTE="$WORKDIR/dsd-remote"
  echo "building static dsd (linux/amd64, the upload target) -> $DSD_REMOTE"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$DSD_REMOTE" ./cmd/dsd
fi

echo "confirming remote binary is ABSENT before the run (sanity)"
# REMOTE_BIN is a fixed local literal ("/tmp/dsd-fleet", no metacharacters) —
# client-side expansion into the remote command string is intentional here,
# not a quoting bug. stderr is NOT discarded: a config/connection failure here
# must be visible, not silently misread as "good, the file is absent" — that
# exact mistake is what let the HOME-faking version of this script pass
# without ever actually reaching the container (see header comment).
# shellcheck disable=SC2029
if ! ssh "$HOST_ALIAS" "test ! -e $REMOTE_BIN"; then
  echo "FAIL: could not confirm $REMOTE_BIN is absent before the run (connection failure, or it already exists — test setup is not clean)" >&2
  exit 1
fi

echo "running: dsd fleet --bin $DSD_REMOTE $HOST_ALIAS"
FLEET_JSON="$WORKDIR/fleet.json"
if ! "$DSD_LOCAL" fleet --bin "$DSD_REMOTE" --json "$HOST_ALIAS" > "$FLEET_JSON" 2>"$WORKDIR/fleet.stderr"; then
  rc=$?
  # dsd fleet exits non-zero on WARN/CRIT/unreachable by design (matches
  # dsd health) — that alone isn't a script failure, but a nonzero exit paired
  # with unreachable=1 IS: it means the deploy itself never happened, and this
  # script would be "proving" cleanup on a run that never uploaded anything.
  if grep -q '"unreachable": *[1-9]' "$FLEET_JSON" 2>/dev/null; then
    echo "FAIL: dsd fleet reported the target unreachable (exit $rc) — cleanup was never exercised" >&2
    cat "$FLEET_JSON" "$WORKDIR/fleet.stderr" >&2
    exit 1
  fi
fi
echo "fleet run result:"
cat "$FLEET_JSON"
echo

if grep -q '"cleanup_error"' "$FLEET_JSON"; then
  echo "FAIL: dsd fleet reported a cleanup_error — the remote binary may still be present" >&2
  cat "$FLEET_JSON" >&2
  exit 1
fi

echo "asserting the remote binary is GONE after the run (docker exec into the container, not via ssh again)"
if docker exec "$CONTAINER" test -e "$REMOTE_BIN" 2>/dev/null; then
  echo "FAIL: $REMOTE_BIN still exists on the target after dsd fleet finished — GAP-1 cleanup did not run" >&2
  docker exec "$CONTAINER" ls -la /tmp >&2 || true
  exit 1
fi

echo
echo "OK: dsd fleet --bin uploaded, ran, and removed $REMOTE_BIN — no persistent agent left behind"
