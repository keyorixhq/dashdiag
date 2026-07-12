#!/usr/bin/env bash
# scripts/hardware-coverage-remote.sh — runs ON pve01, not locally.
#
# Pushed and executed by scripts/hardware-coverage.sh over SSH. Do not run
# this directly unless you are already logged into pve01 — it uses pve01's
# own local `pct`/`qm` access and its own SSH trust relationship to the VM
# guests (root SSH to guests is "key-only via pve01": the guests trust
# pve01's key, not any key coming from elsewhere, per TESTMATRIX.md).
#
# LXC guests (pct exec/push/pull) need no guest network path at all — pve01
# talks to them directly through the container API. VM guests are reached by
# SSH *from this host*, since that's the only trust path that works.
set -uo pipefail # not -e: one guest failing must not abort the whole run

WORKDIR="/root/dsd-hwcov"
BIN="$WORKDIR/dsd-cov"
DATA="$WORKDIR/data"
mkdir -p "$DATA"

log() { echo "[$(date +%H:%M:%S 2>/dev/null || echo t)] $*"; }

# ── pve01 itself: runPVE gate, always on, no start/stop ─────────────────────
log "=== pve01 (host) ==="
mkdir -p "$DATA/pve01"
GOCOVERDIR="$DATA/pve01" "$BIN" pve >/dev/null 2>&1
GOCOVERDIR="$DATA/pve01" "$BIN" health --deep >/dev/null 2>&1

# ── LXC helpers (pct exec/push/pull — no SSH) ────────────────────────────────
start_lxc() {
	local vmid=$1 label=$2
	log "=== $label (CT $vmid) ==="
	pct status "$vmid" | grep -q running || pct start "$vmid"
	for _ in $(seq 1 15); do
		pct exec "$vmid" -- true 2>/dev/null && break
		sleep 2
	done
	pct push "$vmid" "$BIN" /tmp/dsd-cov
	pct exec "$vmid" -- chmod +x /tmp/dsd-cov
}

collect_lxc() {
	local vmid=$1 label=$2 pass=$3
	shift 3
	local cmds=("$@")
	local remote_dir="/tmp/covdata-$pass"
	pct exec "$vmid" -- rm -rf "$remote_dir"
	pct exec "$vmid" -- mkdir -p "$remote_dir"
	for c in "${cmds[@]}"; do
		log "  [$label/$pass] -> dsd $c"
		# shellcheck disable=SC2086 # $c is a single subcommand token, no injection surface (fixed list below)
		pct exec "$vmid" -- env GOCOVERDIR="$remote_dir" /tmp/dsd-cov $c >/dev/null 2>&1
	done
	# pct pull only copies a single FILE, not a directory tree — tar inside the
	# container first, pull the tarball, extract it locally.
	local dir="$DATA/${label}-${pass}"
	mkdir -p "$dir"
	pct exec "$vmid" -- tar czf "${remote_dir}.tar.gz" -C /tmp "covdata-$pass"
	if pct pull "$vmid" "${remote_dir}.tar.gz" "${dir}.tar.gz" 2>/dev/null; then
		tar xzf "${dir}.tar.gz" -C "$dir" --strip-components=1
		rm -f "${dir}.tar.gz"
	else
		log "  (pull failed for $label/$pass)"
	fi
}

# ── VM helpers (SSH from pve01 — the only trusted path to these guests) ─────
start_vm() {
	local vmid=$1 ip=$2 user=$3 label=$4
	log "=== $label (VM $vmid, $ip) ==="
	qm status "$vmid" | grep -q running || qm start "$vmid"
	for _ in $(seq 1 60); do
		ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$user@$ip" true 2>/dev/null && return 0
		sleep 3
	done
	return 1
}

collect_vm() {
	local ip=$1 user=$2 label=$3 pass=$4
	shift 4
	local cmds=("$@")
	local remote_dir="/tmp/covdata-$pass"
	local run_prefix=""
	[ "$pass" = "root" ] && [ "$user" != "root" ] && run_prefix="sudo -n"
	ssh -o BatchMode=yes "$user@$ip" "rm -rf $remote_dir && mkdir -p $remote_dir"
	for c in "${cmds[@]}"; do
		log "  [$label/$pass] -> dsd $c"
		# env must come AFTER sudo, not before — sudo drops the caller's
		# environment by default, so `GOCOVERDIR=x sudo cmd` silently loses it.
		ssh -o BatchMode=yes "$user@$ip" "$run_prefix env GOCOVERDIR=$remote_dir /tmp/dsd-cov $c" >/dev/null 2>&1
	done
	local dir="$DATA/${label}-${pass}"
	mkdir -p "$dir"
	scp -q -o BatchMode=yes -r "$user@$ip:$remote_dir/*" "$dir/" 2>/dev/null || log "  (pull failed for $label/$pass)"
}

# ── almalinux9-lxc: RHEL OVAL real dispatch + runDB (postgres installed) ────
if start_lxc 213 almalinux9-lxc; then
	collect_lxc 213 almalinux9-lxc base "cve --all" "health --deep"
	log "  installing postgresql on almalinux9-lxc for runDB coverage"
	pct exec 213 -- dnf install -y postgresql-server postgresql >/dev/null 2>&1
	pct exec 213 -- postgresql-setup --initdb >/dev/null 2>&1
	pct exec 213 -- systemctl enable --now postgresql >/dev/null 2>&1
	collect_lxc 213 almalinux9-lxc db "db"
	pct exec 213 -- rm -rf /tmp/dsd-cov
fi

# ── opensuse16-lxc: SUSE OVAL real dispatch ──────────────────────────────────
if start_lxc 204 opensuse16-lxc; then
	collect_lxc 204 opensuse16-lxc base "cve --all" "health --deep"
	pct exec 204 -- rm -rf /tmp/dsd-cov
fi

# ── alpine-docker: docker.go / health_docker_unix.go real dispatch ──────────
if start_vm 106 192.168.10.38 root alpine-docker; then
	scp -q -o BatchMode=yes "$BIN" root@192.168.10.38:/tmp/dsd-cov
	ssh -o BatchMode=yes root@192.168.10.38 chmod +x /tmp/dsd-cov
	collect_vm 192.168.10.38 root alpine-docker root "docker" "health --deep"
	ssh -o BatchMode=yes root@192.168.10.38 'rm -rf /tmp/dsd-cov /tmp/covdata-root' || true
else
	log "  ⏭️  alpine-docker unreachable, skipping"
fi

# ── libvirt-kvm-test: runKVMGuest / KVM collectors real dispatch ────────────
if start_vm 113 192.168.10.71 debian libvirt-kvm-test; then
	scp -q -o BatchMode=yes "$BIN" debian@192.168.10.71:/tmp/dsd-cov
	ssh -o BatchMode=yes debian@192.168.10.71 chmod +x /tmp/dsd-cov
	collect_vm 192.168.10.71 debian libvirt-kvm-test root "kvm --deep"
	ssh -o BatchMode=yes debian@192.168.10.71 'rm -rf /tmp/dsd-cov /tmp/covdata-root' || true
else
	log "  ⏭️  libvirt-kvm-test unreachable, skipping"
fi

# ── nixos-25-05: isNixOS() true-branch real dispatch ─────────────────────────
if start_vm 212 192.168.10.47 root nixos-25-05; then
	scp -q -o BatchMode=yes "$BIN" root@192.168.10.47:/tmp/dsd-cov
	ssh -o BatchMode=yes root@192.168.10.47 chmod +x /tmp/dsd-cov
	collect_vm 192.168.10.47 root nixos-25-05 root "health --deep" "kvm" "gpu"
	ssh -o BatchMode=yes root@192.168.10.47 'rm -rf /tmp/dsd-cov /tmp/covdata-root' || true
else
	log "  ⏭️  nixos-25-05 unreachable, skipping"
fi

log "=== stopping guests ==="
for vmid in 213 204; do pct shutdown "$vmid" & done
for vmid in 106 113 212; do qm shutdown "$vmid" & done
wait

log "=== done ==="
log "coverage data collected under $DATA:"
find "$DATA" -mindepth 1 -maxdepth 1
