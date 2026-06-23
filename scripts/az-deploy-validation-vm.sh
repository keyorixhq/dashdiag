#!/usr/bin/env bash
# az-deploy-validation-vm.sh — provision (and tear down) a throwaway Azure VM for the
# dsd cloud guest-side validation in docs/CLOUD_VALIDATION.md, and build dsd from `main`
# ON the VM (the new cloud checks are post-v1.7.0 and NOT in any release, so the install
# one-liner / release binary can't be used).
#
# Run in Azure Cloud Shell (Bash) — az + jq are already there, and `az vm create
# --generate-ssh-keys` lets you `ssh` straight in from the same Cloud Shell afterwards.
#
# Usage:
#   ./az-deploy-validation-vm.sh up     [REGION] ["ZONES"] [SIZE]
#   ./az-deploy-validation-vm.sh down
#
# Defaults: swedencentral / zones "1 2 3" / Standard_D2pls_v6 (arm64, NVMe — chosen from
# the deploy-zones scan; proven arm region for this subscription). ZONES is a
# space-separated FALLBACK list: it tries each zone in order and stops at the first with
# capacity (a single zone can be at capacity even when the size is "deployable" region-wide).
#   e.g.  ./az-deploy-validation-vm.sh up swedencentral "1 2 3"   # the default
#
#   NOTE: D2pls_v6 has NO temp disk (no 'd' in the size) → the temp-disk checks (A1/A2)
#   are NOT exercised on it. It DOES cover NVMe io_timeout, host-cache, scheduled-events,
#   Dynamic-Memory-absent, and arm64. For temp-disk too, use a 'd' size (e.g. a Ddsv5) or
#   add a small Standard_D2s_v3, and re-run with that SIZE arg.
set -euo pipefail

RG="dsd-val"
VM="dsd-val-vm"
ADMIN="azureuser"
DATA_DISK_GB=16
GO_VER="1.26.4"   # bump if the build step 404s on the Go arm64 tarball

ACTION="${1:-}"
REGION="${2:-swedencentral}"
ZONES="${3:-1 2 3}"   # space-separated fallback list — tries each in order until one has capacity
SIZE="${4:-Standard_D2pls_v6}"
# arm64 image (D2pls_v6 is Arm64 — an x86 image will NOT boot on it).
IMAGE="Canonical:ubuntu-24_04-lts:server-arm64:latest"

command -v az >/dev/null || { echo "az not found — run in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run in Azure Cloud Shell (Bash)."; exit 1; }

case "$ACTION" in
down)
  echo "Deleting resource group '$RG' (VM, disk, NIC, IP) — capture your bundle first!"
  az group delete -n "$RG" --yes --no-wait && echo "Teardown started (async)."
  exit 0
  ;;
up) : ;;
*)
  echo "Usage: $0 up [REGION] [\"ZONES\"] [SIZE]   |   $0 down"
  echo "       ZONES is a space-separated fallback list, default \"1 2 3\"."; exit 1 ;;
esac

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "Target       : $SIZE  in  $REGION  zone(s) $ZONES (first with capacity)"
echo "------------------------------------------------------------"

# --- quota pre-flight: fail fast (with alternatives) rather than a cryptic create error ---
fam="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" --all -o json \
  | jq -r --arg s "$SIZE" '[.[]|select(.name==$s)]|.[0].family // ""')"
if [ -n "$fam" ]; then
  read -r used lim < <(az vm list-usage -l "$REGION" -o json 2>/dev/null \
    | jq -r --arg f "$fam" '([.[]|select(.name.value==$f)]|.[0]) as $x | "\(($x.currentValue)//0) \(($x.limit)//0)"')
  free=$(( ${lim:-0} - ${used:-0} ))
  echo "Quota ($fam) in $REGION: ${used:-?}/${lim:-?} used → ${free} free"
  if [ "${free:-0}" -lt 2 ]; then
    echo "✗ Not enough vCPU quota for $SIZE in $REGION (need 2)."
    echo "  Run ./az-find-region-with-quota.sh $SIZE  to find a region with headroom,"
    echo "  or request a quota increase for '$fam'. Aborting before create."
    exit 1
  fi
fi
echo "------------------------------------------------------------"

# --- cloud-init: build dsd from main natively (arm64), mark done when ready ---
CLOUDINIT="$(mktemp)"
trap 'rm -f "$CLOUDINIT"' EXIT
cat > "$CLOUDINIT" <<EOF
#cloud-config
package_update: true
packages: [git, chrony]
runcmd:
  - [ bash, -c, "curl -fsSL https://go.dev/dl/go${GO_VER}.linux-arm64.tar.gz | tar -C /usr/local -xz" ]
  - [ bash, -c, "git clone --depth 1 https://github.com/keyorixhq/dashdiag /opt/dashdiag" ]
  - [ bash, -c, "cd /opt/dashdiag && /usr/local/go/bin/go build -o /usr/local/bin/dsd ./cmd/dsd" ]
  - [ bash, -c, "/usr/local/bin/dsd version >/dev/null 2>&1 || true; touch /var/lib/dsd-build-done" ]
EOF

echo "Creating resource group (also generates an SSH key in Cloud Shell)..."
az group create -n "$RG" -l "$REGION" -o none

# Try each zone in order — a specific zone can be at capacity (ZonalAllocationFailed)
# even when the SKU is "deployable" in the region. Each attempt uses a zone-unique VM name
# so a failed attempt's leftover NIC/IP can't block the next; all of it is removed by `down`.
CREATED_VM="" CREATED_ZONE=""
for z in $ZONES; do
  vmname="${VM}-z${z}"
  echo "→ Attempting $SIZE in $REGION zone $z (as $vmname)..."
  if az vm create \
       -g "$RG" -n "$vmname" -l "$REGION" --zone "$z" \
       --image "$IMAGE" --size "$SIZE" \
       --admin-username "$ADMIN" --generate-ssh-keys \
       --data-disk-sizes-gb "$DATA_DISK_GB" --data-disk-caching ReadWrite \
       --custom-data "$CLOUDINIT" -o none; then
    CREATED_VM="$vmname" CREATED_ZONE="$z"
    break
  fi
  echo "  ✗ zone $z unavailable (capacity/allocation) — cleaning the partial attempt and trying the next..."
  az vm delete -g "$RG" -n "$vmname" --yes 2>/dev/null || true
done

if [ -z "$CREATED_VM" ]; then
  echo "------------------------------------------------------------"
  echo "✗ No zone in [$ZONES] had capacity for $SIZE in $REGION right now."
  echo "  Try again later, a different region (./az-find-region-with-quota.sh $SIZE), or run \`$0 down\` to clean up."
  exit 1
fi

VM="$CREATED_VM"
IP="$(az vm show -g "$RG" -n "$VM" -d --query publicIps -o tsv)"
echo "✓ Deployed in zone $CREATED_ZONE."

cat <<EOF
------------------------------------------------------------
VM up: $VM  ($SIZE, arm64)  @ $IP   (data disk: ${DATA_DISK_GB}GB, host-caching=ReadWrite)

1) Wait for the build (cloud-init installs Go ${GO_VER} + builds dsd from main, ~1-2 min):
     ssh ${ADMIN}@${IP} 'until [ -f /var/lib/dsd-build-done ]; do sleep 5; done; dsd --help >/dev/null && echo BUILD_OK'

2) Validate (dual-privilege — the hard rule):
     ssh ${ADMIN}@${IP} 'sudo dsd health --json' > root.json
     ssh ${ADMIN}@${IP} 'dsd health --json'      > nonroot.json
     diff <(jq -S "del(.timestamp,.checks[].duration)" nonroot.json) \\
          <(jq -S "del(.timestamp,.checks[].duration)" root.json)
   Eyeball the Azure/CloudMeta checks per docs/CLOUD_VALIDATION.md §Azure
   (A3 host-cache WARN on the ReadWrite data disk; A4 NVMe io_timeout; A5 DM-absent; A6 scheduled-events).

3) Capture a replayable bundle, then TEAR DOWN (capture, don't camp — metered):
     ssh ${ADMIN}@${IP} 'sudo dsd capture --raw -o /tmp/azure-${SIZE}.tar.gz'
     scp ${ADMIN}@${IP}:/tmp/azure-${SIZE}.tar.gz .
     $0 down
------------------------------------------------------------
EOF
