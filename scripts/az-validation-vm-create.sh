#!/usr/bin/env bash
# az-validation-vm-create.sh — create ONE Azure VM for the dsd cloud guest-side validation
# (docs/CLOUD_VALIDATION.md), trying zones 1→2→3 for capacity, and build dsd from `main` on
# it. FLAGLESS by design: Cloud Shell is ephemeral (no persistent script storage), so this
# is meant to be pasted in and run — or curl'd:
#
#   curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/scripts/az-validation-vm-create.sh | bash
#
# Tear it down afterwards with az-validation-vm-destroy.sh (capture your bundle FIRST —
# the VM is metered). Edit the config block below to change region/size, not via flags.
#
# NOTE: D2pls_v6 has no temp disk (no 'd') → the temp-disk checks (A1/A2) aren't exercised;
# it covers NVMe io_timeout, host-cache, scheduled-events, DM-absent, and arm64.
set -euo pipefail

# --- fixed config (edit here, not via flags) ---
RG=dsd-val
VM=dsd-val-vm
REGION=swedencentral
ZONES="1 2 3"                                       # tried in order; first with capacity wins
SIZE=Standard_D2pls_v6                              # arm64, NVMe
IMAGE="Canonical:ubuntu-24_04-lts:server-arm64:latest"   # arm64 image (x86 image won't boot on D2pls)
ADMIN=azureuser
DATA_DISK_GB=16                                     # data disk at ReadWrite caching → host-cache check
GO_VER=1.26.4                                       # bump if the build step 404s on the Go arm64 tarball

command -v az >/dev/null || { echo "az not found — run in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run in Azure Cloud Shell (Bash)."; exit 1; }

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "Target       : $SIZE in $REGION, zones [$ZONES] (first with capacity)"
echo "------------------------------------------------------------"

# --- quota pre-flight: fail fast rather than a cryptic create error ---
fam="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" --all -o json \
  | jq -r --arg s "$SIZE" '[.[]|select(.name==$s)]|.[0].family // ""')"
if [ -n "$fam" ]; then
  read -r used lim < <(az vm list-usage -l "$REGION" -o json 2>/dev/null \
    | jq -r --arg f "$fam" '([.[]|select(.name.value==$f)]|.[0]) as $x | "\(($x.currentValue)//0) \(($x.limit)//0)"')
  free=$(( ${lim:-0} - ${used:-0} ))
  echo "Quota ($fam) in $REGION: ${used:-?}/${lim:-?} used → ${free} free"
  if [ "${free:-0}" -lt 2 ]; then
    echo "✗ Not enough vCPU quota for $SIZE in $REGION (need 2). Request an increase for '$fam', or edit REGION."
    exit 1
  fi
fi
echo "------------------------------------------------------------"

# --- cloud-init: build dsd from main natively (the new cloud checks are post-v1.8.0... ---
# (actually shipped in v1.8.0, but building from main always tracks the latest) ---
CLOUDINIT="$(mktemp)"
trap 'rm -f "$CLOUDINIT"' EXIT
cat > "$CLOUDINIT" <<EOF
#cloud-config
package_update: true
packages: [git, chrony]
runcmd:
  - [ bash, -c, "curl -fsSL https://go.dev/dl/go${GO_VER}.linux-arm64.tar.gz | tar -C /usr/local -xz" ]
  - [ bash, -c, "git clone --depth 1 https://github.com/keyorixhq/dashdiag /opt/dashdiag" ]
  # HOME=/root: cloud-init runcmd has no HOME, so go can't find its module cache without it.
  # touch only on SUCCESS — a failed build must NOT signal "done" to the wait-loop (it did, once).
  - [ bash, -c, "cd /opt/dashdiag && HOME=/root /usr/local/go/bin/go build -o /usr/local/bin/dsd ./cmd/dsd && touch /var/lib/dsd-build-done" ]
EOF

echo "Creating resource group (also generates an SSH key in Cloud Shell)..."
az group create -n "$RG" -l "$REGION" -o none

# Try each zone in order — a single zone can be at capacity (ZonalAllocationFailed) even
# when the size is deployable region-wide. Zone-unique VM names so a failed attempt's
# leftover NIC/IP can't block the next; az-validation-vm-destroy.sh removes all of it.
CREATED_VM="" CREATED_ZONE=""
for z in $ZONES; do
  vmname="${VM}-z${z}"
  echo "→ Attempting zone $z (as $vmname)..."
  if az vm create \
       -g "$RG" -n "$vmname" -l "$REGION" --zone "$z" \
       --image "$IMAGE" --size "$SIZE" \
       --admin-username "$ADMIN" --generate-ssh-keys \
       --data-disk-sizes-gb "$DATA_DISK_GB" --data-disk-caching ReadWrite \
       --custom-data "$CLOUDINIT" -o none; then
    CREATED_VM="$vmname" CREATED_ZONE="$z"
    break
  fi
  echo "  ✗ zone $z unavailable (capacity) — cleaning the partial attempt, trying the next..."
  az vm delete -g "$RG" -n "$vmname" --yes 2>/dev/null || true
done

if [ -z "$CREATED_VM" ]; then
  echo "✗ No zone in [$ZONES] had capacity for $SIZE in $REGION. Try later or another region."
  echo "  Run az-validation-vm-destroy.sh to remove the (empty) resource group."
  exit 1
fi

IP="$(az vm show -g "$RG" -n "$CREATED_VM" -d --query publicIps -o tsv)"
cat <<EOF
------------------------------------------------------------
✓ $CREATED_VM  ($SIZE, arm64, zone $CREATED_ZONE)  @ $IP   (data disk ${DATA_DISK_GB}GB, host-caching=ReadWrite)

1) wait for the dsd build (cloud-init installs Go ${GO_VER} + builds from main, ~1-2 min):
     ssh ${ADMIN}@${IP} 'until [ -f /var/lib/dsd-build-done ]; do sleep 5; done; dsd --help >/dev/null && echo BUILD_OK'
2) validate (dual-privilege — the hard rule):
     ssh ${ADMIN}@${IP} 'sudo dsd health --json' > root.json
     ssh ${ADMIN}@${IP} 'dsd health --json'      > nonroot.json
     diff <(jq -S "del(.timestamp,.checks[].duration)" nonroot.json) \\
          <(jq -S "del(.timestamp,.checks[].duration)" root.json)
   (docs/CLOUD_VALIDATION.md §Azure: A3 host-cache WARN, A4 NVMe io_timeout, A5 DM-absent, A6 scheduled-events)
3) capture a replay bundle, then destroy (capture, don't camp — metered):
     ssh ${ADMIN}@${IP} 'sudo dsd capture --raw -o /tmp/azure-${SIZE}.tar.gz'
     scp ${ADMIN}@${IP}:/tmp/azure-${SIZE}.tar.gz .
     bash az-validation-vm-destroy.sh
------------------------------------------------------------
EOF
