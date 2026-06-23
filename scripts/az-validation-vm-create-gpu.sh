#!/usr/bin/env bash
# az-validation-vm-create-gpu.sh — create ONE NVIDIA-GPU Azure VM for the dsd cloud
# validation, specifically to exercise the GPU collector's NVIDIA `nvidia-smi` path,
# which (unlike AMD amdgpu-sysfs and Intel i915) has never been validated on live
# hardware. FLAGLESS: paste into Azure Cloud Shell (Bash) and run, or:
#
#   curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/scripts/az-validation-vm-create-gpu.sh | bash
#
# Why NC4as_T4_v3: it is the CHEAPEST real NVIDIA GPU on Azure (1× Tesla T4, 4 vCPU,
# ~€0.45-0.50/hr) — enough to populate nvidia-smi and exercise the collector. A100/H100
# would run the identical text parser at 6-8× the cost, so they add no coverage. The VM
# does NOT ship with a driver; we install Azure's NVIDIA GPU Driver extension (which
# handles the kernel-module build + any reboot) so `nvidia-smi` comes up on its own.
# Keep the run SHORT — capture a replay bundle, then tear down with az-validation-vm-destroy.sh
# (the bundle is a permanent fixture that outlives the metered VM). set -euo pipefail.
#
# NOTE (2026-06-24): GPU quota was confirmed UNAVAILABLE on our credit subscription —
# `az-find-region-with-quota.sh Standard_NC4as_T4_v3` found no region with both
# deployability and free quota (credit/sponsored subs ship with 0 GPU vCPUs). A quota
# increase on such a sub is often denied or forces a pay-as-you-go conversion (removing
# the credit guardrail), so this is parked until real GPU access exists. The script is
# ready to fire the moment it does.
set -euo pipefail

# --- fixed config ---
RG=dsd-val
VM=dsd-val-gpu
REGION=westeurope                     # T4 (NCASv3_T4) is broadly offered here; edit if quota says otherwise
ZONES="1 2 3"                         # tried in order; NC-series T4 is often NON-zonal — we fall back to no-zone
SIZE=Standard_NC4as_T4_v3             # AMD EPYC + 1× NVIDIA Tesla T4, 4 vCPU — cheapest live NVIDIA GPU
IMAGE=Ubuntu2404                      # x86 gen2
ADMIN=azureuser
DATA_DISK_GB=16                       # ReadWrite-cached on purpose: re-exercises the Azure host-caching WARN
GO_VER=1.26.4
GPU_EXT_VERSION=1.9                   # Microsoft.HpcCompute/NvidiaGpuDriverLinux; bump if a newer line is required

command -v az >/dev/null || { echo "az not found — run in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run in Azure Cloud Shell (Bash)."; exit 1; }

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "Target       : $SIZE (NVIDIA T4) in $REGION, zones [$ZONES] (non-zonal fallback)"
echo "------------------------------------------------------------"

# --- offered pre-flight: refuse if the size isn't even offered to this subscription here ---
fam="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" --all -o json \
  | jq -r --arg s "$SIZE" '[.[]|select(.name==$s)]|.[0].family // ""')"
vcpus="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" -l "$REGION" \
  --query "[].capabilities[?name=='vCPUs'].value | [0]" -o tsv 2>/dev/null)"
vcpus="${vcpus:-4}"
restrict="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" -l "$REGION" \
  --query "[0].restrictions[].reasonCode" -o tsv 2>/dev/null || true)"
echo "Family : ${fam:-<unknown>}   vCPUs/box : $vcpus   Restrictions($REGION): ${restrict:-none}"
if [ -z "$fam" ]; then
  echo "✗ $SIZE is not offered to this subscription anywhere. GPU SKUs usually need a quota/access request first."
  echo "  Probe regions with:  ./scripts/az-find-region-with-quota.sh $SIZE"
  exit 1
fi
case "$restrict" in
  *NotAvailableForSubscription*) echo "✗ $SIZE is RESTRICTED in $REGION (no access/quota). Try another REGION or request access."; exit 1 ;;
esac

# --- quota pre-flight: need a full box's worth of family vCPUs free ---
if [ -n "$fam" ]; then
  read -r used lim < <(az vm list-usage -l "$REGION" -o json 2>/dev/null \
    | jq -r --arg f "$fam" '([.[]|select(.name.value==$f)]|.[0]) as $x | "\(($x.currentValue)//0) \(($x.limit)//0)"')
  free=$(( ${lim:-0} - ${used:-0} ))
  echo "Quota ($fam) in $REGION: ${used:-?}/${lim:-?} used → ${free} free  (need $vcpus)"
  if [ "${free:-0}" -lt "$vcpus" ]; then
    echo "✗ Not enough vCPU quota for $SIZE in $REGION (need $vcpus). Request an increase for '$fam', or edit REGION."
    echo "  Probe other regions with:  ./scripts/az-find-region-with-quota.sh $SIZE"
    exit 1
  fi
fi
echo "------------------------------------------------------------"

# --- cloud-init: build dsd from main (x86/amd64). HOME=/root: cloud-init runcmd has no HOME.
# The NVIDIA driver itself is installed by the GPU extension below, NOT here. ---
CLOUDINIT="$(mktemp)"
trap 'rm -f "$CLOUDINIT"' EXIT
cat > "$CLOUDINIT" <<EOF
#cloud-config
package_update: true
packages: [git, chrony]
runcmd:
  - [ bash, -c, "curl -fsSL https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz | tar -C /usr/local -xz" ]
  - [ bash, -c, "git clone --depth 1 https://github.com/keyorixhq/dashdiag /opt/dashdiag" ]
  - [ bash, -c, "cd /opt/dashdiag && HOME=/root /usr/local/go/bin/go build -o /usr/local/bin/dsd ./cmd/dsd && touch /var/lib/dsd-build-done" ]
EOF

echo "Creating resource group (also generates an SSH key in Cloud Shell)..."
az group create -n "$RG" -l "$REGION" -o none

# --- create: try each zone, then fall back to a NON-zonal create (T4 is often non-zonal) ---
CREATED_VM="" CREATED_ZONE=""
try_create() { # $1=vmname  $2=zone-or-empty
  local vmname="$1" zone="$2" zoneargs=()
  [ -n "$zone" ] && zoneargs=(--zone "$zone")
  az vm create \
    -g "$RG" -n "$vmname" -l "$REGION" "${zoneargs[@]}" \
    --image "$IMAGE" --size "$SIZE" \
    --admin-username "$ADMIN" --generate-ssh-keys \
    --data-disk-sizes-gb "$DATA_DISK_GB" --data-disk-caching ReadWrite \
    --custom-data "$CLOUDINIT" -o none
}
for z in $ZONES; do
  vmname="${VM}-z${z}"
  echo "→ Attempting zone $z (as $vmname)..."
  if try_create "$vmname" "$z"; then CREATED_VM="$vmname" CREATED_ZONE="$z"; break; fi
  echo "  ✗ zone $z unavailable — cleaning the partial attempt, trying the next..."
  az vm delete -g "$RG" -n "$vmname" --yes 2>/dev/null || true
done
if [ -z "$CREATED_VM" ]; then
  echo "→ No zone took it — attempting a NON-zonal create (normal for T4)..."
  vmname="${VM}-nozone"
  if try_create "$vmname" ""; then CREATED_VM="$vmname" CREATED_ZONE="none"; else
    az vm delete -g "$RG" -n "$vmname" --yes 2>/dev/null || true
  fi
fi
if [ -z "$CREATED_VM" ]; then
  echo "✗ No capacity for $SIZE in $REGION (zonal or non-zonal). Try later or another region."
  echo "  Probe regions:  ./scripts/az-find-region-with-quota.sh $SIZE"
  echo "  Then remove the empty RG:  bash az-validation-vm-destroy.sh"
  exit 1
fi

# --- install the NVIDIA driver via the Azure extension (builds the module + reboots if needed) ---
echo "→ Installing NVIDIA GPU Driver extension (this can take several minutes + a reboot)..."
if ! az vm extension set \
      -g "$RG" --vm-name "$CREATED_VM" \
      -n NvidiaGpuDriverLinux --publisher Microsoft.HpcCompute \
      --version "$GPU_EXT_VERSION" --settings '{}' -o none 2>/dev/null; then
  echo "  ⚠ extension install returned non-zero (version $GPU_EXT_VERSION may be stale)."
  echo "    Fallback: ssh in and run  'sudo ubuntu-drivers install && sudo reboot'  to get nvidia-smi."
fi

IP="$(az vm show -g "$RG" -n "$CREATED_VM" -d --query publicIps -o tsv)"
cat <<EOF
------------------------------------------------------------
✓ $CREATED_VM  ($SIZE, NVIDIA T4, zone $CREATED_ZONE)  @ $IP   (data disk ${DATA_DISK_GB}GB, host-caching=ReadWrite)

1) wait for the dsd build (~1-2 min):
     ssh ${ADMIN}@${IP} 'until [ -f /var/lib/dsd-build-done ]; do sleep 5; done; dsd --help >/dev/null && echo BUILD_OK'
2) wait for the NVIDIA driver (extension; can be several min + a reboot):
     ssh ${ADMIN}@${IP} 'until nvidia-smi >/dev/null 2>&1; do echo waiting-for-driver; sleep 15; done; nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu --format=csv'
3) validate the GPU collector — dual-privilege (CLAUDE.md hard rule), the NEW coverage:
     ssh ${ADMIN}@${IP} 'dsd gpu;        sudo dsd gpu'
     ssh ${ADMIN}@${IP} 'dsd gpu --deep --json' | jq .
     ssh ${ADMIN}@${IP} 'sudo dsd gpu --deep --json' | jq .
   (watch for false-OK: a healthy verdict with temp/util/power UNREAD is the bug class to catch.
    Cloud GPU passthrough may MASK thermal/power/clock — note which fields come back unknown.)
4) full health, dual-privilege, then diff:
     ssh ${ADMIN}@${IP} 'sudo dsd health --gpu --json' > root.json
     ssh ${ADMIN}@${IP} 'dsd health --gpu --json'      > nonroot.json
     diff <(jq -S 'del(.timestamp,.checks[].duration)' nonroot.json) <(jq -S 'del(.timestamp,.checks[].duration)' root.json)
5) capture a replay bundle (the permanent fixture), pull it, then DESTROY (metered!):
     ssh ${ADMIN}@${IP} 'sudo dsd capture --raw -o /tmp/azure-${SIZE}.tar.gz'
     scp ${ADMIN}@${IP}:/tmp/azure-${SIZE}.tar.gz .
     bash az-validation-vm-destroy.sh
------------------------------------------------------------
EOF
