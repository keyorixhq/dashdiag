#!/usr/bin/env bash
# az-validation-vm-create-nvme.sh — create ONE *NVMe* Azure VM (x86) for the dsd cloud
# validation, specifically to exercise the A4 NVMe io_timeout check that the arm D2pls_v6
# can't (it's SCSI). FLAGLESS: paste into Azure Cloud Shell (Bash) and run, or:
#
#   curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/scripts/az-validation-vm-create-nvme.sh | bash
#
# Why D2as_v6: it is NVMe-ONLY (DiskControllerTypes=NVMe — verified per-size below before
# deploying, so we never spin a SCSI box by mistake), so /sys/class/nvme is guaranteed
# populated with a modern NVMe-tagged Ubuntu image. Tear down with az-validation-vm-destroy.sh.
set -euo pipefail

# --- fixed config ---
RG=dsd-val
VM=dsd-val-nvme
REGION=swedencentral
ZONES="1 2 3"
SIZE=Standard_D2as_v6                 # AMD v6, x86, NVMe-ONLY
IMAGE=Ubuntu2404                      # x86 gen2; must be NVMe-tagged (NVMe-only size errors loudly if not)
ADMIN=azureuser
DATA_DISK_GB=16
GO_VER=1.26.4

command -v az >/dev/null || { echo "az not found — run in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run in Azure Cloud Shell (Bash)."; exit 1; }

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "Target       : $SIZE (x86, NVMe-only) in $REGION, zones [$ZONES]"
echo "------------------------------------------------------------"

# --- NVMe pre-flight: refuse to deploy unless the size actually offers NVMe (no wasted box) ---
dct="$(az vm list-skus --resource-type virtualMachines --size "$SIZE" -l "$REGION" \
  --query "[].capabilities[?name=='DiskControllerTypes'].value | [0]" -o tsv 2>/dev/null)"
echo "DiskControllerTypes($SIZE @ $REGION): ${dct:-<none>}"
case "$dct" in
  *NVMe*) : ;;  # NVMe-only or SCSI,NVMe — good
  *) echo "✗ $SIZE does not offer NVMe in $REGION (got '${dct:-none}') — pick another NVMe size. Aborting."; exit 1 ;;
esac

# --- quota pre-flight ---
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

# --- cloud-init: build dsd from main (x86/amd64). HOME=/root: cloud-init runcmd has no HOME. ---
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

CREATED_VM="" CREATED_ZONE=""
for z in $ZONES; do
  vmname="${VM}-z${z}"
  echo "→ Attempting zone $z (as $vmname)..."
  if az vm create \
       -g "$RG" -n "$vmname" -l "$REGION" --zone "$z" \
       --image "$IMAGE" --size "$SIZE" --disk-controller-type NVMe \
       --admin-username "$ADMIN" --generate-ssh-keys \
       --data-disk-sizes-gb "$DATA_DISK_GB" --data-disk-caching ReadWrite \
       --custom-data "$CLOUDINIT" -o none; then
    CREATED_VM="$vmname" CREATED_ZONE="$z"
    break
  fi
  echo "  ✗ zone $z unavailable — cleaning the partial attempt, trying the next..."
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
✓ $CREATED_VM  ($SIZE, x86 NVMe, zone $CREATED_ZONE)  @ $IP   (data disk ${DATA_DISK_GB}GB, host-caching=ReadWrite)

1) wait for the dsd build (~1-2 min): ssh ${ADMIN}@${IP} 'until [ -f /var/lib/dsd-build-done ]; do sleep 5; done; dsd --help >/dev/null && echo BUILD_OK'
2) confirm NVMe is actually present, then validate (dual-privilege):
     ssh ${ADMIN}@${IP} 'ls /sys/class/nvme; cat /sys/module/nvme_core/parameters/io_timeout'
     ssh ${ADMIN}@${IP} 'sudo dsd health --packages --json' > root.json
     ssh ${ADMIN}@${IP} 'dsd health --packages --json'      > nonroot.json
   (docs/CLOUD_VALIDATION.md §Azure A4: nvme_present should be TRUE; INFO if io_timeout < 60s)
3) capture + destroy:
     ssh ${ADMIN}@${IP} 'sudo dsd capture --raw -o /tmp/azure-${SIZE}.tar.gz'; scp ${ADMIN}@${IP}:/tmp/azure-${SIZE}.tar.gz .
     bash az-validation-vm-destroy.sh
------------------------------------------------------------
EOF
