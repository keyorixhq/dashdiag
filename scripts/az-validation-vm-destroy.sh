#!/usr/bin/env bash
# az-validation-vm-destroy.sh — delete the dsd cloud-validation resource group (VM, disk,
# NIC, public IP, NSG — everything az-validation-vm-create.sh made). FLAGLESS: paste into
# Azure Cloud Shell (Bash) and run, or:
#
#   curl -fsSL https://raw.githubusercontent.com/keyorixhq/dashdiag/main/scripts/az-validation-vm-destroy.sh | bash
#
# Capture your dsd bundle FIRST — this is irreversible and the VM is metered, so run it as
# soon as validation is done.
set -euo pipefail

RG=dsd-val

command -v az >/dev/null || { echo "az not found — run in Azure Cloud Shell (Bash)."; exit 1; }

if ! az group show -n "$RG" -o none 2>/dev/null; then
  echo "Resource group '$RG' does not exist — nothing to delete."
  exit 0
fi

echo "Deleting resource group '$RG' (VM, disk, NIC, public IP, NSG)..."
az group delete -n "$RG" --yes --no-wait
echo "Teardown started (async). Confirm it's gone with:  az group show -n $RG   (should 404)."
