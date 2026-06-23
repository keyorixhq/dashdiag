#!/usr/bin/env bash
# az-find-deploy-zones.sh — find the regions / availability zones where a given
# Azure VM size is actually DEPLOYABLE for THIS subscription.
#
# `az vm list-skus --all` is the key: it includes sizes that are restricted for the
# subscription (quota / capacity / not-offered), so the `restrictions` field tells you
# *why* you can't deploy — exactly the wall a fresh subscription keeps hitting.
#
# Run it in Azure Cloud Shell (Bash) — az + jq are already there.
#
# Usage:
#   ./az-find-deploy-zones.sh [SKU] [REGION]
#     SKU     defaults to Standard_D2pls_v5 (Arm64 Ampere, Accelerated-Networking capable)
#     REGION  optional — limit to one region (e.g. northeurope); omit to scan all
#
# Examples:
#   ./az-find-deploy-zones.sh                          # D2pls_v5 everywhere
#   ./az-find-deploy-zones.sh Standard_D2s_v3          # the x86 size, everywhere
#   ./az-find-deploy-zones.sh Standard_D2pls_v5 northeurope
set -euo pipefail

SKU="${1:-Standard_D2pls_v6}"
REGION="${2:-}"

command -v az >/dev/null || { echo "az CLI not found — run this in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run this in Azure Cloud Shell (Bash)."; exit 1; }

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "VM size      : $SKU"
echo "Region scope : ${REGION:-all regions}"
echo "------------------------------------------------------------"

# --size is a name-prefix filter; --all surfaces restricted SKUs (without it they're hidden).
args=(vm list-skus --resource-type virtualMachines --size "$SKU" --all --output json)
[ -n "$REGION" ] && args+=(--location "$REGION")

json="$(az "${args[@]}")"

echo "$json" | jq -r --arg sku "$SKU" '
  [ .[] | select(.name == $sku) ]
  | if length == 0 then
      "No record for \($sku) in this scope — the size is not offered here (try another region, or check the exact size name)."
    else
      sort_by(.locationInfo[0].location)[]
      | .locationInfo[0].location as $loc
      | ((.locationInfo[0].zones // []) | map(tostring)) as $allzones
      # zones blocked for THIS subscription:
      | ([ .restrictions[]? | select(.type=="Zone")     | .restrictionInfo.zones[]? | tostring ]) as $rzones
      # whole-region restriction (e.g. NotAvailableForSubscription):
      | ([ .restrictions[]? | select(.type=="Location") | .reasonCode ]) as $locrestrict
      | (($allzones - $rzones) | sort) as $okzones
      | if   ($locrestrict | length) > 0 then
               "✗ \($loc): RESTRICTED (\($locrestrict | join(","))) — not available to this subscription (request quota/access or use another region)"
         elif ($allzones | length) == 0 then
               "• \($loc): available, NON-ZONAL (no AZ pinning in this region)"
         elif ($okzones | length) == 0 then
               "✗ \($loc): all zones blocked for this subscription (\($rzones | join(",")))"
         else
               "✓ \($loc): deployable in zone(s) \($okzones | join(", "))"
               + (if ($rzones | length) > 0 then "   [blocked: \($rzones | join(","))]" else "" end)
         end
    end
'

echo "------------------------------------------------------------"
echo "Legend: ✓ deployable   • non-zonal (deployable, no AZ choice)   ✗ blocked for this subscription"
echo "If everything is ✗: file a quota/access request for that size's vCPU family,"
echo "or fall back to an x86 AN-capable size (e.g. Standard_D2s_v3) and re-run this."
