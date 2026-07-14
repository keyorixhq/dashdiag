#!/usr/bin/env bash
# az-find-region-with-quota.sh — find Azure regions where a given VM size is BOTH
# deployable for this subscription AND has enough vCPU quota headroom to actually launch.
#
# Companion to az-find-deploy-zones.sh: that one answers "is the size offered / not
# restricted here?" (zones + restrictions). This one adds the dimension it doesn't cover —
# live vCPU quota — because a region can be un-restricted yet capped (the fresh-subscription
# wall). A region is reported ✓ only when:
#   1. the size is offered with NO whole-region (Location) restriction, AND
#   2. the size's vCPU family has >= the size's vCPU count free, AND
#   3. the region's Total Regional vCPUs limit has >= that many free.
#
# `az vm list-skus --all` gives the size's family + vCPU count and the restrictions;
# `az vm list-usage -l <region>` gives currentValue/limit per family and the regional total.
# Run in Azure Cloud Shell (Bash) — az + jq are already there.
#
# Usage:
#   ./az-find-region-with-quota.sh [SKU] [REGION ...]
#     SKU       defaults to Standard_D2s_v3 (the dsd cloud-validation primary; see docs/CLOUD_VALIDATION.md)
#     REGION... optional allowlist to scope the scan (faster); omit to scan every region the size is offered in
#
# Examples:
#   ./az-find-region-with-quota.sh                                  # D2s_v3, all offered regions
#   ./az-find-region-with-quota.sh Standard_D2ds_v6                 # the NVMe size
#   ./az-find-region-with-quota.sh Standard_D2s_v3 westeurope eastus northeurope
set -euo pipefail

SKU="${1:-Standard_D2s_v3}"
shift || true
REGION_ALLOWLIST=("$@")

command -v az >/dev/null || { echo "az CLI not found — run this in Azure Cloud Shell (Bash)."; exit 1; }
command -v jq >/dev/null || { echo "jq not found — run this in Azure Cloud Shell (Bash)."; exit 1; }

echo "Subscription : $(az account show --query name -o tsv 2>/dev/null || echo '?')"
echo "VM size      : $SKU"
echo "Region scope : ${REGION_ALLOWLIST[*]:-all offered regions}"
echo "------------------------------------------------------------"

skus_json="$(az vm list-skus --resource-type virtualMachines --size "$SKU" --all --output json)"

# The size's vCPU family (quota join key) and vCPU count, from the first matching record.
read -r FAMILY VCPUS < <(echo "$skus_json" | jq -r --arg sku "$SKU" '
  [ .[] | select(.name == $sku) ] | .[0]
  | "\(.family // "?") \((.capabilities[]? | select(.name=="vCPUs") | .value) // "?")"')

if [[ "$FAMILY" = "?" ]] || [[ -z "${FAMILY:-}" ]]; then
  echo "No record for $SKU — the size name may be wrong or not offered to this subscription."
  exit 1
fi
echo "vCPU family  : $FAMILY     vCPUs per VM : $VCPUS"
echo "------------------------------------------------------------"

# Regions where the size is offered with no whole-region (Location) restriction.
mapfile -t CANDIDATES < <(echo "$skus_json" | jq -r --arg sku "$SKU" '
  .[] | select(.name == $sku)
  | select([ .restrictions[]? | select(.type=="Location") ] | length == 0)
  | .locationInfo[0].location' | sort -u)

# Apply the optional allowlist.
if [[ "${#REGION_ALLOWLIST[@]}" -gt 0 ]]; then
  declare -A want=(); for r in "${REGION_ALLOWLIST[@]}"; do want["$r"]=1; done
  filtered=(); for r in "${CANDIDATES[@]}"; do [[ -n "${want[$r]:-}" ]] && filtered+=("$r"); done
  CANDIDATES=("${filtered[@]}")
fi

if [[ "${#CANDIDATES[@]}" -eq 0 ]]; then
  echo "✗ $SKU is restricted in every region in scope (Location restriction). Request quota/access, or try another size."
  exit 0
fi

echo "Checking vCPU quota in ${#CANDIDATES[@]} candidate region(s) — one list-usage call each, ~1-2s per region..."
echo

ok_regions=()
for loc in "${CANDIDATES[@]}"; do
  usage="$(az vm list-usage -l "$loc" --output json 2>/dev/null)" || { echo "✗ $loc: could not read quota (skipped)"; continue; }

  # Family headroom (limit - currentValue) and regional-total headroom, matched by the
  # quota name (.name.value matches the SKU .family for size families; the regional cap is
  # the "cores" / "Total Regional vCPUs" entry).
  read -r fam_used fam_lim reg_used reg_lim < <(echo "$usage" | jq -r --arg fam "$FAMILY" '
    ([ .[] | select(.name.value == $fam) ] | .[0]) as $f
    | ([ .[] | select(.name.value == "cores" or (.localName // "") == "Total Regional vCPUs") ] | .[0]) as $r
    | "\(($f.currentValue) // "?") \(($f.limit) // "?") \(($r.currentValue) // "?") \(($r.limit) // "?")"')

  if [[ "$fam_lim" = "?" ]]; then
    echo "• $loc: deployable, but no '$FAMILY' quota entry returned (family may be unfamiliar here) — verify manually"
    continue
  fi

  fam_free=$(( fam_lim - fam_used ))
  reg_free=$(( reg_lim - reg_used ))
  if [[ "$fam_free" -ge "$VCPUS" ]] && [[ "$reg_free" -ge "$VCPUS" ]]; then
    echo "✓ $loc: deployable + quota OK  (family $fam_used/$fam_lim → $fam_free free; regional $reg_used/$reg_lim → $reg_free free; need $VCPUS)"
    ok_regions+=("$loc")
  else
    echo "✗ $loc: NO quota  (family $fam_used/$fam_lim → $fam_free free; regional $reg_used/$reg_lim → $reg_free free; need $VCPUS)"
  fi
done

echo "------------------------------------------------------------"
if [[ "${#ok_regions[@]}" -gt 0 ]]; then
  echo "Pick one of: ${ok_regions[*]}"
  echo "Then: az vm create -g dsd-val -n dsd-val --location ${ok_regions[0]} --image Ubuntu2204 --size $SKU ..."
else
  echo "No region has both deployability and free quota for $SKU."
  echo "Request a vCPU quota increase for '$FAMILY' (and/or Total Regional vCPUs) in a deployable region,"
  echo "or fall back to a smaller/different size and re-run."
fi
