# Backlog

Demand-gated feature/collector work. **Hard rule: no new collectors before first paying
customer.** Items here are specced so they're ready to build *when a customer or contact
pulls for them* — not a build queue. When demand appears, build the specific check that
demand asked for, not the whole list.

Effort estimates use observed velocity: a well-scoped single collector/check, following
existing patterns, with a real test target, is roughly **0.5–1 day** including tests and a
real-hardware/real-platform capture. "High-value core" items are the ones that map to real
production incidents people would actually diagnose.

---

## Cloud-depth collectors (AWS / Azure)

Analog to the existing VMware guest depth (ballooning, vmxnet3/e1000, SCSI timeout).
Basic cloud *detection* already works and is validated (AWS + Azure captures, NVMe-timeout
insight). This is the *deep* per-cloud surface. **Status: demand-gated — no cloud customer
yet.** Build the specific check a cloud customer/contact pulls for.

### AWS (Nitro/EC2) — high-value core (~5–6 checks, ~3–4 days)
1. ENA driver presence + version health (missing/old ENA = degraded networking)
2. ENA bandwidth/PPS allowance exhaustion (`ethtool -S` allowance-drop counters = throttling)
3. EBS/NVMe latency + queue-depth under throttle
4. IMDS reachability + v1-vs-v2 enforcement
5. Time-sync via Nitro PTP / chrony source
6. (stretch) instance-store vs EBS detection

### AWS — full coverage (additional ~6–10 checks, ~4–6 more days)
ENA SR-IOV/express status, Nitro enclave presence, placement-group signals, cloud-init/
cloud-config validation, EBS volume-type/IOPS-vs-workload mismatch, ENA-express, etc.

### Azure (Hyper-V) — high-value core (~5–7 checks, ~3–4 days)
1. Accelerated Networking active vs silent fallback to synthetic netvsc (perf-critical)
2. Mellanox VF (SR-IOV) driver health
3. Dynamic Memory / ballooning pressure detection (Hyper-V — real, unlike modern Nitro)
4. Managed-disk cache-mode mismatch (ReadOnly/ReadWrite/None vs workload)
5. Temp-disk (/dev/sdb) detection + "don't store data here" warning
6. Scheduled-events metadata (maintenance/eviction warnings)
7. WAAgent / cloud-init health

### Azure — full coverage (additional ~5–8 checks, ~4–5 more days)
netvsc synthetic/VF transition detail, host-cache vs disk-cache, Azure NVMe timeout tuning,
time-sync via Hyper-V PTP, etc.

### Totals
- **High-value core (both clouds): ~10–13 checks, ~6–8 days** of build+test.
- **Full coverage (both clouds): ~25–35 checks, ~15–20 days.**
- Recommended approach: build NONE until demand; then build the single check pulled for,
  let the customer reveal which of the core matters, build those first. Full coverage is a
  treadmill (clouds ship new instance types/drivers constantly) — not a state to "finish."

---

## Notes / cross-refs
- Hardware-validation gaps (server-grade ECC/IPMI/NUMA, ARM, x86 metal, SteamOS, vSphere)
  are tracked in `docs/PLATFORM_COVERAGE.md` under "Known validation gaps" — also demand-gated.
- Cross-platform fix-hint bug (systemd hints on non-systemd hosts) is BUG-053/054 in `BUGS.md`.
