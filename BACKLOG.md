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

## Post-unexpected-reboot forensics (`PostBoot` collector)

**Status: demand-gated — build when a real unexpected-reboot post-mortem surfaces**
on a test host or a prospect node. Do NOT build speculatively (Principle 3). The
source-availability scaffolding (`internal/collectors/postboot_source_linux.go`)
is drafted so the build is short when demand arrives; the scaffold is NOT a build
trigger.

**Demand signal (external):** Azure's own VM-support taxonomy carries dedicated
escalation paths for *"VM restarted or stopped unexpectedly"* and *"My VM is not
booting"* — i.e. the cloud's own triage tree confirms operators hit this often
enough to warrant a named flow. That's evidence of real demand for a host-level
verdict, not a reason to build now. Build on a concrete pull.

### Problem it solves

After a host reboots unexpectedly and comes back up, the operator's question is
"what killed it, and was it the box or the platform?" Azure's flow can't see
inside the guest; `dsd` can. The win is a seconds-to-verdict post-mortem from the
host's own durable records — the cleanest fit for the "OBD for your server" pitch.

### What makes this distinct from existing collectors (NOT a duplicate)

- `OOMCollector` (oom_linux.go) reads OOM events from the **current** boot's last
  24h. PostBoot reads **boot -1** (`journalctl --boot=-1`). Reuse `parseOOMEvents`
  against the prior boot; do not re-implement it.
- `TimelineCollector` (timeline_linux.go) builds a current-boot incident timeline.
  PostBoot reuses the journal/dmesg event readers but scopes them to the prior
  boot and asks a different question: cause-of-stop, not chronology.
- Net new: the **cross-boot source-availability trichotomy** — the hard,
  load-bearing part, already drafted.

### The core design property (this is the whole point)

Post-reboot forensics INVERTS the standing "not-applicable collector → omit, never
phantom OK" rule (json.go, COMPATIBILITY.md §checks[]). Across a reboot boundary,
the most common outcome is that the evidence **physically no longer exists**
(volatile journald — the default on many cloud/minimal images). That absence is
the headline finding and must be LOUD. Three states stay distinguishable:

- **FOUND** — read boot -1; forensics returns findings or a clean "nothing
  notable" (a real healthy result).
- **ABSENT** — no prior boot on record (first boot). Real, not a failure; verdict
  must say "no prior boot on record", never imply a clean shutdown we didn't see.
- **UNMEASURABLE** — could not look (volatile journald / EACCES / non-systemd with
  no wtmp). Surfaces as INFO/WARN, **never OK, never omitted.**

This is the same honesty already shipped in `OOMCollector.StatusReason` ("kernel
log unreadable") and `TimelineInfo.SourcesUnavailable` — extended across the
reboot boundary, where it matters most.

### What it checks (boot -1)

| Check | Source | Couldn't-measure case |
|---|---|---|
| Last shutdown clean vs unclean | journal `shutdown.target` reached; wtmp gap | volatile journald → wtmp-only (coarse) |
| OOM kill in prior boot | `journalctl --boot=-1 -k` via `parseOOMEvents` | journal unreadable → UNMEASURABLE |
| Kernel panic / oops in prior boot | journal `--boot=-1` priority≤3, panic/oops regex | no persistent journal → can't see boot -1 |
| Thermal critical / throttle in prior boot | journal thermal events | same |
| Filesystem journal-replay at THIS boot | current dmesg "EXT4-fs … recovery"/xfs replay | (current-boot signal — always readable) |
| Hardware reset signature | IPMI SEL via existing ipmi_linux.go, if BMC present | no /dev/ipmi → "no BMC; can't confirm/deny" |

The fs-journal-replay row is deliberately a **current-boot** signal (the replay
happens at THIS mount), so it's available even when boot -1 isn't — a useful
corroborating "the last stop was hard" tell when the journal is volatile.

### Output

New subcommand surface `dsd health --since-boot` (or a `PostBoot` check folded
into `dsd health`, TBD by how it reads in practice). Verdict text states
provenance and stops at findings, never inferences: "host stopped because it ran
out of memory; the OOM killer reaped <proc> at <ts>" — NOT "your app has a memory
leak." The `--json` projection uses the frozen top-level shape (verdict/counts/
checks[]/insights[]); the UNMEASURABLE case emits a real INFO/WARN insight, so it
is never the omitted-collector path.

### Test targets (real hardware/platforms, per methodology)

- **CentOS 7 EOL box** (tenant `vcd-msk-3`) — default journald storage differs
  from modern systemd; good for exercising the volatile/persistent split.
- **khhv01** (AMD EPYC Proxmox) — real BMC/IPMI present, exercises the hardware-
  reset row and the "no BMC" couldn't-measure path by contrast with VMs.
- **Alpine CT210** (OpenRC) — the non-systemd / wtmp-only / fully-blind branches.
- A host with `Storage=volatile` journald — the headline UNMEASURABLE path; must
  render LOUD, not as empty-OK.

Dual-privilege run is mandatory here: root sees boot -1; non-root may legitimately
report `journal_unreadable`. Both together are the honest picture.

### Effort

~1–1.5 days once pulled: the source trichotomy is drafted and unit-testable
against fixtures; the readers are reuse; the new work is the boot -1 scoping, the
panel/insight wiring, and four real-target captures.

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
