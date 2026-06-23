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

## SUSE / cloud-registration depth (`Subscription` collector hardening + new checks)

**Status: demand-gated — build when a real SUSE/PAYG box or a SUSE-running prospect
surfaces.** Checks 1 and 6 are partly buildable/validatable today; checks 2–5 are
SUSE-cloud-specific and have NO local test surface — they can only be built honestly
against a real Azure (or AWS/GCP) PAYG SLES instance that can actually enter a broken-
registration state. That makes the metered cloud VM the *only* validation path, not
speculative tooling — but it is still gated on a real pull (a capture that breaks, or a
prospect on SUSE).

**Demand signal (external, verified):** Azure's VM-support taxonomy carries a dedicated
"Kernel Upgrades, Package Management (Yum, Zypper, RPM, DPKG, APT)" escalation lane.
Digging into *why* SUSE specifically loads that lane: most Azure SLES images are **PAYG**,
which do NOT update from public repos — they register on first boot against an Azure-IP-
locked, attestation-gated, DNS-invisible private update infrastructure. Any drift in the
billing-attestation metadata, the `cloud-regionsrv-client` packages, or the network egress
path silently breaks `zypper`, and the box quietly stops receiving security updates. The
same failure class is documented identically for AWS and GCP PAYG SLES — so these checks
have cross-cloud value, not Azure-only. (Refs: MS Learn suse-public-cloud-connectivity-
registration-issues; SUSE "Public Cloud Update Infrastructure 101"; GCP/AWS SLES PAYG docs.)

### What already exists (do NOT rebuild)

`SUSEConnectCollector` (suseconnect_collector.go, check name `Subscription`) already does
check #1 across SUSE (`SUSEConnect`), RHEL/Oracle/Rocky/Alma (`subscription-manager`), and
Ubuntu Pro (`pro`). The SUSE false-OK bug — unregistered "Not Registered" misread as
registered — was already found live on openSUSE Leap 15.6 and is guarded by
`suseconnect_parse_test.go`. So #1 is a HARDENING target, not a greenfield build.

### The six checks (priority order = strength of demand evidence × host-visibility)

**1. Registration status — EXISTS, harden.** `SUSEConnect --status-text`/cloud-register
state → Registered / Not-registered / Invalid-credentials (422). Highest-value signal: a
not-registered or 422 box silently cannot receive security updates. Couldn't-measure rule
(already partly honored): SUSEConnect absent, or a chost image that omits it, must read as
*unknown*, NEVER as registered. Hardening work: surface the 422/attestation-failure state
as a distinct verdict (today it likely collapses to generic not-registered), and add the
expiry-window WARN.

**2. Repository reachability + staleness — NEW.** Can `zypper` actually refresh, and do
configured repos resolve? Real symptom is `zypper ref` throwing "Error retrieving metadata
… script died unexpectedly" / "Resource temporarily unavailable" — a network/attestation
failure masquerading as a transient error. dsd verdict "repos defined but unreachable"
turns a cryptic zypper stack trace into a diagnosis. Couldn't-measure: no zypper / not
SUSE → not-applicable (omit, per the normal rule — this is genuinely n/a, unlike #1's
unknown).

**3. Cloud-registration package currency — NEW, predictive.** Is `cloud-regionsrv-client`
+ the Azure plugin (`cloud-regionsrv-client-plugin-azure`, `regionServiceClientConfigAzure`)
present and not ancient? Stale versions are the root cause of the "instance became
incompatible with the update-infrastructure API" trap — registration looks fine today but
will break. Genuinely predictive: catches the failure before it bites.

**4. PAYG-vs-BYOS consistency — NEW.** Detect licensing mode and flag dangerous mixed
states. Registering a PAYG instance against SUSE Customer Center (instead of the cloud
update infra) creates conflicts that aren't easily solved; a box showing both PAYG billing
and SCC registration is a catchable misconfiguration.

**5. Update-path egress sanity — NEW, guest-visible slice of a network problem.** Is the
instance's egress IP in an Azure range, or is traffic forced through a proxy / on-prem
route / NAT that will black-hole the (DNS-invisible) update servers? dsd can't fix routing
but can say "your update path looks redirected" — the diagnosis that currently needs a
support ticket. Scope carefully: this is host-visible egress inference, NOT network-
control-plane territory (stay inside the network-free principle).

**6. Package-DB / lock health — NEW, cross-distro, validatable TODAY.** Stale zypper locks,
locked packages, rpm/dpkg DB corruption — all silently block updates. Generalizes across
the entire "Yum, Zypper, RPM, DPKG, APT" menu item, so it earns its keep on every Linux
host, not just SUSE. This is the one check with a local test surface right now: CentOS 7
EOL box (yum/rpm), Debian boxes (dpkg/apt), AlmaLinux CT213.

### Validation environment per check

| Check | Validatable today? | Needs |
|---|---|---|
| 1 Registration status | partly (openSUSE Leap, unregistered path tested) | real PAYG SLES for the 422/registered-active states |
| 2 Repo reachability | no | PAYG SLES, ideally one with broken repos |
| 3 Cloud-pkg currency | no | PAYG SLES (old image to see the stale case) |
| 4 PAYG/BYOS consistency | no | PAYG SLES + a BYOS SLES for contrast |
| 5 Egress sanity | no | PAYG SLES behind a proxy/UDR to see the broken case |
| 6 Package-DB/lock health | YES | CentOS 7 EOL, Debian 12, AlmaLinux CT213 |

Dual-privilege run applies (registration/repo reads may need root). The metered Azure SLES
VM is a time-boxed capture session, not a standing box: deploy PAYG SLES + (for contrast)
openSUSE Leap and a BYOS SLES, capture both privilege levels, tear down. The capture is the
durable artifact (replayable per ADR-0003); the VM is disposable. SLES carries a per-hour
software charge on top of compute — capture, don't camp.

### Effort

Check 6 alone: ~0.5–1 day, buildable now. Checks 1-hardening + 2–5: ~2–3 days once a real
PAYG SLES capture exists, most of it being the capture session and per-state validation,
not code. Do NOT build 2–5 from this spec — build the one a real broken SUSE box or a
SUSE-running prospect actually pulls for.

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
insight). This is the *deep* per-cloud surface. **Status: AWS + Azure high-value cores both
SHIPPED (v1.6.0 / v1.7.0+#450); only the full-coverage tails remain, demand-gated.** Build
the specific check a cloud customer/contact pulls for.

### AWS (Nitro/EC2) — ✅ high-value core SHIPPED (v1.6.0, #443)
`AWSCollector` (`internal/collectors/aws_linux.go`), gated on EC2 DMI, wired into health.
Validated live on Graviton arm64 (t4g) + x86 (t3) — see memory `aws-deep-checks-collector`.
1. ✅ ENA driver presence + version health
2. ✅ ENA bandwidth/PPS allowance exhaustion (`ethtool -S` allowance-drop counters)
3. ✅ EBS/NVMe silent-throttle (0xD0 vendor log-page)
4. ✅ IMDS reachability + v1-vs-v2 enforcement posture
5. ✅ Time-sync via Amazon Time Sync / chrony source
6. ✅ instance-store vs EBS distinguished in device detection
Bonus beyond the original spec: SSM agent install/run state, spot-rebalance recommendation.

### AWS — full coverage tail (demand-gated, build-on-pull only)
ENA SR-IOV/express status, Nitro enclave presence, placement-group signals, cloud-init/
cloud-config validation, EBS volume-type/IOPS-vs-workload mismatch. Treadmill — not a
state to "finish."

### Azure (Hyper-V) — ✅ core SHIPPED (v1.7.0 #444 + #450)
`AzureCollector` (`internal/collectors/azure_linux.go`), gated on Azure DMI, wired into
health. Validated live on x86 D2s_v3 + arm64 Ampere D2pls_v5 — see memory
`azure-deep-checks-collector`.
1. ✅ Accelerated Networking active vs silent fallback to synthetic netvsc
2. ✅ Mellanox VF (SR-IOV) driver health
3. ✅ Dynamic Memory (hv_balloon) detection + kernel-logged ceiling (#450). NOTE:
   ballooning *pressure* is deliberately not claimed — no reliable guest-side counter.
4. ✅ Managed-disk host-cache hazard — data disk with ReadWrite caching, via IMDS
   storageProfile (#450)
5. ✅ Temp/resource-disk detection + persistent-data-on-ephemeral WARN (#450)
6. ✅ Scheduled-events (maintenance/eviction) — fixed the CloudMeta precedence bug +
   all event types (#450)
7. ✅ WAAgent health (cloud-init covered by the shared `CloudInitCollector`)
   ✅ Time-sync via Hyper-V PTP

> ⚠️ The #450 IMDS-derived checks (4 host-cache, 6 scheduled-events) and the
> ballooning detection are unit-tested but **not yet live-validated** — they parse
> Azure IMDS JSON whose exact shape needs confirming on a real Azure VM (root +
> non-root, x86 + arm64) before they are fully trusted. See `azure-deep-checks-collector`.

### Azure — full coverage tail (demand-gated)
netvsc synthetic/VF transition detail, host-cache vs disk-cache, Azure NVMe timeout tuning.

### What's left
- **Shipped:** AWS core (6/6 + bonuses); **Azure core (6/6 + WAAgent + PTP)** — both clouds'
  high-value cores are now complete.
- **Remaining (tail, treadmill):** the full-coverage lists above only — clouds ship new
  instance types/drivers constantly, so this is never a state to "finish."
- One open follow-up (not new build): **live-validate the #450 Azure IMDS/ballooning
  checks** on a real Azure VM before trusting their verdicts.
- Approach unchanged: build NONE of the tail speculatively; when a cloud customer pulls,
  build the single check asked for.

---

## Notes / cross-refs
- Hardware-validation gaps (server-grade ECC/IPMI/NUMA, ARM, x86 metal, SteamOS, vSphere)
  are tracked in `docs/PLATFORM_COVERAGE.md` under "Known validation gaps" — also demand-gated.
- Cross-platform fix-hint bug (systemd hints on non-systemd hosts) is BUG-053/054 in `BUGS.md`.
