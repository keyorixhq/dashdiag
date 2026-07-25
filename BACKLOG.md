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

## DESIGN NOTE: Cloud-PAYG-update-infra health — the four-question model

**This is a concept formalization, NOT a build authorization.** It writes down the shared
abstraction that the SUSE and RHEL specs below are both instances of, plus the per-distro
mapping table, so that whoever builds any one backend does it in a shape the others can
later share. It explicitly does NOT define an interface or authorize a framework — see
"What to formalize when" at the end. No code follows from this note alone.

### Why this exists

Research across Azure (and AWS/GCP) shows the update-infra brittleness is a CLASS, not a
per-distro quirk. Every commercial distro on a cloud uses the same PATTERN: it does not
update from public repos; it updates from a cloud-operated, IP-locked, entitlement-gated
private infrastructure, and drift in entitlement / config / network silently stops updates
— the box looks healthy while quietly missing security patches. The distros differ only in
WHICH file or command answers each question, not in the questions.

### The four questions (distro-independent)

Every cloud-PAYG host answers the same four. A health surface asks all four; the backend
fills in the distro-specific probe:

  Q1. ENTITLED?     Am I registered / entitled to an update source at all?
  Q2. REACHABLE?    Can I actually reach that source right now? (the IP-lock + proxy/UDR class)
  Q3. EXPIRING?     Is my entitlement going to lapse? (the predictive, silent-time-bomb class)
  Q4. CONSISTENT?   Am I misconfigured in a way that silently breaks updates or double-bills?

Q3 is the one with unique product value: it is host-visible, network-free, and PREDICTIVE
— a dated artifact on disk that will break updates on a known future day. The RHUI cert
(RHEL R2) is the cleanest instance and the strongest single build candidate in this surface.

### Per-distro mapping table (the formalization; also the capture-session grading grid)

Each captured box fills/confirms one column. "?" = unverified, resolve from a real capture.

| | SUSE (SLES PAYG) | RHEL (PAYG) | Oracle Linux (PAYG) | CentOS (OpenLogic) | Ubuntu (PAYG/Pro) |
|---|---|---|---|---|---|
| **Q1 Entitled** | `SUSEConnect --status-text` / cloudregister state | `subscription-manager status` + RHUI cert present | preconfigured Oracle public yum (no registration) | OpenLogic repos (no registration) | `pro status` attach state |
| **Q2 Reachable** | `zypper ref` (script-died / 422) | `yum/dnf check-update` (curl#56 / no-mirrors) | `yum check-update` | `yum check-update` | `apt update` |
| **Q3 Expiring** | subscription `expires_at` | **RHUI client cert enddate** (`/etc/pki/rhui/*.pem`, ~2yr) | (none — public yum, no client cert) | (none) | Pro contract expiry |
| **Q4 Consistent** | PAYG+SCC double-register conflict; stale `cloud-regionsrv-client` | PAYG+RHSM double-billing; `rh-cloud.repo` enabled; EUS/non-EUS releasever lock | `/etc/yum/vars/ociregion` must be EMPTY | `/etc/yum/vars/releasever` must NOT exist | (mild) |
| **Couldn't-measure** | no SUSEConnect/chost image → unknown | non-root cert unreadable → unknown | n/a if not OL PAYG | n/a if not CentOS | no `pro` → unknown |
| **Brittleness** | high (attestation-gated) | high (cert-expiry adds a time bomb) | low-med | low-med (EOL is the real issue) | low (public mirrors) |

Cross-cloud note: Q1/Q2 failure modes are documented IDENTICALLY on AWS and GCP (different
endpoints, same IP-lock + entitlement pattern). The abstraction is cloud-independent; only
the egress-range list in Q2 is cloud-specific.

### How this maps onto existing code (proven pattern, do NOT reinvent)

Two existing structures already implement "detect platform, dispatch per-backend, return a
common model" — the shape this surface wants, arrived at by accretion from real cases:

- `SUSEConnectCollector` (`Subscription` check) already dispatches Q1 across SUSE/RHEL/
  Ubuntu by binary presence, returning one `SUSEConnectInfo`. That IS the Q1 backend
  dispatch, already built and (for SUSE) tested.
- `AWSCollector` / `AzureCollector` (shipped v1.6.0/v1.7.0) already do cloud DMI-detection +
  gated wiring into health. That IS the "which cloud am I on" detection the Q2 egress-range
  check needs — reuse it, don't rebuild cloud detection.

So the eventual surface is NOT greenfield architecture: it's Q1 (exists) + three more
questions routed through the same dispatch idiom, reusing the same cloud-detection the
cloud-depth collectors already ship.

### What to formalize WHEN (the discipline line)

- **NOW (this note):** the four-question model + the mapping table. Pure concept + evidence.
  Zero code, zero risk. Makes every future backend build coherent and shareable.
- **NOT now:** a `CloudUpdateInfra` interface, backend registry, or dispatch framework.
  Building the abstraction before two real backends are validated would encode GUESSES
  about how RHEL/Oracle/CentOS fail into an interface shape, which every real capture would
  then fight. One backend is too few to factor from (you abstract its quirks); the right
  shape is DISCOVERED from ≥2 concrete validated cases — exactly as `SUSEConnectCollector`
  discovered its shape from SUSE-then-RHEL-then-Ubuntu, not by up-front design.
- **LATER (interface, only after the Azure capture session validates ≥2 backends):** factor
  the common Q1–Q4 shape out of the real SUSE + RHEL backends once both are proven. The
  capture session is what produces those concrete cases; the interface follows the evidence.

This mirrors the project's core lesson — real hardware surfaces bugs synthetic tests miss —
applied to design: real backends surface the right abstraction; designing it from research
surfaces a plausible-looking wrong one.

### Cross-refs
- SUSE backend detail: "SUSE / cloud-registration depth" (below).
- RHEL backend detail: "RHEL / RHUI depth" (below).
- Capture/validation: `dashdiag-private/planning/AZURE_SLES_CAPTURE_RUNBOOK.md` (the session
  that produces the ≥2 validated backends this note defers the interface to).

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

**6. Package-DB / lock health — ✅ SHIPPED (#457), cross-distro.** In the Packages
collector: an interrupted dpkg (apt, via `dpkg --audit`) or an unreadable/corrupt rpmdb
(dnf/yum/zypper — all rpm-based, via `rpm -q rpm` with a transient-lock retry) silently
blocks EVERY update; WARN + the update count is marked untrustworthy. Runs even when the
package query itself fails (a blocked DB is the cause), folding that into `query-failed`.
**Live-validated on Debian + AlmaLinux 9 + openSUSE Leap 16** (pve01 matrix) — which
caught 3 issues units missed: an rpm fresh-boot false-positive (fixed via retry), db-health
being dropped when the query errored (fixed), and that a stale `/run/zypp.pid` does NOT
block modern libzypp (so the zypper-lock check was dropped as a false alarm; zypper routes
through the rpmdb probe instead). The positive/corruption path is unit-tested, not induced
live (destructive).

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

**Status: ✅ SHIPPED (#459).** `PostBootCollector` (`internal/collectors/postboot_linux.go`)
on the source-availability scaffold: reads boot -1 for unclean shutdown / OOM / kernel
panic, with the FOUND/ABSENT/UNMEASURABLE trichotomy surfaced loud (a missing prior boot is
the headline, never a silent OK). Gated on a readable cross-boot source (journal or wtmp),
wired into health, quiet when the prior boot was clean. **Live-validated** on Debian /
AlmaLinux / openSUSE / Alpine (pve01) — caught + fixed 3 issues (journalctl --grep
exit-on-no-match → tail-scan; wtmp falsely claiming OOM/panic-clean → disclosed unavailable;
unclean verdict confirmed both ways on real hosts). Deferred follow-ups (not gaps): IPMI/BMC
hardware-reset corroboration row, fs-journal-replay-at-this-boot row.

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

## Cloud-depth collectors (AWS / Azure / GCP)

Analog to the existing VMware guest depth (ballooning, vmxnet3/e1000, SCSI timeout).
Basic cloud *detection* already works and is validated (AWS + Azure captures, NVMe-timeout
insight). This is the *deep* per-cloud surface. **Status: AWS, Azure, and GCP guest-side
collectors all SHIPPED (cores + the guest-visible tail). What remains is genuinely NOT
guest-buildable — it lives in the cloud control plane and would need the provider API,
which dsd's architecture forbids (guest-side, network-free, no cloud creds).**

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

### AWS — full coverage tail
- ✅ **Nitro Enclaves** presence + allocator service (#453, recognition)
- ✅ **ENA Express / SRD** active detection via `ethtool -S ena_srd_*` (#453, recognition)
- ❌ NOT guest-buildable (control-plane only — need the EC2 API, out of scope): placement-group
  signals, EBS volume-type / IOPS-vs-workload mismatch, provisioned-IOPS. cloud-init/cloud-config
  validation is already covered by `CloudInitCollector`. These are not gaps — building them
  guest-side would mean shipping a guess, not a check.

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

### Azure — full coverage tail
- ✅ **NVMe `io_timeout` tuning** — INFO when the low 30s default is set on an NVMe VM (#454)
- (already covered, not duplicated) netvsc synthetic/VF transition = the v1.7.0 AN check;
  managed-disk host-cache = the #450 caching check.

### GCP (Google Compute Engine) — ✅ SHIPPED (#452)
`GCPCollector` (`internal/collectors/gcp_linux.go`), gated on the GCE DMI product name,
wired into health — the GCP analog of AWS/Azure, closing the last detection-only cloud.
1. ✅ NIC driver gVNIC (gve) vs virtio_net — recognition context
2. ✅ Google guest agent installed-but-not-running → WARN (SSH-key / OS-Login break)
3. ✅ Host-maintenance policy — WARN on TERMINATE for a non-preemptible VM; in-progress
   maintenance-event → WARN
4. ✅ OS Login enabled — recognition context
5. ✅ Time-sync on the metadata server — INFO if not
- ❌ NOT guest-buildable (control-plane only): per-disk performance tier / provisioned IOPS,
  placement policy. Same EC2-API-equivalent limitation.

### What's left
- **Shipped:** AWS (core 6/6 + bonuses + tail), Azure (core 6/6 + WAAgent + PTP + tail),
  GCP (full collector). All three clouds' guest-side surface is complete.
- **Genuinely remaining = nothing guest-buildable.** The leftover per-cloud items
  (placement groups, EBS/PD volume-type & provisioned IOPS, etc.) are control-plane state
  that needs the provider API — out of scope by design, not a gap.
- **Open follow-up (not new build) — LIVE VALIDATION debt.** Unit-tested but not yet
  confirmed on real VMs: the #450 Azure IMDS/ballooning checks, the GCP metadata-derived
  checks (#452), the AWS ENA-Express SRD counters (#453), and the Azure NVMe io_timeout
  units/threshold (#454). Validate on real VMs (root + non-root) before the verdicts are
  fully trusted — classic parser-vs-reality risk.

---

## SSDLC — build & CI hygiene (NOT collector work; not subject to the demand-gate)

Process/toolchain items that harden the build and release, not shippable checks. The
collector demand-gate above does NOT apply here — this is baseline hygiene, adopted because
it is cheap and always-on, not because a customer pulled for it. (Distinct from Principle 3,
which gates *feature/collector* builds on real demand.)

### govulncheck — dependency vuln scanning ✅ DONE (2026-07-04, #700/#701)

**Status:** fully wired — local pre-push hook step, CI `pull_request` gate, and the weekly
schedule all live and green. Both remaining sequencing steps below shipped in #700.

**2026-07-04 finding while wiring the PR gate:** `security.yml` was **manually disabled at the
GitHub Actions level since 2026-05-14** (`state: disabled_manually` via the API) — despite the
file itself being correct, it had not run once in ~2 months, on push-to-main or the weekly
schedule, silently voiding this whole section's "CI already runs govulncheck" claim. Re-enabled
via `gh api --method PUT .../workflows/security.yml/enable` (#701). Its first live run then
found two real reachable stdlib CVEs (GO-2026-5039 `net/textproto`, GO-2026-5037 `crypto/x509`),
both fixed in Go 1.26.4 but present in the 1.26.3 `go.mod`/`go.work` pinned — CI had been
building every PR against a vulnerable toolchain. Bumped both files to 1.26.4. Lesson: a
correctly-written CI workflow file proves nothing about whether the workflow is actually
running — check `gh api repos/.../actions/workflows/<file>` for `state` too.

**2026-07-04, follow-up — closed the *class* of bug, not just the instance:** bumping go.mod to
1.26.4 fixed the immediate CVEs but left the same trap armed — the next stdlib CVE fix in 1.26.5
would go unnoticed again until someone manually re-bumps go.mod. All three workflows'
`actions/setup-go` steps (`ci.yml` ×7, `release.yml`, `security.yml`) switched from
`go-version-file: 'go.mod'` (installs go.mod's literal patch) to a floating `go-version: '1.26'`
(always installs the latest 1.26.x patch). go.mod's `go` directive is a minimum-language-version
floor, not an exact pin, so a newer installed patch is always compatible — CI now auto-tracks
security fixes without a go.mod bump in the loop at all.

**Baseline run (local):**
- govulncheck v1.5.0, Go 1.26.4, DB @ vuln.go.dev updated 2026-06-26
- `govulncheck ./...` → *No vulnerabilities found*, exit 0
- Expected: small dep tree + source-mode call-graph reachability = low/zero noise. When it
  does fire it means a vuln on a path dsd actually reaches — not a bare CVE match.

**Sequencing — baseline-then-gate (deliberate, do NOT reorder):**
govulncheck exits non-zero on any *reachable* vuln. Gating before a clean baseline exists
risks blocking every merge over untriaged findings. Order:
  1. local manual run → confirm clean  ✅ (done)
  2. CI on push-to-main + weekly schedule  ✅ (shipped in `security.yml`, and confirmed actually
     enabled/running as of 2026-07-04 — see the finding above)
  3. add to pre-push hook (beside gosec/semgrep; `set -e` supplies the gating)  ✅ (#700)
  4. add a `pull_request` trigger to `security.yml` so PRs are gated pre-merge  ✅ (#700)
  5. mark the PR govulncheck check required in branch protection AFTER a few green PRs  ✅ (2026-07-04)

**2026-07-04 — went further than step 5 alone:** `main` had **no branch protection at all** —
zero required checks, no restriction on force-push or branch deletion. Set up full protection:
all 15 current CI checks required (the full suite, not just `security`), `strict: true`
(branch must be up to date before merge), force-push and deletion blocked, `enforce_admins:
true` (no bypass, including for the repo owner), no required PR-review count (solo-maintainer
self-merge preserved — matches the existing branch→PR→merge workflow, doesn't add a new gate
beyond "CI is green").

**Why local AND CI, not one:** reachability verdicts have a time dimension. A future run can
flag a vuln with zero change to `go.mod` — the dep didn't move, the DB gained an entry. The
pre-push hook gives fast local feedback; CI catches the DB-moved-between-push-and-merge case
the local run structurally cannot see. Already implemented as `security.yml`'s weekly cron —
the header comment there records exactly this rationale.

**Ops notes:**
- Binary installs under `$(go env GOPATH)/bin`; that dir is NOT on the interactive PATH here —
  the pre-push hook must resolve it via `$(go env GOPATH)/bin/govulncheck` (a bare
  `command -v govulncheck` guard would silently skip it, defeating the check).
- Build-time egress only (fetches the DB from vuln.go.dev at scan time). Does NOT touch the
  network-free *runtime* guarantee — it is the build box reaching out, not dsd. An air-gapped
  local-DB mode exists; defer until something demands it.

**Handoff:** the pre-push hook step + the `security.yml` `pull_request` trigger are tree
mutations → Claude Code, per the planning/code split. Hook step mirrors the existing
golangci-lint/semgrep skip idiom but resolves the binary by full GOPATH path. CI needs no new
action — reuse the existing `go install …@latest` + `go-version-file: go.mod` shape.

### Related SSDLC candidates

**Status as of v1.17.2 (2026-07-06): the whole list below is done or explicitly
deferred by choice.** No open, un-actioned SSDLC gap remains.

- **CodeQL + OpenSSF Scorecard** — ✅ shipped (`codeql.yml`, `scorecard.yml`), both
  confirmed actually running (not just present as files — `state: active` via
  the API) and re-verified clean post-SHA-pinning (below). Live Scorecard pull
  (2026-07-05): 5.5/10 — the low sub-scores are either structural for a
  solo-maintainer repo (`Code-Review`/`Contributors`/`Maintained` — nothing to
  fix without a second reviewer or more repo age) or already-addressed
  (`Signed-Releases` was stale at pull time, predating minisign activation;
  resolves itself on the next scored release).
- **GitHub Actions pinned to commit SHA** — ✅ DONE (PR #721, 2026-07-05). The
  note that used to live here said this was "a deliberate house style, don't
  fix it" — that was wrong the moment Scorecard's `Pinned-Dependencies` check
  was actually read (it scored 0). Every third-party Action across all 5
  workflow files now pins to a full SHA with the version kept as a trailing
  comment (`@<sha> # v7`); Dependabot's existing `github-actions` ecosystem
  config already understands and auto-bumps this format. Verified working on
  both PR-triggered *and* push-to-main-only workflows (`codeql.yml`/
  `scorecard.yml` never run on a PR, so their pinning could only be proven
  post-merge — confirmed clean).
- **Fuzz the SMART / os-release / /proc parsers** — ✅ DONE (2026-07-04,
  `FuzzParseOSRelease`), confirmed-clean regression coverage, not a live bug
  fix at the time. Superseded in scope by the continuous fuzzing rig below,
  which since found a real bug in a sibling parser.
- **Verifiable release artifacts for enterprise pre-pilot security review** —
  ✅ DONE, all three legs, all built on the existing `release.yml` (never
  adopted GoReleaser or cosign):
  - **Signing** (minisign, PR #717): `internal/selfupdate.MinisignPublicKey`
    embedded; `dsd update`/`install.sh` fail closed on an unsigned release.
  - **Provenance** (PR #706): `actions/attest-build-provenance`, SLSA-style,
    no key to protect.
  - **SBOM** (PR #721): one source-level `dist/dsd.spdx.json` via `syft
    dir:.` (CGO_ENABLED=0 means identical deps across all 4 platform
    binaries, so one SBOM covers the release, not four copies).
  - All three verified end-to-end on the **first real release to carry them**
    (v1.17.2, 2026-07-06) — not just "the workflow didn't error": downloaded
    the actual release artifacts and ran `sha256sum -c`, `minisign -Vm`, and
    `gh attestation verify` against them for real.
  - **One real bug shipping this**: `apt-get install minisign` doesn't exist
    on `ubuntu-22.04` even with `universe` enabled — the first `v1.17.2` tag
    attempt failed cleanly on the signing step (before anything published).
    Fixed by fetching minisign's own pinned+checksummed upstream binary
    instead of relying on OS package availability (PR #726).
- **Secret scanning (gitleaks) in pre-commit + CI** — ✅ DONE (2026-07-04,
  #703/#704). Pre-commit hook (`gitleaks protect --staged`) plus a CI
  `gitleaks` job (full commit history, `fetch-depth: 0`) on push/PR/weekly,
  now a required branch-protection check. `go install
  github.com/zricethezav/gitleaks/v8@latest` — note the module path trap:
  the GitHub org renamed to `gitleaks` but the Go module still lives under
  the original author's `zricethezav` namespace.
- **Native GitHub secret scanning + push protection** — ✅ DONE (2026-07-05,
  enabled via the repo settings API, no code change). Complements the
  gitleaks CI job: push protection blocks a recognized secret pattern
  *before* it lands, rather than catching it after.
- **Private vulnerability reporting** — ✅ DONE (2026-07-05) — gives
  researchers a structured private disclosure channel, complementing
  `SECURITY.md`'s existing contact-based process.
- **Dependency Graph + `dependency-review-action`** — ✅ DONE (PR #721,
  Dependency Graph enabled 2026-07-05). Blocks a PR that *introduces* a new
  vulnerable/license-flagged dependency at review time — distinct from
  govulncheck (already-merged code only) and Dependabot (schedule-based,
  doesn't gate a PR). `fail-on-severity: high`, matching this project's own
  CVSS-threshold philosophy elsewhere (`health --cve` WARNs at ≥7.0).
- **Dependabot security updates + malware alerts** — ✅ DONE (2026-07-05/06,
  enabled via repo settings, no code change). Fast-tracks a PR the moment a
  *known* CVE or malicious-package advisory is found, instead of waiting for
  the weekly scheduled version-bump PR.
- **CODEOWNERS** — ✅ DONE (PR #718, 2026-07-05). Routes review attention to
  the release-signing/replay-hermeticity/CI paths. Doesn't gate merges today
  (branch protection has no require-code-owner-review rule — deliberate, for
  solo-maintainer self-merge); documentation/signal now, ready to enforce
  the day a second reviewer exists.
- **Continuous fuzzing rig** — ✅ DONE (PRs #719/#720/#728/#729), live on
  pve01 CT 220. Rotates through every `FuzzXxx` target, **discovered
  dynamically per rotation** (`go test -list`) rather than a hardcoded list —
  built specifically because the existing `make test-fuzz`/`test-fuzz-linux`
  Makefile targets had silently drifted, never running 18 of the module's 44
  fuzz functions (fixed alongside, same PR). CPU-capped (`CPUQuota=100%`)
  after an uncapped rig measurably heated/loaded the shared homelab host.
  **Found a real bug within its first rotation**: `parseZFSCount` overflowed
  parsing a huge `K`-suffixed value, silently producing a negative ZFS vdev
  error count (int64 wraparound) that would slip past a `== 0` health check
  as a false "pool healthy" OK (BUG-097, PR #727) — a site the project's own
  manual false-OK audits had missed, because it already checked
  `strconv.ParseFloat`'s error explicitly and so wasn't caught by the
  discard-error-pattern sweep below. Two rig bugs found+fixed in the process
  of shipping this: the auto-crash-PR mechanism failed to push when based on
  a stale checkout (#728), and a `grep -q`-in-a-pipe SIGPIPE-under-`pipefail`
  bug made the per-target freshness check misreport every target as
  "doesn't exist" (#729, undetectable via manual reproduction — see that
  PR's description for the full root-cause story).
- **Float-parsing NaN/Inf/negative hardening sweep** — ✅ DONE (PRs #722/
  #723/#724/#727), triggered directly by building out the fuzzing rig above.
  `strconv.ParseFloat` treats `"NaN"`/`"Inf"`/`"+Inf"`/`"-Inf"` as
  *successful* parses, not errors — the same bug class as the earlier NVMe-
  temp/GPU-clock fixes (#372/#373). Found and fixed 33 call sites across 18
  files in `internal/collectors`, all now routed through one shared, fuzzed
  helper (`parseFloat`/`parseFiniteFloat`, `io.go`) instead of 29 independent
  copies of the same anti-pattern. Includes a corrected duration-parsing
  float→int overflow claim: PR #724 initially claimed this class of bug
  "saturates safely, not an active issue" based on a Docker verification
  that silently defaulted to arm64 instead of the deployed amd64 — on
  genuine amd64 (`docker --platform linux/amd64`), it does NOT saturate
  safely. The code fix was already correct either way (clamps before
  conversion); only the stated severity was wrong, corrected in PR #727.
- **SECURITY.md + network-free-as-a-stated-security-property** — still just
  an implicit design choice, not a written guarantee. Only remaining item in
  this list with zero action taken; low priority.

**Deliberately evaluated and declined, not oversights:**
- **DAST** — structurally not applicable; confirmed no `http.ListenAndServe`
  anywhere, dsd never runs as a network service.
- **Org-wide 2FA requirement** — the maintainer's own account already has
  2FA; the org-wide requirement itself is deferred until co-founders join
  (a conscious call, not a gap — nothing to enforce it against yet).
- **License allow/deny list on `dependency-review-action`** — offered as a
  quick follow-up (repo is MIT; a GPL-family deny-list would stop a future
  dependency from silently introducing copyleft), never explicitly
  requested. Cheap, still open if wanted.
- **GitHub Code Quality** (the CodeQL-powered maintainability/reliability
  scan product) — evaluated 2026-07-06. In public preview (free), goes GA
  and starts billing 2026-07-20. Declined: it's the same CodeQL engine
  already running here with additional query packs, and the marginal value
  over the existing `security-and-quality` CodeQL queries + the already-
  aggressive `golangci-lint` config (cyclomatic complexity, `staticcheck`,
  `dupl`, etc.) is unclear enough not to justify taking on a new billed
  feature for it.
- **CII Best Practices badge, signed commits, reproducible-build
  verification, `secret_scanning_non_provider_patterns`** — all evaluated,
  all judged genuinely low-value at the solo-maintainer/pre-revenue stage
  (paperwork, marginal value for a self-merging sole committer, overkill,
  or a materially higher false-positive rate, respectively) — not
  oversights, don't re-litigate without a new reason.

---

## Candidate features (gated on a real request)

### `--export` / CMDB inventory feed (candidate — gated on a real request)

DashDiag already collects hardware inventory (disk model/serial/capacity, CPU,
DIMM layout, installed software) as a byproduct of diagnosis — on every run, on
every box — then discards it. An export flag could emit this already-collected
inventory in a format an external CMDB can ingest.

- **Additive integration, not a CMDB product.** Feeds the *technical-facts*
  columns only (model / serial / specs / installed software). Does NOT supply the
  administrative layer (owner, asset tag, warranty date, physical location,
  licence entitlements) — none of that is visible from the box.
- **Cheap.** Data is already collected — a serialisation/format question, not
  a new collector pass.
- **Gate:** no build until a real customer requests it and names the target CMDB
  (ServiceNow, Snipe-IT, NetBox, Lansweeper, …). Format varies per system; wrong
  guess = throwaway work. Origin: Yuri (ex-MS IT manager, built a homemade Access
  CMDB) — see ADR-0002 §"Adjacent candidate — CMDB inventory feed".

---

## Notes / cross-refs
- Hardware-validation gaps (server-grade ECC/IPMI/NUMA, ARM, x86 metal, SteamOS, vSphere)
  are tracked in `docs/PLATFORM_COVERAGE.md` under "Known validation gaps" — also demand-gated.
- Cross-platform fix-hint bug (systemd hints on non-systemd hosts) is BUG-053/054 in `BUGS.md`.
