# Cloud guest-side validation plan

A runbook to close the **live-validation debt** for the guest-side cloud checks shipped in
the 2026-06-23 session (GCP collector #452, Azure #450/#454, AWS tail #453). These were
built and unit-tested (and fuzz-guarded, #461) but parse cloud metadata / driver output
whose exact shape is confirmed from docs, not a live box. This plan validates them the same
way the AWS/Azure **cores** were validated.

## What is already validated — do NOT redo

| Surface | Status |
|---|---|
| AWS core (ENA allowance, EBS 0xD0 throttle, IMDS v1/v2, Amazon Time Sync, SSM) | ✅ live on t4g (Graviton/arm64) + t3 (x86) |
| Azure core (Accelerated Networking VF, waagent, Hyper-V PTP) | ✅ live on D2s_v3 (x86) + D2pls_v5 (Ampere/arm64) |
| All parsers added this session | ✅ fuzz-guarded (#461) — robustness only, not real-shape |

## What this plan validates (the delta)

- **GCP collector (#452)** — gVNIC, guest agent, host-maintenance policy, OS Login, metadata NTP. *Nothing validated yet — priority 1.*
- **Azure additions (#450/#454)** — Dynamic Memory, temp/resource disk, managed-disk host-cache hazard, scheduled-events, NVMe `io_timeout`.
- **AWS tail (#453)** — Nitro Enclaves; ENA Express (SRD) *(low value — see note, may skip)*.

It is **not** a full-suite re-run. One targeted VM per cloud. arm64 is **not** needed this
round (the cores already have arm coverage; the new checks are driver/metadata/sysfs, not
arch-specific).

---

## Methodology (every run follows these — non-negotiable)

1. **Dual-privilege.** Run twice — once as root, once unprivileged — and diff with volatile
   fields stripped:
   ```
   diff <(jq -S 'del(.timestamp,.checks[].duration)' nonroot.json) \
        <(jq -S 'del(.timestamp,.checks[].duration)' root.json)
   ```
   A check that degrades from a real status (root) to OK/empty (non-root) is a silent-failure
   bug — the worst class. The honest pattern is `*_checked:false` / a "needs root" reason.
2. **Capture, don't camp.** These VMs are metered. On each host:
   ```
   dsd capture --raw -o /tmp/<cloud>-<size>-<date>.tar.gz
   ```
   scp the bundle off, **tear the VM down**, then `dsd replay <bundle>` / `dsd diff` locally
   and keep the bundle as a regression fixture (`testdata/captures/`, gitignored). The bundle
   replays hermetically — it is the durable artifact, the VM is disposable.
3. **Deploy** a static binary: `make release` → `scp dist/dsd-linux-amd64 <vm>:/tmp/dsd`.
   (`/tmp` is often tmpfs — re-scp after any reboot.)
4. **Record** exact instance type, image, region, and date with each capture.
5. **Pass criteria, two-sided:** the *expected verdict appears* when the condition is induced
   **AND** the clean baseline produces *no false alarm*. Both, or it is not validated.

### Commands run on every host
```
/tmp/dsd health --json > root.json          # as root
/tmp/dsd health --json > nonroot.json        # unprivileged (sudo -u nobody, or a normal user)
/tmp/dsd health                              # eyeball the rendered insights
```
The cloud collectors are in the default `dsd health` (gated on DMI / metadata), so no extra
flag is needed except `--packages` if you also want the package-DB check.

---

## GCP — priority 1 (nothing validated)

**VM:** 1 × `e2-micro` (free tier), region with free-tier eligibility (e.g. `us-central1`),
image `debian-12` or `ubuntu-2204`, **gVNIC**:
```
gcloud compute instances create dsd-val \
  --machine-type=e2-micro --image-family=debian-12 --image-project=debian-cloud \
  --network-interface=nic-type=GVNIC,subnet=default
```

| # | Check | Precondition / how to induce | Expected verdict | Pass |
|---|---|---|---|---|
| G1 | gVNIC NIC | default (NIC created with GVNIC) | recognition line: "gVNIC networking (gve)" | gve detected, `uses_gvnic=true` |
| G2 | guest agent running | default | folded into recognition ("guest agent running") | no WARN |
| G3 | guest agent **down** | `sudo systemctl stop google-guest-agent` | **WARN** "installed but not running — SSH-key / OS-Login … fail" | WARN fires; then `start` → WARN clears |
| G4 | OS Login | default (or `gcloud … add-metadata --metadata enable-oslogin=TRUE`) | recognition "OS Login enabled" if on | reflects metadata |
| G5 | host-maintenance **TERMINATE** | `gcloud compute instances set-scheduling dsd-val --maintenance-policy=TERMINATE` (non-preemptible) | **WARN** "TERMINATE on a non-preemptible VM — will be STOPPED, not live-migrated" | WARN fires; set back to MIGRATE → clears |
| G6 | metadata NTP | default chrony config | INFO if NOT pointed at `metadata.google.internal`/169.254.169.254 | matches actual chrony |
| G7 | couldn't-measure | run G3/G5 checks **non-root** (metadata still readable) | same verdicts as root (metadata is unauthenticated) | root/non-root diff clean |

**Capture:** `dsd capture --raw` after G1/G2/G4/G6 baseline; a second capture with G3+G5 induced.

---

## Azure — priority 2 (core done; #450/#454 owed)

**VM:** 1 × an **NVMe-capable v5/v6 size that also has a temp disk**, with **one data disk
attached, host caching = ReadWrite**. Verify on the box: `ls /sys/class/nvme` is non-empty
**and** a temp/resource disk exists (`/dev/disk/azure/resource` or a `/mnt` mount). If no single
size gives both NVMe and a temp disk, use two VMs (one for A4/A5 NVMe, one for A1–A3 temp/cache).
```
az vm create -g dsd-val -n dsd-val --image Ubuntu2204 \
  --size <NVMe-v5-size-with-temp-disk> --data-disk-sizes-gb 16 --data-disk-caching ReadWrite
```

| # | Check | Precondition / how to induce | Expected verdict | Pass |
|---|---|---|---|---|
| A1 | temp/resource disk present | default (size has a temp disk) | recognition "temp disk at /mnt(/resource) (ephemeral)" | detected; `temp_disk_present=true` |
| A2 | persistent data on temp disk | add `/etc/fstab` line mounting under the temp mount (e.g. `UUID=… /mnt/data ext4 …`) | **WARN** "persistent data under the ephemeral temp disk" | WARN fires; remove line → clears |
| A3 | managed-disk host cache hazard | the attached data disk with `--data-disk-caching ReadWrite` | **WARN** "data disk LUN N has ReadWrite host caching" | WARN fires for the data disk; OS disk RW **not** flagged |
| A4 | NVMe `io_timeout` | NVMe size, default kernel cmdline | INFO if `nvme_core.io_timeout` < 60s; recognition "io_timeout=Ns" if tuned | matches `/sys/module/nvme_core/parameters/io_timeout` |
| A5 | Dynamic Memory | default (Azure standard sizes do NOT enable Hyper-V DM) | **negative** — DM absent, nothing claimed | `dynamic_memory=false`; **note**: positive path not validatable on Azure |
| A6 | scheduled-events | IMDS `/metadata/scheduledevents` (usually no event) | no maintenance insight (clean parse) | endpoint parsed, no false event. (Real maintenance event is opportunistic — capture if one ever appears) |
| A7 | couldn't-measure | run **non-root** (IMDS storageProfile needs no auth) | `disks_checked` consistent root/non-root | diff clean; if IMDS blocked non-root → `disks_checked=false`, never silent-OK |

**Note on A5/A6:** these are best-effort (DM not offered; maintenance events can't be forced).
Document the negative result; that still closes "does the parser choke on the real response".

---

## AWS — priority 3 (tail only, #453)

The AWS **core** is already validated — only the tail is owed.

| # | Check | VM / how | Expected | Pass |
|---|---|---|---|---|
| W1 | Nitro Enclaves present | enclave-capable instance (≥4 vCPU, e.g. `c6g.xlarge`/`m5.xlarge`) launched with `--enclave-options Enabled=true`; install `aws-nitro-enclaves-cli` so the allocator runs | recognition "Nitro Enclaves present" | `/dev/nitro_enclaves` detected |
| W2 | ENA Express (SRD) | **expensive** — needs 2 instances in a cluster placement group with ENA Express enabled on the ENIs + traffic between them | recognition "ENA Express active" | `ena_srd_*_pkts` non-zero |

**Recommendation on W2: skip the full setup.** It is recognition-only and the sole unknown is
the counter name. Cheap substitute: on **any** ENA instance run `ethtool -S <ena-iface> | grep
ena_srd` and confirm the `ena_srd_tx_pkts` / `ena_srd_rx_pkts` names exist in the driver's stat
set. If the names differ, fix `enaSRDActive`; otherwise the check is correct-by-construction
(absent counters → safe negative). Only stand up the placement group if you specifically want
the active-path proof.

**Optional core re-confirm:** any `t4g.small` (free-tier) → `dsd health` should reproduce the
known-clean ENA/EBS/IMDS/time-sync recognition (cheap sanity that nothing regressed).

---

## Optional, SEPARATE task — gated SUSE / RHEL (build + validate)

These checks are **not built yet** (backlog, demand-gated) and need **PAYG** images
specifically — a different VM set from everything above. Only pursue if you want that surface.

| Box | Image | Builds + validates |
|---|---|---|
| PAYG **SLES** | Azure/AWS/GCP marketplace **PAYG** SLES (not BYOS) | SUSE spec checks 1–5: registration 422/attestation, `zypper ref` repo reachability, `cloud-regionsrv-client` currency, PAYG-vs-BYOS consistency, update-path egress sanity |
| PAYG **RHEL** | marketplace **PAYG** RHEL | RHEL/RHUI: **RHUI client-cert expiry** (`/etc/pki/rhui/*.pem` enddate) — the predictive Q3 from the Cloud-PAYG design note; the strongest single candidate |
| (contrast) BYOS SLES + openSUSE Leap | — | needed to validate the PAYG-vs-BYOS and registered-vs-unregistered branches |

SLES PAYG carries a per-hour software charge on top of compute — **capture, don't camp**.
These are a build task, not just validation; sequence after the validation set above.

---

## Cost / time

- Validation set: **~3 VMs** (GCP e2-micro free; one Azure v5; one AWS enclave instance),
  each time-boxed to a single capture session and **torn down the same session**.
- Skipping ENA Express (W2) avoids the only multi-instance/placement-group cost.
- SUSE/RHEL PAYG is separate and metered — do it only when building that surface.

## Result tracking

For each row: record `PASS` / `FAIL` / `N/A` + the capture bundle filename + instance
type/region/date. Any **false alarm on a clean baseline** is a P1 bug — fix before the verdict
is trusted, the same way live validation caught the rpm fresh-boot false-positive (#457) and
the PostBoot `journalctl --grep` exit-code bug (#459). File each finding and re-capture.
