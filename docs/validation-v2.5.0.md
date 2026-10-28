# v2.5.0 validation: v2.4.0 vs main (4f9c01a), real data

Why: the v2.4.0..main verdict and collector changes (#1136-#1145) were tested with
fixtures on macOS and in CI only. The risk measured here is noise (a check that
can never be read in its context raising the verdict/exit code), not crashes.
Full data: `raw/` of session DD-RELEASE-250-1 (`MANIFEST.sha256`).

## 1. Replay diff (49 bundles, linux/amd64 binaries, run on the e2e VM)

`~/proj/dashdiag-captures` holds 57 files; 49 are `.tar.gz` bundles (the rest are
HTML/text reports). `dsd replay --json` with both binaries.

| | old -> new |
|---|---|
| verdict | unchanged in 49/49 (every bundle is already WARN or CRIT, so the floor cannot show) |
| exit code | 0 -> 0 in 49/49 (`dsd replay` exits 0 for both binaries) |
| insight counts | +1 unverified in 49/49, +1 more in 10 (CloudMeta), +1 in 1 (Disk) |

None of the 49 bundles has `direrrs.json` (captured before 2026-10-27), so a
permission error on a directory replays as absent. Expected, and the reason the
non-root bundles show no new TLS/ReadDir unverified.

| new unverified insight | bundles | class | what |
|---|---|---|---|
| `CPU Load/RunQueue`: "CPU usage sample failed" | 49/49 | **(c) regression, fixed in item 4** | `cpuSample` gained an `ok` field; every older recording lacks it, so a valid recorded sample (usage 33%, run_queue 5) decoded as failed. A clean old bundle would have replayed as "Not fully verified". |
| `CloudMeta`: "metadata could not be read from any provider's IMDS" | 10/49 (AWS, OCI, Graviton, SLES/Ubuntu arm64 captures) | (b) noise, replay only | Replay registers the collector from the DMI hint, but the bundle was captured offline, so no IMDS response exists to replay. Live offline runs are unaffected (the gate keeps the collector out). Left as a LEFTOVER: replay should say "not captured" rather than "could not be read". |
| `Disk`: "mount /run/user/0/doc (fuse.portal) is unreachable" | 1/49 (artix) | (b) noise | `xdg-document-portal` FUSE mount refuses statfs; intended gap closure, benign on a desktop-portal host. |

No (a) "old was a false OK" appears in this corpus: all 49 hosts already had
WARN/CRIT, so the false-OK fixes (which only change an otherwise-OK verdict) have
no row to flip. They are covered by the Guard A fixtures instead.

## 2. Live runs

e2e VM (Debian 13, 4 vCPU, user `e2e`, passwordless sudo). Binaries v2.4.0 and
main, `HOME` pointed at a scratch dir. Exit code old -> new:

| command | as e2e | as root |
|---|---|---|
| `health --json`, `health` | 2 -> 2 | 2 -> 2 |
| cpu db gpu kvm net processes pve steamos thermal services | 0 -> 0 | 0 -> 0 |
| disk docker logs security | 1 -> 1 | 1 -> 1 |
| k8s | 1 -> 1 | 0 -> 0 |
| **tls** | **0 -> 1** | 0 -> 0 |

pve01 (Proxmox VE 9.1.1, bare metal, run by the coordinator, `nobody` / root):
`health` CRIT exit 2 in all four runs (unverified 16 -> 17 as nobody, 2 -> 2 as
root; the one new insight is Logs "could not verify: crash/core dump files,
journal corruption", correct). `processes` 0 -> 1 / 0 -> 0, `tls` 0 -> 1 / 0 -> 0,
`pve` 0 -> 1 / 0 -> 1 (as root a real WARN, "7 VM/CT have no backup", now honoured).
Hardware smoke: 6 passed, 0 failed, 1 skipped (no battery).

Both hosts have real CRITs, so `health` cannot show the exit-code noise itself.
The noise is in the unverified counts:

| run | unverified (v2.4.0 -> main) | root-only reads among them |
|---|---|---|
| e2e VM, non-root | 12 -> 13 | 9 of 13 |
| pve01, non-root | 16 -> 17 | most (shadow, auth logs, kmsg, journal, LVM, PostBoot) |
| e2e VM / pve01, root | 4 / 2 | 0 (CPU corroboration under load, Logs 10 s timeout) |

## 3. Decision (item 3)

Data: non-root runs carry 9-22 unverified insights against 2-4 as root, and
`dsd tls` / `dsd processes` / `dsd pve` went 0 -> 1 for a non-root user on a
stock host. A non-root `dsd health` on a host with no finding could never be OK.
Rule implemented: a needs-root unverified check on a non-root run is shown
("needs root: N checks skipped - re-run with sudo") but does not floor the
verdict; any other unverified insight or errored collector still does. Result on
the e2e VM with the branch binary: non-root `dsd tls` exit 0 with the skip line
(root: 0); non-root `dsd health --json` counts `unverified 12, needs_root 10`
(`unverified` stays truthful), and the two that still floor are not privilege
gaps: CPU load that could not be corroborated under load, and kubectl present
with no reachable cluster.

## 4. Regression found and fixed

The `cpu/usage-sample` recording gained an `ok` field in this release; all 49
older bundles decoded it as false (row 1 of the replay table). `cpuSample` now
decodes a recording without `ok` as a success unless it is the all-zero struct a
failed sample used to be. After the fix 0 of 49 bundles show the insight (49
before); the CloudMeta and Disk rows are unchanged.
