# Replay-fidelity fixtures

Raw `dsd capture --raw` bundles + a golden `check → status` map, used by
`scripts/check-replay-fidelity.sh` (run in CI) to guard the **cross-environment
replay-fidelity** class: a collector that reads live *environment* state
(container-context, `adjtimex`/clock-sync, kernel, arch) at **replay** time
instead of from the bundle, so `dsd replay` reports the replaying machine's
findings rather than the captured host's.

The existing double-replay hermeticity job (`.github/workflows/ci.yml`) only
proves two replays in the *same* environment agree — it is blind to this class,
because capture-env == replay-env hides the divergence. This fixture closes that
gap: it was captured on a **distinctive** host whose verdicts differ from any CI
runner, so replaying it anywhere must still reproduce the captured verdicts.

## `debian13-vmware-unsynced`

A real VMware Debian 13 (trixie) guest, captured **as root**, then sanitized
(`dsd sanitize --identifiers` — hostname/IPv4/MAC + secrets redacted; only the
gateway lookup-key `192.168.30.1` remains, by replay necessity). Distinctive
because:

- **Clock = CRIT** (no NTP/chrony, no open-vm-tools) — the exact verdict that the
  clock collector previously flipped to a green `host: synced` OK when replayed
  inside a container (#586). This is the canary.
- **Network = CRIT** (empty `/etc/resolv.conf`), **VMware = WARN** (no
  open-vm-tools, SCSI 30s timeout, `disk.EnableUUID` off), **KernelSec/Hardening
  = WARN**, **Firewall = INFO** (no `nft`). A broad set of env-sensitive axes.

If any check's replayed status drifts from `*.golden.json`, a collector is
reading live state under replay — fail loud.

### Regenerating the golden (only after an *intended* verdict change)

```bash
dsd replay --json fixtures/replay-fidelity/debian13-vmware-unsynced.tar.gz \
  | jq -S '[.checks[] | {(.name): .status}] | add' \
  > fixtures/replay-fidelity/debian13-vmware-unsynced.golden.json
```

Review the diff: a status that moved toward OK without a deliberate reason is the
bug this guard exists to catch.
