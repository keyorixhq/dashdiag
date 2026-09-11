# Continuous fuzzing rig

`make test-fuzz` / `make test-fuzz-linux` run every `FuzzXxx` target for a short
burst each (30s by default) and are meant to be run manually before cutting a
release (SSDLC Layer 2, ADR-0007). That's useful but fragile: it depends on a
human remembering to run it, and — discovered while building this doc — the
hardcoded target list had silently drifted, missing 18 of the module's 44 real
fuzz functions for months. Nothing failed; those 18 parsers (ZFS/mdstat/DRBD
recovery-percent parsing, systemd/SSH duration parsing, Azure/AWS/GPU/NVMe/SATA
value parsing, `/etc/os-release`) were simply never fuzzed by anyone running the
Makefile target.

`scripts/fuzz-continuous.sh` closes both gaps: it re-discovers every `FuzzXxx`
function across the module on each rotation (via `go test -list`, not a
hardcoded list — it can't go stale the same way), and it's meant to run forever
on a dedicated always-on box instead of depending on a human's memory.

## Where fuzzing runs

There are three sites. Don't assume pve01 is the only one — an agent reading
this doc has already twice concluded that and reasoned wrongly about release
risk from it.

| Site | What it runs | Cadence | Self-discovering? | Findings surface as |
|---|---|---|---|---|
| **GitHub Actions** (`.github/workflows/fuzz.yml`) | Every `FuzzXxx` target (55 as of 2026-09), split across 2 shards via `scripts/run-fuzz-targets.sh all` | Weekly (Monday 02:00 UTC) + `workflow_dispatch` | Yes — `scripts/fuzz-discover.sh`, same mechanism as pve01 | CI job failure on the `Fuzz` workflow; the crash reproducer is uploaded as a build artifact (`fuzz-crashes-shard<N>-<run>`), not auto-opened as a PR |
| **pve01** (CT 220 `dashdiag-fuzz`, 192.168.10.33) | Every `FuzzXxx` target, one rotation at a time, `FUZZTIME=15m` each | Continuous (systemd, `Restart=always`) | Yes — `scripts/fuzz-discover.sh` via `scripts/fuzz-continuous.sh` | Auto-opened/updated PR on `fuzz/corpus-updates` (see "What a crash looks like from the outside" below), plus every failing run's log on the `fuzz rig: failing-run logs` issue (see "Run logs") |
| **VCD tenant rig** (VM `dashdiag-fuzz`, reached via a bastion) | Every `FuzzXxx` target, one at a time, `FUZZTIME=15m` each | Continuous (systemd `dashdiag-fuzz.service`, `Restart=always`) | Yes — `scripts/fuzz-discover.sh` via `scripts/fuzz-continuous.sh` | Auto-opened/updated PR on `fuzz/corpus-updates` on a real reproducer, plus every failing run's log on the `fuzz rig: failing-run logs` issue |

**pve01 is currently unreachable** (as of 2026-09-02): the box is in Andrei's
Valencia apartment and he's away for a week or more. Don't assume its rotation
is progressing during that window — GitHub Actions is the only site confirmed
running.

**VCD tenant rig** (confirmed 2026-09-11): a VMware Cloud Director tenant runs
two separate always-on VMs — one for dashdiag (`dashdiag-fuzz`) and one for
keyorix (`keyorix-fuzz`) — each reachable only through a bastion host, not
directly. The dashdiag VM runs this exact `scripts/fuzz-continuous.sh` under
`dashdiag-fuzz.service`; the keyorix VM runs `scripts/fuzzing/run-rotation.sh`
from the keyorix repo. It replaced an earlier single `vcd-fuzz` VM. The tenant
is temporary (weeks-scale VMware resources), which is why every failing run's
log is also copied off the box to the tracking issue (see "Run logs") — when
the tenant expires, anything only on the box is lost. Connection details
(bastion address, host IPs, credentials) are operational and kept out of the
repo; ask Andrei.

## How Go's fuzz corpus actually behaves here (read this before wondering why nothing shows up in `git status`)

A fuzzing run reports "new interesting: N" constantly — that's coverage-increasing
input the fuzz engine found. Those inputs are cached in the local Go build cache
(`$GOCACHE/fuzz/...`), **not** written into the repo. Only a genuine **crash**
(a failing input) gets written into `testdata/fuzz/<FuzzName>/` in the package
directory — that's Go's own fuzz engine behavior, not something this script
arranges. So the script's logic is simple: if `testdata/fuzz/` has a diff after
a run, that diff is by construction a real failing input worth a human's
attention — there's no separate "just accumulating corpus" case to special-case
or silently ignore.

Practical implication: the rig's *local disk* is what accumulates fuzzing
depth over time (the build cache persists across rotations as long as the box
isn't rebuilt) — the value compounds by leaving the rig alone and running, not
by anything getting synced back to git on every round.

## What gets synced back to git

Only crash reproducers, automatically, as a PR:

- The script commits any new `testdata/fuzz/**` files to a branch
  (`fuzz/corpus-updates` by default) and opens/updates a PR via `gh pr create`.
- **Nothing auto-merges.** A found crash is a real bug report, and the PR is
  reviewed like any other — the reproducer becomes a permanent regression test
  once whatever bug it found is fixed.
- It publishes the reproducer immediately on the failing target, not batched at
  the end of a rotation, so a mid-run interruption can't lose a finding (see
  the script's `sync_repo`, which does `git clean -fd` before *every* target,
  not just once per rotation — safe for anything already pushed, destructive
  for anything that isn't).
- `sync_repo` runs before each individual target, not once per rotation —
  given how often this codebase merges, a target near the end of a 44+-target
  list would otherwise fuzz code that's hours (sometimes most of a day) stale
  by the time it's reached. The tradeoff: syncing this often means a target
  can occasionally be renamed/removed between when the rotation's list was
  built and when it's reached — the script checks the target still exists
  (`go test -list`) immediately before fuzzing it and skips it quietly if not,
  rather than mistaking "target no longer exists" for a crash.

## Run logs

Every run of every target gets its own log file, and none is ever overwritten
or pruned (`scripts/fuzz-runlog.sh`). Until 2026-09 the rig wrote to
`/tmp/fuzz-<Target>.log`, which the same target's next run overwrote and a
reboot wiped: the VCD rig raised 37 `CRASH` alerts between July and August and
only one log survived long enough to be read, so the other 36 could never be
sorted into real bug vs. harness flake.

```
$FUZZ_LOG_DIR/                       default ~/fuzz-logs — must be OUTSIDE the checkout
  <Target>/
    20260911T101636Z_6c2ac753ab12_4711_exit0.log.gz   start time, commit, pid, exit status
    20260911T134001Z_6c2ac753ab12_4711_exit1.log.gz
    latest.log.gz -> newest finished run
  .pending-post/                     failing runs not yet copied to GitHub
  .tracking-issue                    number of the GitHub issue they go to
```

Each log starts and ends with `# key: value` lines — host, target, package,
full commit, Go version, fuzztime, start, finish, duration, exit status — so a
log still makes sense after it's been copied somewhere else. Read one with
`zcat`, or `zless <Target>/latest.log.gz`. The `fuzz: elapsed` progress lines
that make up most of a log compress very well; a year of continuous fuzzing is
on the order of 100 MB.

**The box itself is not "forever".** pve01 has been unreachable for weeks at a
time and the VCD tenant is temporary, so every run that exits non-zero is
*also* posted as a comment on a single tracking issue in this repo, titled
`fuzz rig: failing-run logs` (created on first use). The comment carries the
log's header, the first `FAIL`/`panic:` line, and the log's last 50 KB with the
progress lines removed. That happens whether or not the run produced a
`testdata/fuzz` reproducer — the runs that didn't are exactly the ones that
used to vanish.

Posting is queued. If GitHub can't be reached, or the token lacks the Issues
permission, the log stays in `.pending-post/` and is retried after each later
target, up to 5 at a time, and once at startup. A queue that isn't draining
shows up in the journal as `runlog: ... still queued`. Set
`FUZZ_POST_FAILURES=0` to keep logs on the box only. To start a fresh tracking
issue, close the old one and delete `$FUZZ_LOG_DIR/.tracking-issue`.

## Provisioning the rig (pve01)

**Live and running since 2026-07-05**: CT 220 `dashdiag-fuzz`, 192.168.10.33,
4 cores / 4GB / 20GB disk, `CPUQuota=100%` (see the systemd unit below —
added after an uncapped rig measurably heated/loaded the shared host), Go
1.26.4 + gh CLI installed, repo cloned to `/root/proj/dashdiag`.

**Track record so far**: found one real bug within its first rotation —
`parseZFSCount` silently overflowed to a negative ZFS vdev error count
(BUG-097, PR #727), a site the project's own manual false-OK audits had
missed. Getting the rig's own tooling right took two more fixes along the
way: the auto-crash-PR push failed when based on a stale checkout (PR #728),
and a `grep -q`-in-a-pipe SIGPIPE-under-`pipefail` bug made the per-target
freshness check (below) misreport every target as "doesn't exist" — a bug
only reproducible by actually running the script, not by manual
command-line reproduction (PR #729, see that PR for the full story).

The steps below are the reusable recipe (e.g. for rebuilding the rig from
scratch, or standing up a second one) — the existing `debian13-lxc` (CT 201) is
too small for this (512MB RAM / 4GB disk — the Go module cache plus build cache
alone will not fit comfortably alongside fuzzing), hence a dedicated container:

```sh
# on pve01
pct create 220 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname dashdiag-fuzz \
  --arch amd64 \
  --cores 4 \
  --memory 4096 \
  --swap 1024 \
  --rootfs local-lvm:20 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1
pct start 220
```

Inside the container:

```sh
apt-get update && apt-get install -y git curl build-essential

# Go (match the project's pinned minor — see ci.yml's floating-version note)
curl -fsSLO https://go.dev/dl/go1.26.4.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.26.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && export PATH=$PATH:/usr/local/go/bin

# GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
apt-get update && apt-get install -y gh

git clone https://github.com/keyorixhq/dashdiag.git ~/proj/dashdiag
```

**Auth (do this step yourself, on the box, not through an assistant session)** —
same discipline as the minisign key: a repo-scoped credential should never pass
through a chat session. Create a **fine-grained PAT** scoped only to
`keyorixhq/dashdiag` with Contents (read/write), Pull requests (read/write)
and Issues (read/write) — Issues is for the failing-run log comments (see "Run
logs"); without it those stay queued on the box — then:

```sh
gh auth login --with-token < token.txt
rm token.txt
```

## Running it

```sh
chmod +x ~/proj/dashdiag/scripts/fuzz-continuous.sh
FUZZTIME=15m REPO_DIR=~/proj/dashdiag ~/proj/dashdiag/scripts/fuzz-continuous.sh
```

55+ targets as of 2026-09 (growing over time — discovered dynamically via
scripts/fuzz-discover.sh, not a fixed number) × 15m ≈ 14+ hours per rotation,
though since each target now re-syncs to
`origin/main` individually rather than once per rotation, "rotation" is a
looser concept than it used to be — see the per-target sync note below.
Shrink `FUZZTIME` for faster rotations if you'd rather trade depth-per-target
for more frequent full-module coverage.

On CT 220 this is wired up as a systemd service (below), `enabled` (starts on
boot) and currently **running**:

```sh
pct exec 220 -- systemctl status dashdiag-fuzz --no-pager
pct exec 220 -- journalctl -u dashdiag-fuzz -f   # watch it run
```

To set this up on a fresh rig instead of a foreground shell:

```ini
# /etc/systemd/system/dashdiag-fuzz.service
[Unit]
Description=dashdiag continuous fuzzing
After=network-online.target

[Service]
Type=simple
User=root
Environment=REPO_DIR=/root/proj/dashdiag
Environment=FUZZTIME=15m
# systemd's default PATH doesn't include /usr/local/go/bin (that's only added to
# ~/.bashrc, which a service never sources) — without this, ExecStart fails with
# "go: command not found". Confirmed live on the pve01 rig (CT 220).
Environment=PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Optional: Environment=FUZZ_NOTIFY_URL=https://ntfy.sh/your-topic-here
# Optional: Environment=FUZZ_LOG_DIR=/root/fuzz-logs  (the default is $HOME/fuzz-logs;
#           anywhere outside the checkout — sync_repo's `git clean` would delete it)
# Optional: Environment=FUZZ_POST_FAILURES=0          (keep failing-run logs off GitHub)
ExecStart=/root/proj/dashdiag/scripts/fuzz-continuous.sh
Restart=always
RestartSec=30
Nice=19
CPUWeight=20
# Nice/CPUWeight alone did NOT cap actual heat/noise in practice — they only
# affect relative priority when something ELSE is contending for CPU, which
# on an idle homelab box is rare, so an uncapped rig still pegged near 100%
# continuously (confirmed live: pve01's package temp hit 91°C, load average
# 8.4 on an 8-thread box). CPUQuota is the actual fix — a hard ceiling
# regardless of contention. Tradeoff: -fuzztime is wall-clock, not CPU-time,
# so capping CPU makes each pass shallower (fewer mutations tried), not the
# rotation slower.
CPUQuota=100%

[Install]
WantedBy=multi-user.target
```

`Nice=19` + `CPUWeight=20`: this is background, best-effort work sharing pve01
with the rest of the test fleet — it should never compete for CPU against an
active validation session on another guest.

```sh
systemctl daemon-reload
systemctl enable --now dashdiag-fuzz
journalctl -u dashdiag-fuzz -f   # watch it run
```

## What a crash looks like from the outside

A new PR titled `test(fuzz): crash reproducer(s) from continuous fuzzing`
appears on `keyorixhq/dashdiag`, containing one or more new files under
`internal/*/testdata/fuzz/`. Reproduce locally with:

```sh
go test -run=<FuzzName> ./internal/<package>/
```

Fix the parser, confirm the same command passes, and merge the PR — the
reproducer is now a permanent regression test alongside the existing seed
corpus.

Every failing run — with or without a reproducer — also adds a comment to the
`fuzz rig: failing-run logs` issue with its log. A comment with no matching
PR is a run that exited non-zero without writing a reproducer: a timeout
(`context deadline exceeded` at the end of `-fuzztime` is a known Go fuzzing
harness flake), an out-of-memory kill, or a build failure. The log in the
comment says which.

## Pausing / stopping

```sh
systemctl stop dashdiag-fuzz     # pause
systemctl disable dashdiag-fuzz  # stop it starting on boot
pct stop 220                     # or just stop the whole container
```

The build cache is disposable. The one thing worth keeping is
`$FUZZ_LOG_DIR`: failing runs' logs are already on the tracking issue once
`.pending-post/` is empty, but passing runs' logs exist only on the box — copy
the directory off before destroying it if you want them.
