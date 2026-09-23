# Demo fixtures

Reproducible demo scenarios live in `fixtures/`. Render any with no hardware:

```sh
dsd mock fixtures/<name>.yaml
```

The marketing narrative, LinkedIn copy, and demo scripts are maintained privately
(not in this public repo).

## `dsd demo` vs `dsd mock`

Both render a fixture through the exact same pipeline as a live `dsd health`
run — no collectors, no hardware, no network. They serve different audiences:

| | `dsd mock <file.yaml>` | `dsd demo [scenario]` |
|---|---|---|
| Audience | Contributors, marketing screenshots | A first-run user, right after install |
| Fixture source | Any file on disk (`fixtures/*.yaml` or your own) | A curated set embedded in the binary (`go:embed`) |
| Scenario choice | You pick the file | `--list` to browse, a name to pick, nothing for the flagship |
| Extra output | None | A "DEMO — simulated host" banner + a short narrative |
| Exit code | Whatever the fixture's insights imply | Always `0` — never a live host gate |

`dsd demo`'s embedded scenarios are copies of five `fixtures/*.yaml` files
(`failing-drive` [default], `proxmox-backup-gap`, `vmware-guest-scsi-timeout`,
`docker-host-meltdown`, `cve-actively-exploited`), kept in sync by
`internal/demo/demo_test.go`'s `TestEmbeddedScenariosMatchFixtures`. `fixtures/`
is the source of truth — edit there, then run `make demo-sync` to re-copy.
Each fixture's header comment states whether it's grounded in a real validated
finding or fully synthetic; the `narrative:` field (consumed only by `dsd
demo`, ignored by `dsd mock`) is the 3-5 line "what happened, why, what to do"
story printed after the summary.
