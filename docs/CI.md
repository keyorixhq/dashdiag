# Gate CI on dsd

`keyorixhq/dashdiag` is also a GitHub Action (`action.yml` at repo root): it
installs a checksum-verified `dsd` release and gates the job on a read-only
health verdict — no agent, no daemon, nothing left behind on the runner.

## Gate a self-hosted runner or VM-image build

```yaml
- id: dsd
  uses: keyorixhq/dashdiag@v2
  with:
    policy: .dsd-policy.yaml   # dsd policy init > .dsd-policy.yaml
    fail-on: warn
- run: echo "verdict was ${{ steps.dsd.outputs.verdict }}"
```

That's the whole gate: the step fails the job on `WARN`/`CRIT` per `fail-on`,
uploads a redacted `dsd share` report as a build artifact, and exposes
`verdict`/`top_catch`/`report` as step outputs for anything downstream that
wants to branch on them or post a summary comment.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `version` | latest release | Pin a specific dsd release tag. |
| `policy` | — | Path to a `dsd policy` YAML file (thresholds + `deny` levels). |
| `hosts` | — | Space-separated remote hosts to check via `dsd fleet` over SSH, instead of the runner itself. |
| `ssh-key` | — | Private key for `hosts`. Required when `hosts` is set. |
| `fail-on` | `crit` | `warn` or `crit` — the minimum severity that fails the job. |
| `allow-network` | `false` | Let dsd make its own outbound calls (DNS/connectivity probes, cloud-metadata). Off by default — see `PRIVACY.md`. |

## Outputs

`verdict` (`OK`/`WARN`/`CRIT`), `top_catch` (JSON, or the string `"null"` on
a clean run — see the "Top catch" line in `dsd health`'s own output),
`report` (path to the `dsd share --format md` artifact; local-runner only,
not populated for the `hosts` path).

See `.github/workflows/action-selftest.yml` in this repo for a working,
CI-verified example, and the top-level README's "CI / scripting" section for
the plain-SSH equivalent that doesn't need the Action at all.
