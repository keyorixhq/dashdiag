# Competitive Notes — DashDiag (dsd)

> Scope: positioning-relevant competitive observations for DashDiag itself.
> Portfolio/platform-level competitive research lives in the unpackops repo
> (`docs/research/COMPETITOR_PAIN_NOTES.md`). Per COMPANY_PRINCIPLES.md
> Principle 3: everything here is signal, not demand. Nothing in this file is
> build permission.

---

## AWS DevOps Agent (assessed 2026-06-13)

Source: https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent.html

### What it is

A managed AWS service: an autonomous agent that investigates incidents the
moment an alert/ticket arrives, builds an application topology graph,
correlates telemetry + code + deployment data, produces mitigation plans,
and issues prevention recommendations. Routes findings through Slack /
ServiceNow. Extensible via customer-provided MCP servers. Administered
through the AWS Management Console; organized around "Agent Spaces" that
contain AWS account configurations and tool integrations.

### Why it does not overlap with dsd

Different layer, different prerequisites, different trust model:

1. **Telemetry prerequisite.** The agent's raw material is an existing
   observability pipeline (CloudWatch, Datadog, Dynatrace, New Relic,
   Splunk) plus CI/CD and repo integrations. It never touches a host
   directly. A box with nothing instrumented is invisible to it. dsd's
   premise is the opposite: run one binary on an uninstrumented machine,
   get a verdict in seconds.

2. **Altitude.** It reasons at application/service-topology level (which
   service degraded after which deploy). dsd reasons at host level (SMART,
   CPU pressure, filesystems, services on *this* machine). Air traffic
   control vs handheld OBD scanner.

3. **"Multicloud/hybrid" is integration reach, not neutrality.** Multicloud
   support is delivered *through* the third-party observability
   integrations — if your GCP/on-prem workloads already ship telemetry into
   Datadog, the agent reasons about them via Datadog. The control plane
   stays AWS (console-administered, account-anchored Agent Spaces). Same
   pattern as EKS Anywhere/Outposts: hybrid = extend the AWS control plane
   outward. There is no locally-run, cloud-neutral mode and no structural
   incentive for AWS to build one.

4. **Trust / connectivity model.** Managed cloud service: incident data
   flows through an AWS-hosted agent. The data-sovereignty crowd is
   excluded twice — first by the telemetry prerequisite, then by "infra
   state goes to a US hyperscaler." Air-gapped, regulated, on-prem, and
   MSP-touching-a-client's-server-for-the-first-time scenarios are out by
   the product's own architecture. dsd's network-free single binary +
   `--blob`/`decode` offload path (ADR-0002 D6) sits exactly in that
   negative space.

### What it validates / threatens

- **Validates the category.** "Find problems admins didn't know to ask
  about" is now effectively an AWS marketing line. The pain is real enough
  for a hyperscaler to productize.
- **Crowds the up-stack RCA layer, not dsd.** It is closer to the (deferred)
  UnpackOps RCA-platform concept than to dsd. See unpackops
  COMPETITOR_PAIN_NOTES §6 for the portfolio-level read.
- **Possible complement, not competitor:** the agent explicitly supports
  customer MCP servers as tool extensions. A dsd MCP server exposing
  deterministic host verdicts (`--json`) is a plausible *input* to their
  agent — "give the agent the diagnosis, not the commands."

### Watch items (would change this assessment)

- AWS ships an agentless host-level collector that works without a
  telemetry stack.
- An on-prem / customer-hosted control plane appears.
- Pricing/packaging that targets SMB or single-server use rather than
  fleet/enterprise.

---

## Agentic-DevOps field report (assessed 2026-06-20)

Source: Brett Fisher (*Agentic DevOps*) long-form interview. Practitioner
read, not a buyer — **signal only, no gate moves.** Portfolio-level analysis
and the moat framing live in unpackops `COMPETITOR_PAIN_NOTES.md` §8; recorded
here only for the two points that bear directly on dsd's positioning.

1. **Independent corroboration of dsd's posture.** From first principles the
   speaker arrives at exactly dsd's shape as AI's safe entry to DevOps:
   read-only, narrow-scope, human-in-the-loop, incremental. Infra correctness
   is binary (a 70%-correct config does not deploy), so generation is the wrong
   first product and read-only verdict/explanation is the right one. This is
   external validation of the read-only wall (ADR-0006 D3) and the no-AI-in-the-
   binary line (ADR-0008 D2), reached by someone with no stake in dsd.

2. **The context-moat, in dsd terms.** The field's shared bottleneck is
   *context* — and competitors manufacture it by fine-tuning models, which is
   unverifiable (recall, not citation). dsd's `--json` is the opposite: it
   *generates* deterministic, structured, citable evidence. "Give the agent the
   diagnosis, not the commands" (already the dsd-MCP-server framing above) is
   the same idea — the verdict layer is the context other tools are trying to
   train into a model.

Non-goal reinforced: dsd never grows a config-generation feature. Read-only
verdicts forever; the wall is now backed by an outside practitioner's reasoning,
not just our own.
