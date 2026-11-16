# Pre-registration: DashDiag redaction canary oracle

Written before the first run.

Question: does a secret-shaped value planted in host data survive the DashDiag
redactors (share.RedactText, share.RedactJSONBytes, source.RedactSecretsText,
source.RedactJSONSecrets) in any encoding the scanner knows?

Contexts are split in advance into:
- in-claim: shapes covered by a documented rule family (key=value for secret-named
  keys, Bearer, URL userinfo, netrc, JWT, shadow hash, PEM block, JSON secret-named key).
  A surviving canary here is a defect and fails the test.
- out-of-claim: shapes the redactors document as best-effort/not covered
  (space-separated CLI flags, free prose, curl -u and similar). A surviving canary is
  recorded in the report (CANARY_OUT) and never fails the test.

Valid-run rule: the planted-leak self-test must detect every planted survivor, and the
control (a perfect redactor) must produce zero hits. Otherwise the run is INVALID.
Any claimed finding needs a deterministic repro replayed 3 times (the test is fully
deterministic for a given CANARY_SEED).
