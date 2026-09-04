# Two product-claim gaps — 2026-09-02

Found by code reading against `main` @ `313bdd08`, not by hardware validation, so this
does not belong in `BUGS.md` (that log is explicitly testbed discoveries). Both are the
same shape: **a claim the product makes that the code does not establish.**

Neither is a crash or a wrong answer. Both are the kind of thing a prospect's security
reviewer asks about in the first ten minutes.

---

## GAP-1 — "read-only, agentless" is not true in fleet mode, and nothing cleans up

**Evidence.** `internal/fleet/fleet.go`:

- `scp(ctx, opts, localPath, host, remotePath)` (line 466) uploads the `dsd` binary to
  the target.
- `remoteCmd = "chmod +x " + q + " && " + q + " health --json"` (line 259).
- `RemoteBinDir` defaults to `/tmp` (`withDefaults`), never CLI-controlled.
- A search of `internal/fleet` for `rm`, `unlink`, `cleanup`, `Cleanup`, or any deferred
  teardown of the remote path returns **zero matches**.

So a fleet scan performs two writes on every target — a file create and a mode change —
and leaves an executable behind. Every host ever fleet-scanned still has `/tmp/dsd`.

**Why it matters more than it looks.** Copy-run is a standard agentless pattern and `/tmp`
clears on reboot, so the behaviour is defensible. The problem is that neither claim carves
it out, and there is no evidence anyone decided this — the absence of cleanup reads as an
oversight, not a choice. "Agentless" stops meaning much when the binary persists across
the session that put it there.

**The decision (yours, not a code change):** either

1. **Fleet mode cleans up** — a deferred removal of the remote binary, with a test that
   proves the remote path is gone after a run; or
2. **The claim changes** — "no persistent agent: a temporary binary is copied to `/tmp`
   for the duration of a scan" — stated in README, SECURITY.md and the fleet docs.

Option 1 is better for the pitch. Option 2 is honest and free. Doing neither is the
current state, and it is the one option that fails a security review.

**Then make it structural.** Enumerate every write-capable call
(`os.Create`, `os.WriteFile`, `os.OpenFile` with write flags, `os.Remove*`, `os.Rename`,
`os.Mkdir*`, `os.Chmod`, `os.Symlink`) reachable from a non-fleet code path and assert the
set is empty. Today the tree has 67 such call sites in non-test code; they need
classifying once into "writes the operator's own output artifact" versus "touches a
target." After that the test holds the line for free, and it is an artifact you can hand
to a reviewer rather than a paragraph asserting good intent.

---

## GAP-2 — the bundle designed for sharing is unredacted by default

**Evidence.** `cmd/capture_raw.go:36`:

```go
captureCmd.Flags().Bool("sanitize", false,
    "best-effort redaction of common credentials (keys, passwords, tokens) from the bundle before writing — for safe sharing")
```

The flag's own help text says the bundle is for sharing. The default is `false`. So
`dsd capture --raw` writes every sysfs read and every command output verbatim — env vars,
process arguments, config file contents — into a tarball whose purpose is to leave the
building.

**What is already good here**, and should not be lost in the fix: the redactor is real
(`internal/source/sanitize.go`, `Bundle.Sanitize`, `redactSecretsAndJSON`,
`redactIdentifiers`), and `sanitizeDisclosureNote` reports a bundle's *actual* redaction
state to whoever opens it. That second mechanism is better than most tools in this
category have, and it is what makes flipping the default safe rather than merely
reassuring.

**Why the default is the whole issue.** A support bundle is captured by someone under
time pressure who runs the documented command and emails the result. An opt-in safety
control on an artifact designed to be sent to a third party will be missed, and the
failure is silent and unrecoverable — the secrets are in someone else's inbox before
anyone notices.

**Suggested fix:** default `--sanitize` to `true`, add `--no-sanitize` for the case that
genuinely needs raw bytes, keep the disclosure note on both paths.

**Checked, and it clears the obvious blocker:** `dsd replay` does not depend on
unsanitized input. `cmd/replay.go`'s only sanitization references are
`output.SanitizeControl` on manifest fields — control-character escaping for terminal
output, unrelated to credential redaction. And `Bundle.Sanitize` masks values in place
rather than dropping files or changing bundle structure.

**Not checked, and it is the one risk:** whether any collector or parser asserts on a
*value* that redaction would mask, such that a sanitized bundle replays differently from
a raw one. That needs a test — capture a bundle, sanitize it, replay both, diff the
output — and it is the test that should ship with the default flip.

---

## Why neither is implemented here

GAP-1 needs a product decision before any code is right. GAP-2 is nearly a one-line
change, but flipping a documented CLI default belongs with the replay-equivalence test
above, and that test has to be run, not reasoned about — the same rule this project
already applies everywhere else.
