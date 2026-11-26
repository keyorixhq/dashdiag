# INVARIANTS — MC4 target: real dsd_capture MCP handler, no-host-write

Targets: `cmd` · `FuzzMC4ToolCaptureNoHostWrite` (seamed data source, hot loop),
`TestMC4RealCollectorNoHostWrite` (unseamed full collector sweep, bounded),
`TestMC4FingerprintCatchesEscapedWrite` (red/green proof).

Scope: the PRODUCTION `toolCapture` handler driven over a real `mcp.Server`
`IOTransport` with a hostile-fuzzed `out_path` — `safeBundlePath` + real
`source.Recorder` + real `b.SaveTarball` → a real file on disk. This is the
read-only / no-host-write claim tested END TO END at the MCP layer, the gap MC1
target 1 (stubbed handlers, "a fingerprint oracle here would be vacuous") and
DL1 target 2 (`safeBundlePath` fuzzed in isolation) each left open.

Reading of "REAL toolCapture (not stubbed)": the handler and its write path run
for real; ONLY the data source (`runHealthOnceFn`) is seamed in the fuzz hot
loop, to a cheap deterministic stub, so the loop is reproducible and the shared
thermally-constrained host is not made to run a full `dsd health` sweep hundreds
of times. The unseamed full sweep is covered by `TestMC4RealCollectorNoHostWrite`
(a handful of iterations). Network stays OFF (default) throughout.

- **C1 no panic / bounded.** The real handler survives any `out_path` bytes
  without panicking; the drive stays under generous ABSOLUTE wall-time (7.5 s) and
  alloc (64 MiB) ceilings. (An amplification bound keyed to `len(out_path)` is NOT
  used: capture cost is fixed overhead, not input-proportional.)
- **C2 sentinel unchanged (LOAD-BEARING).** A fingerprinted sentinel tree OUTSIDE
  the server's cwd is byte-identical before and after every input. No `out_path`
  (traversal, absolute, symlink-looking, NUL, overlong, obfuscated `....//`) ever
  causes a write, delete, re-timestamp or re-permission there.
- **C3 writes land only under cwd (LOAD-BEARING).** Any new regular file after the
  call is under the cwd subtree (the `SaveTarball` destination); when
  `safeBundlePath` REJECTS the path, no new file appears at all.

Red/green: `TestMC4FingerprintCatchesEscapedWrite` disables containment
(`--allow-absolute-paths` / `mcpAllowAbsolutePaths=true`), captures to an absolute
path INSIDE the sentinel, and asserts the fingerprint oracle DOES observe the
escaped write — proving C2/C3 are live guards and characterising exactly what
`--allow-absolute-paths` gives up. GREEN: with the secure default, every seed +
fuzzed `out_path` leaves the sentinel untouched.

Does NOT verify: that the collector pipeline itself writes nothing (seamed in the
hot loop — see the unseamed companion test); bundle CONTENT / redaction
correctness; writes outside the two fingerprinted roots (cwd subtree + one
sibling sentinel — the sentinel is deliberately the traversal target, and C3's
"only under cwd" is the general catch); xattrs/ACLs (Fingerprint omits them); the
`--allow-absolute-paths` opt-out mode as a safe default (it is an explicit
operator choice; its blast radius is what the red/green test characterises).
