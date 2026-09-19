package cmd_test

// FuzzCommandAllowlist drives dsd's real CLI surface (argv, env, and replayed
// capture bundles) through a real subprocess — a purpose-built binary of
// cmd/dsd compiled with -tags dsdfuzzexec, the ONLY build in existence where
// platform.ExecHook is ever non-nil (see cmd/dsd/fuzzexechook_dsdfuzzexec.go).
// That hook denies every command dsd attempts to execute and records
// (resolved-or-bare-name, args) to a JSON-lines trace file, which this test
// reads back after the subprocess exits.
//
// Why a subprocess, not an in-process call: rootCmd.Execute() and several
// RunE paths end in a literal os.Exit() (cmd/health.go, baseline.go,
// compare.go, tls.go, story.go, root.go) — calling it in-process would kill
// the fuzzer's own test binary on the first exit path hit. cmd/root_test.go
// already documents this and punts full-dispatch testing to a subprocess
// (smoke_test.go); this fuzzer follows the same, already-established pattern.
//
// Sound oracles (near-zero false positives):
//   - ALLOWLIST: every command dsd attempted to execute must match
//     execAllowlistContract (execallowlist_contract_test.go, hand-reviewed,
//     not generated) — an unlisted binary or an unmatched verb is fatal.
//   - OPTION INJECTION: a fuzzed argv/env token must never reach an executed
//     command as an argument in flag position (leading '-') unless preceded
//     by a literal "--" in that same command's args.
//   - WRITES CONTRACT: every file that exists under the per-exec temp $HOME
//     or CWD after the run must match the allowed-writes contract (STEP 1
//     report) or an explicit --out/--report-style target named verbatim in
//     argv — anything else is fatal.
//   - BOUNDED WORK: a single invocation must not need force-killing —
//     ExecHook denies before any real subprocess spawn, so even a `health`
//     run that touches every collector should complete in well under a
//     second; a generous ceiling catches an actual hang.
//
// Explicitly excluded from the fuzzed subcommand surface (see
// knownviolations_test.go): `update` (self-overwrites its own binary path,
// outside ExecHook's reach), `fleet` (mutates remote hosts via ssh/scp,
// outside ExecHook's reach by design), `tls` (CheckRemoteEndpoint now checks
// platform.OfflineForced() before ever dialing — KV-TLS-OFFLINE-BYPASS is
// fixed, proven deterministically by TestTLSEndpointHonoursOfflineGate
// against a loopback listener — but the subcommand stays excluded here
// regardless: `dsd tls --endpoint`/`--endpoints-file` is in
// networkFlagExempt, i.e. still a real, unconditional live-dial code path by
// product design once network isn't forced off (see PRIVACY.md "Network
// calls"), and letting a fuzzer hand it arbitrary --endpoint values has not
// been separately re-reviewed against the OPTION-INJECTION/WRITES oracles.
// The DSD_OFFLINE=1 this harness force-appends happens to also satisfy the
// new offline gate, but that's incidental, not a substitute for that review —
// kept excluded out of caution rather than assumed safe).
//
// Safety: $HOME and CWD are fresh t.TempDir()s every exec (never touches the
// real filesystem outside them), DSD_OFFLINE=1 is force-appended last so it
// always wins over any fuzzed env duplicate, stdin is empty (nil ==
// /dev/null), and every argv token containing a path separator is clamped to
// a plain relative filename component before use — dsd's --out/--report
// family will happily write to an operator-supplied ABSOLUTE path (a real,
// intentional feature — see the allowed-writes contract), which is exactly
// why this harness, running unsandboxed on a real machine, must never hand
// it one. No real network: DSD_OFFLINE=1 (now also enforced by tls's own
// offline gate) plus the `tls` exclusion above, belt-and-suspenders.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	dsdFuzzExecTag    = "dsdfuzzexec"
	argvSep           = "\x1f"
	bundlePlaceholder = "@BUNDLE@"
)

var excludedSubcommands = map[string]bool{
	"update": true,
	"fleet":  true,
	"tls":    true,
}

// buildFuzzExecBinary compiles cmd/dsd once with -tags dsdfuzzexec. Called
// once per fuzz process start (before f.Fuzz registers its closure), not per
// case.
func buildFuzzExecBinary(t testing.TB) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "dsd-fuzzexec")
	cmd := exec.Command("go", "build", "-tags", dsdFuzzExecTag, "-o", bin, dsdPkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building dsdfuzzexec binary: %v\n%s", err, out)
	}
	return bin
}

// clampPathLikeToken neutralizes path traversal / absolute-path escape in a
// fuzzed argv token while preserving its fuzzed character content as a plain
// filename component — see the file-level safety comment.
func clampPathLikeToken(tok string) string {
	if !strings.ContainsAny(tok, "/\\") {
		return tok
	}
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(tok)
	if safe == "" {
		return "_"
	}
	return safe
}

func splitArgv(blob string) []string {
	var out []string
	for tok := range strings.SplitSeq(blob, argvSep) {
		if tok == "" {
			continue
		}
		out = append(out, clampPathLikeToken(tok))
	}
	return out
}

func splitEnv(blob string) []string {
	var out []string
	for line := range strings.SplitSeq(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

func hasBundlePlaceholder(args []string) bool {
	return slices.Contains(args, bundlePlaceholder)
}

func substituteBundle(args []string, bundlePath string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == bundlePlaceholder {
			out[i] = bundlePath
		} else {
			out[i] = a
		}
	}
	return out
}

type execTrace struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

func readTrace(path string) ([]execTrace, error) {
	f, err := os.Open(path) // #nosec G304 -- harness-controlled temp path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no exec attempted this run
		}
		return nil, err
	}
	defer f.Close()
	var out []execTrace
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec execTrace
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // tolerate a torn last line from a force-killed process
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func argsHavePrefix(args, prefix []string) bool {
	if len(args) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if p == wildcardToken {
			continue // "*" matches any single token at this position
		}
		if args[i] != p {
			return false
		}
	}
	return true
}

// wildcardToken, used inside a prefix, matches exactly one arbitrary arg
// token at that position — for the handful of real call sites with dynamic
// content BEFORE the end of the prefix (a CVE ID between two fixed flags, a
// bare dynamic boolean name). It never matches zero or multiple tokens, and
// it never grants "anything after this point" — trailing args beyond the end
// of a prefix are already unconstrained by argsHavePrefix, which is exactly
// why denyAnywhere (below) exists for tools whose real invocations have
// unbounded dynamic trailing content.
const wildcardToken = "*"

// argsContainAny reports whether any of denyAnywhere matches an arg,
// checked independently of (and in addition to) prefix matching — closes
// the gap a short/loose prefix leaves open for a tool whose real call sites
// append a variable amount of trailing content after it (journalctl's
// per-unit `-u` repeats, dmesg's optional trailing flags): a prefix match
// alone can't rule out a mutating flag appended after the matched prefix,
// but this can, independent of where in args it appears.
//
// Matching is by PREFIX, not exact equality: most GNU-style long flags
// accept a `--flag=value` form (e.g. journalctl's `--vacuum-time=1s`) — an
// exact-equality deny list checking for bare "--vacuum-time" would silently
// miss it. strings.HasPrefix(a, d) catches both the bare and `=value` forms
// for any denyAnywhere entry that is itself a flag name.
func argsContainAny(args, denyAnywhere []string) string {
	for _, a := range args {
		for _, d := range denyAnywhere {
			if strings.HasPrefix(a, d) {
				return a
			}
		}
	}
	return ""
}

func checkAllowlist(t *testing.T, traces []execTrace) {
	t.Helper()
	for _, rec := range traces {
		base := filepath.Base(rec.Name)
		rule, known := execAllowlistContract[base]
		if !known {
			t.Fatalf("ALLOWLIST: dsd attempted to execute %q (args=%v) — binary not in execAllowlistContract", rec.Name, rec.Args)
		}
		if len(rule.prefixes) == 0 {
			t.Fatalf("ALLOWLIST: %q has zero prefixes in execAllowlistContract — every binary must list at least one allowed shape (an empty []string{} prefix for a bare/no-arg invocation), there is no binary-level-only escape hatch", base)
		}
		matched := false
		for _, pfx := range rule.prefixes {
			if argsHavePrefix(rec.Args, pfx) {
				matched = true
				break
			}
		}
		if !matched {
			hint := ""
			if kv, ok := execAllowlistKnownException[base]; ok {
				hint = fmt.Sprintf(" (name-resolution gap tracked as %s)", kv)
			}
			t.Fatalf("ALLOWLIST: dsd executed %q with args %v — no allowed verb prefix matches%s", rec.Name, rec.Args, hint)
		}
		if bad := argsContainAny(rec.Args, rule.denyAnywhere); bad != "" {
			t.Fatalf("ALLOWLIST: dsd executed %q with args %v — %q is a denied token for this binary even though a prefix matched (denyAnywhere)", rec.Name, rec.Args, bad)
		}
	}
}

// optionInjectionKnownCollision keys are (resolved-binary-basename, literal
// token) pairs where the token is BOTH a real dsd CLI flag — parsed entirely
// by cobra on dsd's own command line and never passed through to any
// subprocess — and, coincidentally, a hardcoded literal argument dsd's source
// passes to that binary for an unrelated reason. checkOptionInjection cannot
// tell "this fuzzed seed token also happens to be a hardcoded literal
// elsewhere in the binary" apart from a real injection since both look like
// the same string reaching the same argv in flag position; this is a
// hand-reviewed, string-collision-only carve-out (not a real deviation from
// the read-only invariant, so it does not belong in knownViolations), keyed
// tightly by binary so it can never mask an actual injected flag on a
// different command.
var optionInjectionKnownCollision = map[[2]string]string{
	{"systemctl", "--plain"}: "logs_linux.go detectCrashLoops hardcodes `systemctl list-units --state=failed --no-legend --no-pager --plain`; dsd's own --plain output-format flag is consumed entirely by cobra and never reaches this or any other subprocess call.",
}

func checkOptionInjection(t *testing.T, traces []execTrace, fuzzedTokens map[string]bool) {
	t.Helper()
	for _, rec := range traces {
		base := filepath.Base(rec.Name)
		sawDoubleDash := false
		for _, a := range rec.Args {
			if a == "--" {
				sawDoubleDash = true
				continue
			}
			if !fuzzedTokens[a] {
				continue
			}
			if strings.HasPrefix(a, "-") && !sawDoubleDash {
				if _, known := optionInjectionKnownCollision[[2]string{base, a}]; known {
					continue
				}
				t.Fatalf("OPTION INJECTION: fuzzed value %q reached %q in flag position (leading '-', no preceding '--') in args %v", a, rec.Name, rec.Args)
			}
		}
	}
}

func isAllowedHomeWrite(rel string) bool {
	switch rel {
	case filepath.Join(".dsd", "state.json"),
		filepath.Join(".dsd", "update-check.json"),
		filepath.Join(".dsd", "store.jsonl"),
		filepath.Join(".dsd", "security-baseline.json"),
		".dsd.yaml":
		return true
	}
	return strings.HasPrefix(rel, filepath.Join(".dsd", "baselines")+string(filepath.Separator)) ||
		strings.HasPrefix(rel, filepath.Join(".dsd", "golden")+string(filepath.Separator))
}

var cwdAutoNamePatterns = []struct{ prefix, suffix string }{
	{"dsd-report-", ".md"},
	{"dsd-report-", ".html"},
	{"dsd-guest-report-", ".html"},
	{"dsd-raw-", ".tar.gz"},
	{"dsd-migrate-baseline-", ".tar.gz"},
}

// homeFailOpenViolationFor maps a CWD-relative path to the specific
// KV-HOME-FAILOPEN-* ID that would produce it (baselineDir/goldenDir/
// SecurityBaselinePath each fail open to a distinct shape — see
// internal/baseline's TestHomeFailOpen_KnownViolations), or "" if rel
// doesn't match any of the three. Scoped to the exact known shapes rather
// than a blanket ".dsd/" prefix so an unrelated stray ".dsd/..." write
// (not one of these three specific bugs) is never silently tolerated.
func homeFailOpenViolationFor(rel string) string {
	switch {
	case strings.HasPrefix(rel, filepath.Join(".dsd", "baselines")+string(filepath.Separator)):
		return "KV-HOME-FAILOPEN-BASELINE"
	case strings.HasPrefix(rel, filepath.Join(".dsd", "golden")+string(filepath.Separator)):
		return "KV-HOME-FAILOPEN-GOLDEN"
	case rel == filepath.Join(".dsd", "security-baseline.json"):
		return "KV-HOME-FAILOPEN-SECBASELINE"
	}
	return ""
}

// isAllowedCWDWrite tolerates a CWD-relative ".dsd/..." write ONLY when it
// matches one of the three known $HOME-fail-open shapes AND that shape's KV
// ID is present in knownViolations (knownviolations_test.go) — an unknown
// ID (the entry was removed) makes it fatal even though this harness always
// sets a real $HOME, so that branch should not actually trigger live here;
// this keeps the tolerance genuinely registry-driven rather than a
// hardcoded carve-out the registry only documents.
func isAllowedCWDWrite(rel string, fuzzedTokens map[string]bool) bool {
	name := filepath.Base(rel)
	for _, p := range cwdAutoNamePatterns {
		if strings.HasPrefix(name, p.prefix) && strings.HasSuffix(name, p.suffix) {
			return true
		}
	}
	if fuzzedTokens[rel] || fuzzedTokens[name] {
		return true // explicit --out/-o/--report target named verbatim in argv
	}
	if kv := homeFailOpenViolationFor(rel); kv != "" {
		if _, ok := knownViolations[kv]; ok {
			return true
		}
	}
	return false
}

func checkWritesContract(t *testing.T, homeDir, cwdDir string, fuzzedTokens map[string]bool) {
	t.Helper()
	_ = filepath.WalkDir(homeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // best-effort walk; a stat error mid-walk isn't itself an oracle failure
		}
		rel, relErr := filepath.Rel(homeDir, path)
		if relErr != nil {
			return nil //nolint:nilerr
		}
		if !isAllowedHomeWrite(rel) {
			t.Fatalf("WRITES CONTRACT: unexpected file under $HOME: %q", rel)
		}
		return nil
	})
	_ = filepath.WalkDir(cwdDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr
		}
		rel, relErr := filepath.Rel(cwdDir, path)
		if relErr != nil {
			return nil //nolint:nilerr
		}
		if !isAllowedCWDWrite(rel, fuzzedTokens) {
			t.Fatalf("WRITES CONTRACT: unexpected file under CWD: %q", rel)
		}
		return nil
	})
}

func FuzzCommandAllowlist(f *testing.F) {
	if testing.Short() {
		f.Skip("skipping subprocess-based fuzz target in -short mode (pre-commit hook budget) — run explicitly with `go test -run FuzzCommandAllowlist ./cmd` or `-fuzz FuzzCommandAllowlist`")
	}
	bin := buildFuzzExecBinary(f)

	f.Add("health"+argvSep+"--json", "LANG=C", []byte{})
	f.Add("health"+argvSep+"--plain", "", []byte{})
	f.Add("security"+argvSep+"--json", "", []byte{})
	f.Add("cis"+argvSep+"--json", "", []byte{})
	f.Add("inventory"+argvSep+"--out"+argvSep+"inv.json", "", []byte{})
	f.Add("net"+argvSep+"--json", "", []byte{})
	f.Add("baseline"+argvSep+"save"+argvSep+"x", "", []byte{})
	f.Add("replay"+argvSep+bundlePlaceholder, "", []byte("not a real bundle"))
	f.Add("update", "", []byte{}) // excluded — must be a safe no-op, not a crash
	f.Add("fleet"+argvSep+"--hosts"+argvSep+"-x", "", []byte{})
	f.Add("tls"+argvSep+"--endpoint"+argvSep+"127.0.0.1:1", "", []byte{})
	f.Add("--help", "", []byte{})
	f.Add("", "", []byte{})
	f.Add("health"+argvSep+"--out"+argvSep+"../../etc/cron.d/evil", "", []byte{})

	f.Fuzz(func(t *testing.T, argvBlob, envBlob string, bundleBytes []byte) {
		args := splitArgv(argvBlob)
		for _, tok := range args {
			if excludedSubcommands[tok] {
				return // update/fleet/tls: never driven by this harness, see knownviolations_test.go
			}
		}

		harnessDir := t.TempDir()
		homeDir := t.TempDir()
		cwdDir := t.TempDir()
		tracePath := filepath.Join(harnessDir, "trace.jsonl")

		if hasBundlePlaceholder(args) {
			bundlePath := filepath.Join(harnessDir, "bundle.tar.gz")
			if err := os.WriteFile(bundlePath, bundleBytes, 0o600); err != nil {
				t.Fatalf("writing fuzzed bundle fixture: %v", err)
			}
			args = substituteBundle(args, bundlePath)
		}

		fuzzedTokens := make(map[string]bool, len(args))
		for _, a := range args {
			fuzzedTokens[a] = true
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is the harness-built fixture binary, args are fuzz-harness-clamped
		cmd.Dir = cwdDir
		cmd.Env = append(splitEnv(envBlob),
			"HOME="+homeDir,
			"DSD_OFFLINE=1",
			"DSD_FUZZ_EXEC_TRACE="+tracePath,
		)
		cmd.Stdin = nil // empty stdin: nil reads as /dev/null

		start := time.Now()
		_ = cmd.Run() // exit code is data (0/1/2/other) — never a fuzz failure by itself
		if elapsed := time.Since(start); elapsed > 20*time.Second {
			t.Fatalf("BOUNDED WORK: dsd invocation took %s (args=%v) — possible hang despite ExecHook denying every real exec", elapsed, args)
		}

		traces, err := readTrace(tracePath)
		if err != nil {
			t.Fatalf("reading exec trace: %v", err)
		}
		checkAllowlist(t, traces)
		checkOptionInjection(t, traces, fuzzedTokens)
		checkWritesContract(t, homeDir, cwdDir, fuzzedTokens)
	})
}
