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
// outside ExecHook's reach by design), `tls` (CheckRemoteEndpoint dials out
// even with DSD_OFFLINE=1 — KV-TLS-OFFLINE-BYPASS — so it is not safe to let
// a fuzzer hand it arbitrary --endpoint values; proven separately by
// TestTLSEndpointBypassesOfflineGate against a loopback listener).
//
// Safety: $HOME and CWD are fresh t.TempDir()s every exec (never touches the
// real filesystem outside them), DSD_OFFLINE=1 is force-appended last so it
// always wins over any fuzzed env duplicate, stdin is empty (nil ==
// /dev/null), and every argv token containing a path separator is clamped to
// a plain relative filename component before use — dsd's --out/--report
// family will happily write to an operator-supplied ABSOLUTE path (a real,
// intentional feature — see the allowed-writes contract), which is exactly
// why this harness, running unsandboxed on a real machine, must never hand
// it one. No real network: DSD_OFFLINE=1 plus the `tls` exclusion above.

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
		if args[i] != p {
			return false
		}
	}
	return true
}

func checkAllowlist(t *testing.T, traces []execTrace) {
	t.Helper()
	for _, rec := range traces {
		base := filepath.Base(rec.Name)
		prefixes, known := execAllowlistContract[base]
		if !known {
			t.Fatalf("ALLOWLIST: dsd attempted to execute %q (args=%v) — binary not in execAllowlistContract", rec.Name, rec.Args)
		}
		if prefixes == nil {
			continue // nil == "any args" for this binary, see contract comments
		}
		matched := false
		for _, pfx := range prefixes {
			if pfx == nil || argsHavePrefix(rec.Args, pfx) {
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
	}
}

func checkOptionInjection(t *testing.T, traces []execTrace, fuzzedTokens map[string]bool) {
	t.Helper()
	for _, rec := range traces {
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

// isAllowedCWDWrite tolerates a CWD-relative ".dsd/..." write per
// KV-HOME-FAILOPEN-BASELINE/GOLDEN/SECBASELINE (knownviolations_test.go),
// proven directly by internal/baseline's TestHomeFailOpen_KnownViolations.
// This harness always sets a real $HOME, so that branch should not actually
// trigger here — kept so the tolerance stays wired to the same registry.
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
	return strings.HasPrefix(rel, ".dsd"+string(filepath.Separator))
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
