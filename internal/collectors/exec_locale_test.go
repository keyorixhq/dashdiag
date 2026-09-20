package collectors

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every external command dsd runs must be PATH-trust resolved
// (platform.ResolveTrustedTool — dsd routinely runs as root, and the
// inherited $PATH is not trustworthy for a root process) and, if its
// stdout/stderr is parsed, locale-forced (platform.HardenedEnv — otherwise
// month/day names, decimal separators, and translatable status words are
// localized, and the parsers, which assume English/ASCII, silently break on
// non-English hosts; that was the timeline dmesg bug, #82: `dmesg -T` prints
// "[lun jun 8 ...]" on es_ES and the English layout couldn't parse it, so
// kernel events were dropped).
//
// This is a REPO-WIDE completeness tripwire, not a package-scoped one — it
// used to be (as TestCollectorsUseLocaleSafeExec, os.ReadDir(".") over just
// this directory), and that narrower scope was itself a live bug: the two
// real bypasses this class of guard exists to catch
// (internal/cvedata/rpm.go, internal/platform's former systemctl call) both
// lived OUTSIDE internal/collectors and were invisible to it. A guard whose
// enforcement is narrower than its doc comment's claim is worse than no
// guard — it produces a confident green over ground it never examined. See
// DEFECT-CLASSES.md's P2 principle and COLLECTOR-SWEEP.md.
//
// execWrapperFiles is keyed by path relative to the repo root (not basename)
// so a same-named file in a different package can't accidentally inherit
// another file's exemption. Every entry is a file that DEFINES a hardened
// exec primitive, or an explicitly documented, considered exception — see
// each comment. A newly-added raw exec anywhere else in the repo fails here.
//
// Note: exec.LookPath is intentionally allowed (it runs nothing, just resolves a
// path) — the regex below only matches command *execution*.
var execWrapperFiles = map[string]string{
	// Defines platform.ResolveTrustedTool / platform.HardenedEnv /
	// platform.ExecWaitDelay themselves — resolution, not execution.
	"internal/platform/trustedexec.go": "defines the primitives; does not itself exec",
	// internal/platform is contractually stdlib-only (cannot import
	// internal/source), so its own systemctl-is-active check resolves via
	// the in-package ResolveTrustedTool directly (P2 — moved here from
	// internal/source for exactly this reason).
	"internal/platform/profile.go": "systemctlIsActiveWithLookup, in-package ResolveTrustedTool/ExecWaitDelay",
	// The production exec path every collector (runCmd/runCmdOutput/
	// runCmdCombined) and localeSafeCmd route through.
	"internal/collectors/collector.go":   "localeSafeExec / localeSafeCmd, both platform.ResolveTrustedTool+HardenedEnv'd",
	"internal/collectors/disk_linux.go":  "runCmdTimeout",
	"internal/collectors/disk_darwin.go": "runDarwinCmd",
	// source.Live's default exec backend when no custom Exec is injected —
	// resolves via platform.ResolveTrustedTool; collectors override this
	// with localeSafeExec in production (see collector.go's init()), so
	// this path is a fallback (this package's own tests, mainly).
	"internal/source/live.go":           "defaultExec, platform.ResolveTrustedTool'd",
	"internal/drilldown/drilldown.go":   "runCmd, platform.ResolveTrustedTool+HardenedEnv'd",
	"internal/init/detector.go":         "newPSCmd, platform.ResolveTrustedTool+HardenedEnv'd",
	"internal/baseline/since_deploy.go": "platform.ResolveTrustedTool+HardenedEnv'd inline",
	"internal/cvedata/rpm.go":           "resolveRPM = platform.ResolveTrustedTool",
	"internal/cvedata/oval_debian.go":   "resolveDpkgQuery = platform.ResolveTrustedTool",
	"internal/inventory/inventory.go":   "resolveRPM = platform.ResolveTrustedTool",
	// Considered exception, not an oversight — see
	// internal/fleet/wontfix_spec_test.go (subprocess-wrappers-08,
	// VERIFICATION-2026-08.md §8): ssh/scp must resolve via the OPERATOR's
	// own $PATH (their ~/.ssh/config, keys, agent, a corporate wrapper
	// script, a non-standard install prefix) — PATH-trust would break the
	// feature's actual purpose, not harden it. ExecWaitDelay IS still
	// applied. Q4's test for the next exemption request: is PATH-following
	// the feature, and is this path explicitly non-root? If not, this is
	// not a transferable precedent.
	"internal/fleet/fleet.go": "ssh/scp — deliberately not PATH-trust resolved, see wontfix_spec_test.go",
}

// execLocaleWalkSkipDir reports whether the exec/locale governance walker
// must not descend into a directory named name. Dot-prefixed directories are
// skipped GENERICALLY — matching write_capable_callsites_test.go's
// walker — rather than via an enumerated list of names, because an
// enumerated list silently misses any dot-prefixed directory not already on
// it. That gap is exactly how this test used to walk into nested git
// worktrees: a worktree checkout carries its own full source tree (including
// a go.mod-rooted internal/ package layout), and this repo's own agent
// worktrees live under .claude/worktrees/<name> — but `git worktree add`
// can just as well produce one at any other dot-prefixed path (a bare
// `.git/worktrees/<name>` marker directory, a `.worktree-*` staging dir,
// etc.) that an enumerated list would never anticipate. A worktree's
// contents are a snapshot of some other (possibly half-finished, possibly
// divergent) branch, not part of the source tree this test governs, so none
// of it belongs in the scan regardless of what its directory happens to be
// named — as long as it's dot-prefixed. node_modules/vendor/dist are also
// never first-party source but aren't dot-prefixed, so they stay as an
// explicit list.
func execLocaleWalkSkipDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "node_modules", "vendor", "dist":
		return true
	}
	return false
}

// rawExecViolation is one non-exempt, non-test .go file containing an
// unwrapped exec.Command/CommandContext call.
type rawExecViolation struct {
	rel  string
	line int
}

var rawExecCallRe = regexp.MustCompile(`exec\.Command(Context)?\(`)

// findRawExecViolations walks root — applying execLocaleWalkSkipDir to every
// directory — and returns every non-test .go file (not in exempt) containing
// a raw exec.Command/CommandContext call, plus the total number of .go files
// examined (including exempted ones), so callers can sanity-check the walk
// actually covered the tree it claims to. Factored out of
// TestAllExecCallsResolveThroughTrustedWrapper so its own regression test
// (TestExecLocaleWalkSkipsDotPrefixedDirectories) exercises this EXACT
// walker against a fixture, rather than a reimplementation of it that could
// silently drift from the real one.
func findRawExecViolations(t *testing.T, root string, exempt map[string]string) ([]rawExecViolation, int) {
	t.Helper()
	var checked int
	var violations []rawExecViolation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if execLocaleWalkSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if _, ok := exempt[rel]; ok {
			checked++
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", rel, readErr)
			return nil
		}
		checked++
		if loc := rawExecCallRe.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			violations = append(violations, rawExecViolation{rel: rel, line: line})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for raw exec calls: %v", root, err)
	}
	return violations, checked
}

func TestAllExecCallsResolveThroughTrustedWrapper(t *testing.T) {
	root := repoRootForGovernanceTest(t)
	violations, checked := findRawExecViolations(t, root, execWrapperFiles)

	if checked < 400 { // sanity: repo has ~556 non-test .go files as of writing
		t.Fatalf("only checked %d files under %s — the walk is broken or root is wrong, "+
			"this test would silently police nothing", checked, root)
	}
	for _, v := range violations {
		t.Errorf("%s:%d calls exec.Command/CommandContext directly — route it through "+
			"platform.ResolveTrustedTool (+ platform.HardenedEnv if stdout/stderr is parsed) "+
			"so it isn't PATH-hijackable (dsd routinely runs as root) and, where relevant, "+
			"locale-stable (see #82). If raw exec is genuinely required (a documented, "+
			"considered exception — not the default), add the file to execWrapperFiles here "+
			"with a justifying comment, same bar as internal/fleet/fleet.go's.", v.rel, v.line)
	}
}

// TestExecLocaleWalkSkipsDotPrefixedDirectories is the regression proof for
// #1109: TestAllExecCallsResolveThroughTrustedWrapper's walker used to skip
// only an enumerated list of directory names (.scratch, .git, .claude,
// node_modules, vendor, dist), so a dot-prefixed directory NOT on that list —
// most concretely a nested git worktree checkout, which carries its own full
// go.mod-rooted source tree — was walked into and scanned as if it were
// first-party source. This exercises the SAME findRawExecViolations walker
// used by the real governance test (not a reimplementation of it) against a
// synthetic tree containing a dot-prefixed directory laid out like a nested
// worktree checkout (its own .git file plus an internal/collectors-shaped Go
// tree), and asserts the walker never reports a violation living inside it.
func TestExecLocaleWalkSkipsDotPrefixedDirectories(t *testing.T) {
	root := t.TempDir()

	// A raw, unwrapped exec.Command call directly under root: the walker
	// MUST still find this — proves the walker isn't vacuously skipping
	// everything.
	if err := os.WriteFile(filepath.Join(root, "control.go"),
		[]byte("package fixture\n\nimport \"os/exec\"\n\nfunc bad() { exec.Command(\"ls\") }\n"), 0o644); err != nil {
		t.Fatalf("writing control fixture: %v", err)
	}

	// A dot-prefixed directory NOT on the old enumerated skip list, laid out
	// like a nested git worktree checkout: its own .git FILE (the marker
	// `git worktree add` writes, pointing back at the real repo's
	// .git/worktrees/<name>) plus its own go source tree underneath — the
	// exact shape this repo's own agent worktrees take under
	// .claude/worktrees/<name>.
	worktreeDir := filepath.Join(root, ".worktree-fake-agent")
	worktreeGoDir := filepath.Join(worktreeDir, "internal", "collectors")
	if err := os.MkdirAll(worktreeGoDir, 0o755); err != nil {
		t.Fatalf("creating fake worktree dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeDir, ".git"),
		[]byte("gitdir: /somewhere/.git/worktrees/fake-agent\n"), 0o644); err != nil {
		t.Fatalf("writing fake worktree .git file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGoDir, "violation.go"),
		[]byte("package collectors\n\nimport \"os/exec\"\n\nfunc bad() { exec.Command(\"ls\") }\n"), 0o644); err != nil {
		t.Fatalf("writing worktree violation fixture: %v", err)
	}

	violations, checked := findRawExecViolations(t, root, map[string]string{})

	if checked < 1 {
		t.Fatalf("walk examined %d files — fixture setup is broken", checked)
	}

	foundControl := false
	for _, v := range violations {
		if v.rel == "control.go" {
			foundControl = true
		}
		if strings.HasPrefix(v.rel, ".worktree-fake-agent") {
			t.Errorf("walker descended into dot-prefixed worktree-like directory and flagged %s:%d — "+
				"it must skip any dot-prefixed directory entirely (filepath.SkipDir), not just the "+
				"enumerated names", v.rel, v.line)
		}
	}
	if !foundControl {
		t.Error("walker did not find the control violation directly under root — the walker itself " +
			"is broken, not just the skip logic (this test would pass vacuously)")
	}
}

// TestParsingIsLocaleStable guards the OTHER half of locale-safety: the forced-C
// wrapper above makes subprocess *strings* uniform, but numeric parsing relies
// on Go's strconv being locale-independent by design (it always reads '.' as the
// decimal separator, ignoring LC_NUMERIC). All ~260 numeric parses of tool
// output go through strconv. This test forces a comma-decimal locale into the
// process env and confirms strconv is unaffected — so if anyone ever swaps in a
// locale-sensitive parser (x/text scanning, cgo strtod, a locale-wired Sscanf),
// it fails here, loudly and deterministically, with no host or generated locale
// required. Validated live 2026-06-16 (es_ES on CT201): no leak; see TRIAGE.md.
func TestParsingIsLocaleStable(t *testing.T) {
	t.Setenv("LC_ALL", "es_ES.UTF-8")
	t.Setenv("LC_NUMERIC", "es_ES.UTF-8")
	t.Setenv("LANG", "es_ES.UTF-8")

	// Dot-decimal values exactly as df/free/proc/ping emit them.
	for _, c := range []struct {
		in   string
		want float64
	}{
		{"1234.56", 1234.56},
		{"0.266", 0.266},
		{"22.999288284369936", 22.999288284369936},
		{"3700", 3700},
	} {
		got, err := strconv.ParseFloat(c.in, 64)
		if err != nil || got != c.want {
			t.Errorf("ParseFloat(%q) = %v, %v under es_ES; want %v, nil — a "+
				"locale-sensitive numeric parser was introduced; tool output "+
				"is dot-decimal and must parse locale-independently", c.in, got, err, c.want)
		}
	}

	// strconv must REJECT a comma-decimal: proof it's strconv in the path and
	// not some comma-accepting locale parser that would misread "1234,56".
	if _, err := strconv.ParseFloat("1234,56", 64); err == nil {
		t.Error(`ParseFloat("1234,56") unexpectedly parsed — a comma-accepting ` +
			`locale-sensitive parser is in the numeric path`)
	}
}
