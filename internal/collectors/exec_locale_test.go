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

func TestAllExecCallsResolveThroughTrustedWrapper(t *testing.T) {
	root := repoRootForGovernanceTest(t)
	rawExec := regexp.MustCompile(`exec\.Command(Context)?\(`)

	var checked int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".scratch", ".git", ".claude", "node_modules", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		if _, exempt := execWrapperFiles[rel]; exempt {
			checked++
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			return nil
		}
		checked++
		if loc := rawExec.FindIndex(src); loc != nil {
			line := 1 + strings.Count(string(src[:loc[0]]), "\n")
			t.Errorf("%s:%d calls exec.Command/CommandContext directly — route it through "+
				"platform.ResolveTrustedTool (+ platform.HardenedEnv if stdout/stderr is parsed) "+
				"so it isn't PATH-hijackable (dsd routinely runs as root) and, where relevant, "+
				"locale-stable (see #82). If raw exec is genuinely required (a documented, "+
				"considered exception — not the default), add the file to execWrapperFiles here "+
				"with a justifying comment, same bar as internal/fleet/fleet.go's.", rel, line)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if checked < 400 { // sanity: repo has ~556 non-test .go files as of writing
		t.Fatalf("only checked %d files under %s — the walk is broken or root is wrong, "+
			"this test would silently police nothing", checked, root)
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
