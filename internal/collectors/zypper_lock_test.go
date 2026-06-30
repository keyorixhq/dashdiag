package collectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// dsd runs collectors in parallel, and zypper takes ONE coarse global lock
// (/run/zypp.pid). Whenever two collectors shell zypper at once the loser exits 7
// (ZYPP_LOCKED) with EMPTY stdout (the lock message goes to stderr). A site that
// derives its verdict from zypper's stdout TEXT instead of the exit code, and doesn't
// retry the lock, then silently drops a row or reads a false-OK — and ONLY under root,
// where the locking siblings actually run, so a single-privilege test never sees it.
// This class has bitten three times: #480 (security-update scan false-negative,
// BUG-058), #481 (integrity false-OK), and #661 (kernel reboot-to-apply silently
// dropped under root, BUG-088).
//
// TestZypperCallsAreLockAware is a COMPLETENESS TRIPWIRE, in the same spirit as
// exec_locale_test.go and models/falseok_signal_registry_test.go — NOT a correctness
// proof. It fails when a NEW zypper EXECUTION appears in a collector without a line in
// zypperLockHandling, forcing the author to consciously decide how that call survives
// the lock: retry on zypperLocked / exit-code 7 and key the verdict on the EXIT CODE
// (preferred — see suseRebootSignal / collectZypper), or document why it's lock-exempt.
// The registered note is a factual pointer to that decision, not a guarantee it's
// correct; the linked per-case tests are.
//
// Scope is zypper only: it's the proven offender because of its single exclusive
// global lock. rpm `-q` is lock-tolerant (read path) and the rpm/dpkg DB write paths
// are guarded in pkgDBHealth. Extend this if another coarse-global-lock tool joins the
// parallel run.
//
// Keyed by "file:subcommand" so two sites sharing a subcommand (the package collector
// and the CVE collector both run `list-patches`) are registered independently.
var zypperLockHandling = map[string]string{
	// ✅ Lock-hardened: retry on the lock + key on the exit code, never a false verdict.
	"maintenance_linux.go:needs-rebooting": "suseRebootSignal: exit code (0/102/7) + lock retry → CheckUnverified INFO on a held lock, never a dropped row or false 'Kernel OK' (#661/BUG-088; maintenance_linux_test.go).",
	"packages_linux.go:list-patches":       "collectZypper: zypperLocked retry ×5 → accurate 'query-failed' reason on a held lock, never a false-negative security scan (#480/BUG-058; packages_linux_test.go).",
	"packages_linux.go:verify":             "pkgIntegrityZypper: zypperLocked retry → VerifyLocked INFO on a held lock, never a silent clean integrity check (#481; packages_integrity_linux_test.go).",

	// ✅ Lock-exempt / honest-degrade: not retry-hardened, but a lock-loss can't produce
	// a false-OK green — it fails closed or surfaces an explicit unverified/failed state.
	"packages_linux.go:--version": "detection only (is zypper present?) — no verdict derived from the output; lock-exempt.",
	"packages_linux.go:repos":     "zypperHasSecurityRepo: a lock-loss errors → returns false ('no security repo'). Fail-CLOSED (pessimistic WARN, not a false-OK); the primary security scan (list-patches) already retries the lock, so this secondary signal is not retry-hardened.",
	"cve_linux.go:lp":             "checkCVEZypper (standalone `dsd cve <id>`, no concurrent zypper): `err != nil && len(out)==0` → CVEUnknown, so a lock degrades to honest Unknown, never a false NotAffected. NOTE: uses runCmd (drops stdout on a non-zero exit) — a separate under-report risk if `zypper lp` ever exits non-zero WITH a patch table; tracked apart from the lock class.",
	"cve_linux.go:list-patches":   "scanAllZypper (folded into `health --cve`, runs concurrently): a lock-loss → ScanFailed=true (CVEAllResult.ScanFailed, registered in the false-OK tripwire) → honest 'scan failed', never a false 'no CVEs'. Not retry-hardened — a retry would just upgrade an honest fail to a result.",

	// ✅ Deep advisory, fail-open accepted: a lock-loss skips a low-severity *advisory*
	// (not a health verdict). Documented acceptance, not a hardened path.
	"packages_linux.go:search": "grub-migration risk advisory (deep, `zypper migration` prep): a lock-loss errors → the risk is skipped (fail-open). Accepted as a low-severity deep advisory, never a health CRIT/false-OK; candidate for the lock retry only if it's ever promoted to a verdict.",
	"packages_linux.go:locks":  "grub-migration risk advisory (deep): paired with the 'search' site above; same fail-open-on-lock acceptance.",
}

// runCmdWrappers are the in-package exec helpers; a zypper call through any of them is
// an EXECUTION (vs hasCmd/lookPath/`case "zypper"`, which run nothing).
var runCmdWrappers = map[string]bool{
	"runCmd": true, "runCmdOutput": true, "runCmdCombined": true, "runCmdTimeout": true,
}

func TestZypperCallsAreLockAware(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	type site struct {
		file string
		line int
		sub  string
	}
	var found []site
	seenKey := map[string]bool{}

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || !runCmdWrappers[id.Name] {
				return true
			}
			// String-literal args in order (variable args like grubPkg are skipped —
			// they can't be the "zypper" command name in our call sites).
			var lits []string
			for _, a := range call.Args {
				if bl, ok := a.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					lits = append(lits, strings.Trim(bl.Value, "`\""))
				}
			}
			zi := -1
			for i, l := range lits {
				if l == "zypper" {
					zi = i
					break
				}
			}
			if zi < 0 {
				return true
			}
			// Subcommand = first non-flag literal after "zypper" (else the first flag,
			// e.g. "--version"), which uniquely names what the call does.
			sub := ""
			for _, l := range lits[zi+1:] {
				if !strings.HasPrefix(l, "-") {
					sub = l
					break
				}
			}
			if sub == "" && zi+1 < len(lits) {
				sub = lits[zi+1]
			}
			found = append(found, site{name, fset.Position(call.Pos()).Line, sub})
			seenKey[name+":"+sub] = true
			return true
		})
	}

	for _, s := range found {
		key := s.file + ":" + s.sub
		if _, ok := zypperLockHandling[key]; !ok {
			t.Errorf("%s:%d runs `zypper %s` but %q is not registered in zypperLockHandling.\n"+
				"  zypper holds one global lock (/run/zypp.pid); a sibling collector holding it makes this\n"+
				"  call exit 7 (ZYPP_LOCKED) with EMPTY stdout. Don't key a verdict on stdout text — retry on\n"+
				"  zypperLocked / exit-code 7 and decide on the EXIT CODE (see suseRebootSignal / collectZypper),\n"+
				"  then add a %q: line documenting the strategy. This class dropped a row 3× (#480/#481/#661).",
				s.file, s.line, s.sub, key, key)
		}
	}

	// Keep the registry honest: a documented site that no longer exists must be removed
	// (a stale note reads as coverage that isn't there).
	var stale []string
	for key := range zypperLockHandling {
		if !seenKey[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("zypperLockHandling has %d stale entr(y/ies) with no matching zypper call — remove: %s",
			len(stale), strings.Join(stale, ", "))
	}
}
