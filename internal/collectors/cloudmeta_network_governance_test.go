package collectors

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestOutboundNetworkCallsGatedByNetworkAllowed is a completeness tripwire for
// the exact bug class two sibling commits fixed:
//
//   - gap B (network calls off by default) landed at platform/cloud.go's
//     checkIMDS but missed every raw HTTP call in the cloud-metadata collector
//     subsystem — imdsGet, awsIMDSToken, awsSpotTermination, and probeIMDSOpen
//     all fired unconditional live requests to 169.254.169.254 regardless of
//     --network/DSD_ALLOW_NETWORK. One site was fixed; four siblings in the
//     same subsystem were not.
//   - the services-network-gate fix closed the same class in
//     internal/collectors/services.go: checkServiceLive dials an
//     operator-configured (but never operator-typed-AT-THIS-INVOCATION)
//     host:port with no opt-out — the target comes from an implicit
//     config.Load("") lookup ($HOME/.dsd.yaml), never a CLI flag.
//
// Both are the same "fixed here, missed there" shape this project's own
// review history (VERIFICATION-2026-08.md) has hit nine separate times, so
// this test covers both subsystems rather than existing as two near-identical
// guards. Scope is still deliberately narrower than all of internal/collectors:
// docker.go and netaccess_linux.go also call http.NewRequestWithContext, but
// both are enforced-loopback (Docker's local socket, requireLoopbackURL) — a
// different, already-audited class, not a network-off-by-default promise.
// Widening this test to the whole package would either false-flag those or
// require inventing an exemption for them that says nothing true about this
// bug class.
//
// Why call-graph aware, not a flat per-function check: this codebase's own
// established gate convention (network_quick.go's probeConnectivity, nfs_linux.go's
// nfsCollectServerReachability) places the gate in the WRAPPER function, one
// level above the function that actually builds the raw request — imdsGet
// gates, imdsGetLive makes the http.NewRequestWithContext call; checkService
// gates, checkServiceLive makes the HTTP/TCP call. A flat "does this exact
// function contain the gate" check would false-flag imdsGetLive/
// checkServiceLive forever. Instead: a function's raw call is considered
// gated if the function itself contains the check, OR every one of its
// callers (within this file set) is transitively gated — computed to a fixed
// point, which is sound for this codebase's shallow (1-2 level) wrapper/
// produce call shape and catches a genuinely-unprotected new site (no gated
// caller anywhere in the chain) exactly as reliably as a same-function check
// would.
func TestOutboundNetworkCallsGatedByNetworkAllowed(t *testing.T) {
	root := repoRootForGovernanceTest(t)
	dir := filepath.Join(root, "internal", "collectors")

	files := []string{
		"cloudmeta_linux.go",
		"aws_linux.go",
		"azure_linux.go",
		"gcp_linux.go",
		"oci_linux.go",
		"cloud_helpers_linux.go",
		"services.go",
	}

	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{} // name -> decl
	fileOf := map[string]string{}       // name -> relative file
	callees := map[string][]string{}    // name -> package-local functions it calls
	rawCallLine := map[string]int{}     // name -> line of its own raw network call, if any
	directlyGated := map[string]bool{}  // name -> contains platform.NetworkAllowed() itself

	for _, name := range files {
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if fn.Recv != nil {
				// Methods are excluded from the call-graph nodes entirely, not
				// just left unqualified: fn.Name.Name alone is NOT a unique key
				// across receivers — AWSCollector.Collect, AzureCollector.Collect,
				// GCPCollector.Collect, OCICollector.Collect, and
				// CloudMetaCollector.Collect all share the bare name "Collect".
				// Keying on that collapsed every one of them into a single graph
				// node, and one legitimately-gated Collect (CloudMetaCollector's,
				// via collectAWS -> awsIMDSToken) silently vouched for all the
				// others — caught by the reintroduce-the-gap drill in this
				// commit's own PR description, not by inspection. None of the
				// raw HTTP calls or NetworkAllowed() checks in this subsystem live
				// in a method body, so excluding methods from the graph loses no
				// real coverage — every method here only ever calls INTO the free
				// functions already tracked below.
				continue
			}
			funcs[fn.Name.Name] = fn
			fileOf[fn.Name.Name] = name

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					// DialContext is checked on the method name alone, not a
					// package-qualified name: services.go's TCP dial is
					// `d.DialContext(...)` on a local `*net.Dialer` variable,
					// not a package-level identifier — go/parser has no type
					// info to confirm the receiver is really a net.Dialer.
					// Matching the bare method name is a deliberate,
					// good-enough heuristic for this fixed, small file set:
					// no other DialContext-named method exists in it.
					if f.Sel.Name == "DialContext" {
						if rawCallLine[fn.Name.Name] == 0 {
							rawCallLine[fn.Name.Name] = fset.Position(call.Pos()).Line
						}
						return true
					}
					pkgIdent, ok := f.X.(*ast.Ident)
					if !ok {
						return true
					}
					switch pkgIdent.Name + "." + f.Sel.Name {
					case "http.NewRequestWithContext":
						if rawCallLine[fn.Name.Name] == 0 {
							rawCallLine[fn.Name.Name] = fset.Position(call.Pos()).Line
						}
					case "platform.NetworkAllowed":
						directlyGated[fn.Name.Name] = true
					}
				case *ast.Ident:
					// A bare call, e.g. imdsGetLive(...) — a same-package
					// function reference, potentially one of our own funcs.
					callees[fn.Name.Name] = append(callees[fn.Name.Name], f.Name)
				}
				return true
			})
		}
	}

	// callers[callee] = every function (within this file set) that calls it.
	callers := map[string][]string{}
	for caller, callees := range callees {
		for _, callee := range callees {
			if _, known := funcs[callee]; known {
				callers[callee] = append(callers[callee], caller)
			}
		}
	}

	// Fixed-point closure over TWO distinct protection shapes this codebase
	// actually uses:
	//   (a) wrapper-gates-then-calls-raw-fn (imdsGet -> imdsGetLive): a
	//       function is gated if every one of its known callers is gated.
	//   (b) fn-calls-gated-prerequisite-then-proceeds (awsRebalance calls
	//       the gated awsIMDSToken first and bails on its error before
	//       reaching its own raw call): a function is gated if it calls
	//       ANY target-set function that is itself gated. This slightly
	//       over-approximates (it doesn't verify the gated call happens
	//       strictly before the raw one and short-circuits on error) but
	//       matches this codebase's own established idiom everywhere —
	//       "check err first, bail early" — closely enough to be a real
	//       tripwire rather than a source of noise.
	gated := map[string]bool{}
	for name := range funcs {
		gated[name] = directlyGated[name]
	}
	for changed := true; changed; {
		changed = false
		for name := range funcs {
			if gated[name] {
				continue
			}
			if cs := callers[name]; len(cs) > 0 {
				allGated := true
				for _, c := range cs {
					if !gated[c] {
						allGated = false
						break
					}
				}
				if allGated {
					gated[name] = true
					changed = true
					continue
				}
			}
			for _, callee := range callees[name] {
				if gated[callee] {
					gated[name] = true
					changed = true
					break
				}
			}
		}
	}

	var violations []string
	for name, line := range rawCallLine {
		if gated[name] {
			continue
		}
		site := fmt.Sprintf("%s:%d", fileOf[name], line)
		violations = append(violations, fmt.Sprintf("%s | raw network call (http.NewRequestWithContext "+
			"or a Dialer.DialContext) in %s, not gated by platform.NetworkAllowed() and no fully-gated "+
			"caller found", site, name))
	}

	var real []string
	for _, v := range violations {
		site, _, found := strings.Cut(v, " | ")
		if found {
			if reason, exempted := outboundNetworkGateExemptions[site]; exempted {
				t.Logf("exempted %s: %s", site, reason)
				continue
			}
		}
		real = append(real, v)
	}
	sort.Strings(real)

	if len(real) > 0 {
		t.Errorf("%d outbound network call(s) not gated by platform.NetworkAllowed():\n  %s\n\n"+
			"Every http.NewRequestWithContext or Dialer.DialContext call in this file set must be "+
			"preceded — in the same function, or in every path that can call it — by an "+
			"`if !platform.NetworkAllowed() && !sourceIsReplaying()` check that returns before "+
			"building the request/dial. Match imdsGet/awsIMDSToken/awsSpotTermination/probeIMDSOpen/"+
			"checkService's existing shape, do not invent a new one. If a call is genuinely not "+
			"network-off-by-default's concern (e.g. proven loopback-only), add an "+
			"outboundNetworkGateExemptions entry in this file with a stated, verified reason — this "+
			"is not a suppression list.",
			len(real), strings.Join(real, "\n  "))
	}
}

// outboundNetworkGateExemptions lists "file.go:LINE" sites explicitly allowed
// to call http.NewRequestWithContext or Dialer.DialContext without a
// NetworkAllowed() check (directly or via every caller) in this file set,
// each with the reason it's safe. Empty today — every site found was gated,
// not exempted.
var outboundNetworkGateExemptions = map[string]string{}
