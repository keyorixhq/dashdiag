package cmd

// mcp_governance_test.go — completeness tripwire, same idiom as
// internal/render/sanitize_governance_test.go and this repo's other
// governance tests (internal/models/falseok_signal_registry_test.go,
// internal/collectors/parallel_mutation_governance_test.go,
// internal/render/status_switch_governance_test.go): it does not test
// behaviour, it tests that a class of bug cannot silently reappear.
//
// The bug class this closes: dsd_diff (toolDiff) returned DiffEntry[] over
// MCP with no call to redactMCPJSON, while dsd_health/dsd_replay (toolHealth/
// toolReplay) both do — added in the same commit (343d24f9) that introduced
// redactMCPJSON, on the stated reasoning "DiffEntry carries no raw/free-text
// fields." That reasoning was wrong then, not something that regressed
// later: DiffEntry.Before/After are `Status + " " + Value`, and Value has
// been models.Insight.Message (free text — e.g. heuristics_web.go's
// webConfigVerdict concatenates a config-test tool's raw stderr straight
// into a CRIT Message) since before dsd_diff existed. DiffEntry.Raw was
// never populated (ComputeDiff never copies CheckResult.Raw into a
// DiffEntry), so the one field the original fix's own doc comment names
// (checks[].raw) genuinely is absent — but redactMCPJSON was never scoped to
// that one field; RedactJSONSecrets walks every string leaf in the outbound
// document, and Message is exactly the kind of leaf it exists to catch.
//
// Fingerprint: every MCP tool handler function registered via mcp.AddTool in
// runMCP must call redactMCPJSON somewhere in its own body, or have a
// mcpGovernanceExemptions entry with a stated reason. The handler set is
// read mechanically from runMCP's own mcp.AddTool(...) calls, not
// hand-copied — a fifth tool added later is picked up automatically instead
// of depending on whoever adds it to also remember this test exists.
import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// mcpGovernanceExemptions lists MCP tool handler function names explicitly
// allowed to skip redactMCPJSON, each with the reason it's safe. A reason is
// required — this is not a suppression list.
var mcpGovernanceExemptions = map[string]string{
	// toolCapture returns mcpCaptureOutput (bundle_path, host, captured_at,
	// bytes, sanitized, note) via the MCP SDK's typed structured-output
	// path, not a hand-marshaled JSON text blob — none of those fields carry
	// collector-derived free text the way insights[].message/checks[].raw
	// do (bundle_path/captured_at are dsd-constructed, bytes is a count,
	// note is this file's own sanitizeDisclosureNote string, and host is
	// already redacted to a placeholder by Bundle.Sanitize when Identifiers
	// is set — see toolCapture's respHost handling). The bundle FILE's own
	// contents go through the separate Bundle.Sanitize opt-in
	// (sanitize-bundle-03), a different mechanism for a different surface
	// (the written file, not this response).
	"toolCapture": "structured mcpCaptureOutput carries no collector-derived free text; see sanitizeDisclosureNote/Bundle.Sanitize instead",
}

// TestEveryMCPToolHandlerRedactsSecrets is this file's completeness
// tripwire. See the file-level doc comment for the bug class and reasoning.
func TestEveryMCPToolHandlerRedactsSecrets(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	mcpGoPath := filepath.Join(filepath.Dir(thisFile), "mcp.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mcpGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", mcpGoPath, err)
	}

	handlers := registeredMCPToolHandlers(t, file)
	if len(handlers) < 4 {
		t.Fatalf("only found %d MCP tool handler(s) registered via mcp.AddTool in runMCP — "+
			"extraction is broken, this test would silently police nothing. Handlers found: %v",
			len(handlers), handlers)
	}

	funcs := make(map[string]*ast.FuncDecl, len(file.Decls))
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}

	var violations []string
	guardedCount := 0
	for _, name := range handlers {
		fn, ok := funcs[name]
		if !ok {
			t.Fatalf("runMCP registers handler %q via mcp.AddTool, but no function named %q is defined in %s — "+
				"extraction found a name that doesn't resolve, something is wrong with the walk", name, name, mcpGoPath)
		}

		guarded := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "redactMCPJSON" {
				guarded = true
			}
			return true
		})

		if guarded {
			guardedCount++
			continue
		}
		if reason, exempted := mcpGovernanceExemptions[name]; exempted {
			t.Logf("exempted %s: %s", name, reason)
			continue
		}
		violations = append(violations, name)
	}

	if guardedCount == 0 {
		t.Fatalf("found zero MCP tool handlers that call redactMCPJSON — the guard detector itself is broken " +
			"(expected toolHealth/toolReplay/toolDiff to count)")
	}

	sort.Strings(violations)
	if len(violations) > 0 {
		t.Errorf("%d MCP tool handler(s) registered via mcp.AddTool do not call redactMCPJSON:\n  %s\n\n"+
			"An MCP tool's outbound JSON commonly forwards straight into a cloud-hosted LLM's context "+
			"(see redactMCPJSON's own doc comment) — any collector-derived free text (Insight.Message, "+
			"checks[].raw, or equivalent) that reaches a tool response unredacted is a secret-shaped-content "+
			"leak, not just an out-of-contract field. Wrap the handler's outbound payload with redactMCPJSON, "+
			"or add an mcpGovernanceExemptions entry in this file with a stated reason if the handler's "+
			"response genuinely carries no collector-derived free text. (Completeness tripwire — see this "+
			"file's doc comment.)",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// registeredMCPToolHandlers walks runMCP's body and returns the handler
// function name (the last argument) from every mcp.AddTool(srv, &mcp.Tool{...},
// handlerFunc) call it finds — mechanically, from the actual registration
// call, not a hand-maintained list that could drift from what runMCP really
// registers.
func registeredMCPToolHandlers(t *testing.T, file *ast.File) []string {
	var runMCPFn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "runMCP" {
			runMCPFn = fn
			break
		}
	}
	if runMCPFn == nil || runMCPFn.Body == nil {
		t.Fatal("no runMCP function found in cmd/mcp.go — extraction is broken")
	}

	var handlers []string
	ast.Inspect(runMCPFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "AddTool" {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "mcp" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		last := call.Args[len(call.Args)-1]
		if id, ok := last.(*ast.Ident); ok {
			handlers = append(handlers, id.Name)
		}
		return true
	})
	return handlers
}
