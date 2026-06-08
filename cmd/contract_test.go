package cmd

import (
	"os"
	"strings"
	"testing"
)

// Cross-cutting command contracts are a recurring trap: a behaviour that should
// hold for EVERY diagnostic command gets wired command-by-command, is applied to
// only some, and the gap is rediscovered much later. That is BUG-022 (the
// standalone exit-code contract, completed in #79) — and the same shape caused
// #74 (`dsd net` silently dropped --json) and the systemic --plain emoji leak.
//
// This file makes the omission impossible to merge silently: every registered
// subcommand must be EXPLICITLY classified for the exit-code contract, and every
// command that claims to "gate" must actually wire one of the exit mechanisms.
// A new (or previously-missed) command fails CI until someone makes the decision.

// exitCodeContract classifies each subcommand for the standalone exit-code
// contract (CRIT→2, WARN→1, clean→0). A registered command absent here fails
// TestEverySubcommandClassified — forcing the gates/exempt/todo decision.
var exitCodeContract = map[string]string{
	// Diagnostic commands that gate CI — must propagate findings to the exit code.
	"health": "gates", "cpu": "gates", "disk": "gates", "net": "gates",
	"docker": "gates", "k8s": "gates", "security": "gates", "services": "gates",
	"logs": "gates", "hardware": "gates", "thermal": "gates", "gpu": "gates",
	"cron": "gates", "cve": "gates", "fleet": "gates", "steamos": "gates",
	"tls": "gates",

	// Should gate but not wired yet — tracked follow-up (these can produce findings).
	"cis":       "todo: compliance pass/fail not yet mapped to the exit code",
	"kvm":       "todo: VM error diagnostics not yet wired",
	"pve":       "todo: node/task errors not yet wired",
	"proc":      "todo: assess whether D-state / fd leaks should gate",
	"processes": "todo: assess whether zombie/hung detection should gate",

	// Deliberately exempt — not a current-state health check.
	"timeline":  "exempt: forensic reconstruction of past events, not current state",
	"inventory": "exempt: informational CMDB export",
	"decode":    "exempt: renders a shared report blob, does not diagnose the local host",
	"update":    "exempt: self-updater",
	"baseline":  "exempt: security-baseline save/diff utility",
	"compare":   "exempt: report diff utility",
	"capture":   "exempt: dev capture utility",
	"examples":  "exempt: prints usage examples",
	"hook":      "exempt: internal hook helper",
	"mock":      "exempt: dev mock utility",
	"policy":    "exempt: prints policy info",
	"story":     "exempt: dev/demo utility",
	"tips":      "exempt: prints tips",

	// cobra built-ins.
	"completion": "exempt: cobra builtin",
	"help":       "exempt: cobra builtin",
}

// TestEverySubcommandClassified is the BUG-022 guard: a registered subcommand
// not present in exitCodeContract fails here, so a new command cannot silently
// skip the exit-code decision the way logs/services/net/cpu/… once did.
func TestEverySubcommandClassified(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		name := c.Name()
		if _, ok := exitCodeContract[name]; !ok {
			t.Errorf("subcommand %q is unclassified for the exit-code contract.\n"+
				"Add it to exitCodeContract in contract_test.go as \"gates\" (then wire "+
				"recordResultSeverity / a severity-derived os.Exit) or an explicit "+
				"\"exempt:<reason>\" / \"todo:<reason>\".\n"+
				"This guard prevents BUG-022 — a contract applied to only some commands.", name)
		}
	}
}

// exitMechanisms are the primitives a "gates" command may use to honour the
// contract: the shared runDiagnostic builder (which applies it by construction —
// the strongest option), the lower-level recorder, or a severity-derived os.Exit.
var exitMechanisms = []string{
	"runDiagnostic",
	"recordResultSeverity", "recordWorstInsight", "recordExitCode",
	"recordCVEResultSeverity", "PrintSummary", "os.Exit",
}

// TestGatesCommandsWireExitCode confirms a "gates" classification is not a lie:
// the command's source must reference an exit mechanism. Catches the case where
// a command is declared to gate but the wiring was never added.
func TestGatesCommandsWireExitCode(t *testing.T) {
	for name, status := range exitCodeContract {
		if status != "gates" {
			continue
		}
		src, err := os.ReadFile(name + ".go")
		if err != nil {
			t.Errorf("%q is \"gates\" but %s.go is unreadable (%v) — if its RunE lives "+
				"in another file, point this test at it", name, name, err)
			continue
		}
		body := string(src)
		wired := false
		for _, m := range exitMechanisms {
			if strings.Contains(body, m) {
				wired = true
				break
			}
		}
		if !wired {
			t.Errorf("%q is classified \"gates\" but %s.go wires no exit mechanism %v — "+
				"add recordResultSeverity(...) or fix the classification", name, name, exitMechanisms)
		}
	}
}

// ── --json contract (prevents the #74 class: a command silently ignoring --json
// and printing the human report) ──────────────────────────────────────────────

// jsonContract classifies each subcommand for --json. "json" = a diagnostic
// command that must emit machine-readable JSON; otherwise a documented exemption
// (meta/utility commands that have no data payload).
var jsonContract = map[string]string{
	"health": "json", "cpu": "json", "disk": "json", "net": "json",
	"docker": "json", "k8s": "json", "security": "json", "services": "json",
	"logs": "json", "hardware": "json", "thermal": "json", "gpu": "json",
	"cron": "json", "cve": "json", "fleet": "json", "steamos": "json",
	"tls": "json", "timeline": "json", "cis": "json", "kvm": "json",
	"pve": "json", "proc": "json", "processes": "json", "inventory": "json",

	"baseline":   "exempt: save/diff utility, no data payload",
	"compare":    "exempt: report diff utility",
	"decode":     "exempt: not a diagnostic; --json passes through the decoded report's own JSON",
	"update":     "exempt: self-updater",
	"capture":    "exempt: dev capture utility",
	"examples":   "exempt: prints usage examples",
	"hook":       "exempt: internal hook helper",
	"mock":       "exempt: dev mock utility",
	"policy":     "exempt: prints policy info",
	"story":      "exempt: dev/demo utility",
	"tips":       "exempt: prints tips",
	"completion": "exempt: cobra builtin",
	"help":       "exempt: cobra builtin",
}

// jsonMechanisms are the ways a command may satisfy --json: the builder (which
// owns the --json split), the shared encoder, or a direct json marshal.
var jsonMechanisms = []string{
	"runDiagnostic", "outputJSON", "ModeJSON", "json.Marshal", "json.NewEncoder", "isJSON",
}

// TestEverySubcommandClassifiedForJSON forces every registered command into the
// --json classification — a new command can't silently skip --json the way `net`
// did (#74).
func TestEverySubcommandClassifiedForJSON(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if _, ok := jsonContract[c.Name()]; !ok {
			t.Errorf("subcommand %q is unclassified for the --json contract — add it to "+
				"jsonContract as \"json\" (wire runDiagnostic/outputJSON) or \"exempt:<reason>\". "+
				"Prevents the #74 class (a command that ignores --json and prints the human report).",
				c.Name())
		}
	}
}

// TestJSONCommandsWireJSON confirms a "json" classification is not a lie: the
// command's source must reference a JSON mechanism.
func TestJSONCommandsWireJSON(t *testing.T) {
	for name, status := range jsonContract {
		if status != "json" {
			continue
		}
		src, err := os.ReadFile(name + ".go")
		if err != nil {
			t.Errorf("%q is \"json\" but %s.go is unreadable (%v)", name, name, err)
			continue
		}
		body := string(src)
		wired := false
		for _, m := range jsonMechanisms {
			if strings.Contains(body, m) {
				wired = true
				break
			}
		}
		if !wired {
			t.Errorf("%q is classified \"json\" but %s.go wires no JSON mechanism %v — "+
				"route it through runDiagnostic or emit outputJSON", name, name, jsonMechanisms)
		}
	}
}
