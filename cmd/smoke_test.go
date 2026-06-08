package cmd_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const dsdPkg = "github.com/keyorixhq/dashdiag/cmd/dsd"

func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", dsdPkg}, args...)...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	out := stdout.String()
	if out == "" {
		out = stderr.String()
	}
	return out, code
}

func TestVersion(t *testing.T) {
	out, _ := run(t, "--version")
	if !strings.Contains(out, "dsd") {
		t.Errorf("--version output missing 'dsd': %q", out)
	}
}

func TestHealthPlainExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	_, code := run(t, "health", "--plain")
	if code > 2 {
		t.Errorf("health --plain returned unexpected exit code %d (want 0, 1, or 2)", code)
	}
}

func TestHealthJSONValid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	out, code := run(t, "health", "--json")
	if code > 2 {
		t.Fatalf("health --json returned unexpected exit code %d", code)
	}
	s := strings.TrimSpace(out)
	if !strings.HasPrefix(s, "{") {
		t.Errorf("health --json output is not JSON: %q", s)
	}
	if !strings.Contains(s, `"checks"`) {
		t.Errorf("health --json missing 'checks' field: %q", s)
	}
}

// TestNetJSONValid guards against the regression where `dsd net --json` ignored
// the flag and printed the human report instead of JSON (the main runNet never
// read the json flag). It must emit valid JSON with a top-level "network" key.
func TestNetJSONValid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	out, code := run(t, "net", "--json")
	if code > 2 {
		t.Fatalf("net --json returned unexpected exit code %d", code)
	}
	s := strings.TrimSpace(out)
	if !json.Valid([]byte(s)) {
		t.Errorf("net --json output is not valid JSON: %q", s)
	}
	if !strings.Contains(s, `"network"`) {
		t.Errorf("net --json missing 'network' field: %q", s)
	}
}

// TestNetPlainNoEmoji guards that `dsd net --plain` emits ASCII status tokens
// (OK/WARN/CRIT) rather than ✅/⚠️/❌ — it used to leak emoji because the net
// report hardcoded glyphs instead of honoring the output mode. Covers the base
// report path (the only one a CI runner renders — no bonds/NFS/BIND present).
func TestNetPlainNoEmoji(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	out, code := run(t, "net", "--plain")
	if code > 2 {
		t.Fatalf("net --plain returned unexpected exit code %d", code)
	}
	for _, glyph := range []string{"✅", "⚠️", "❌", "ℹ️"} {
		if strings.Contains(out, glyph) {
			t.Errorf("net --plain leaked emoji %q (should be ASCII OK/WARN/CRIT): %q", glyph, out)
		}
	}
}

// TestSubcommandsPlainNoEmoji guards the --plain ASCII contract across every
// single-purpose subcommand. They used to hardcode status emoji in their
// renderers regardless of mode, leaking multibyte glyphs that ASCII parsers and
// log shippers choke on. All status glyphs now route through asciiOr/StatusIcon.
func TestSubcommandsPlainNoEmoji(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	cmds := []string{
		"cis", "cpu", "cron", "cve", "disk", "docker", "gpu", "hardware",
		"k8s", "kvm", "logs", "proc", "processes", "pve", "security",
		"services", "steamos", "thermal", "timeline", "tls",
	}
	glyphs := []string{"✅", "⚠️", "❌", "ℹ️", "⏳", "⏭️", "⏹", "🔴", "🟡", "🟢"}
	for _, c := range cmds {
		c := c
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			out, code := run(t, c, "--plain")
			if code > 2 {
				t.Fatalf("%s --plain returned unexpected exit code %d", c, code)
			}
			for _, g := range glyphs {
				if strings.Contains(out, g) {
					t.Errorf("%s --plain leaked emoji %q (must be ASCII OK/WARN/CRIT/INFO): %q", c, g, out)
				}
			}
		})
	}
}

func TestHealthOutputContainsCollectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow smoke test in short mode")
	}
	out, code := run(t, "health", "--json")
	if code > 2 {
		t.Fatalf("health --json returned unexpected exit code %d", code)
	}
	for _, collector := range []string{"CPU", "Memory", "Disk", "Network"} {
		if !strings.Contains(out, collector) {
			t.Errorf("health --json output missing collector %q", collector)
		}
	}
}
