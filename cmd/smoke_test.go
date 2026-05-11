package cmd_test

import (
	"os/exec"
	"strings"
	"testing"
)

const dsdPkg = "github.com/keyorixhq/dashdiag/cmd/dsd"

func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", dsdPkg}, args...)...)
	out, err := cmd.Output()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			out = exitErr.Stderr // fall back to stderr for non-JSON commands
		}
	}
	return string(out), code
}

func TestVersion(t *testing.T) {
	out, _ := run(t, "--version")
	if !strings.Contains(out, "dsd") {
		t.Errorf("--version output missing 'dsd': %q", out)
	}
}

func TestHealthPlainExitCode(t *testing.T) {
	_, code := run(t, "health", "--plain")
	if code > 2 {
		t.Errorf("health --plain returned unexpected exit code %d (want 0, 1, or 2)", code)
	}
}

func TestHealthJSONValid(t *testing.T) {
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

func TestHealthOutputContainsCollectors(t *testing.T) {
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
