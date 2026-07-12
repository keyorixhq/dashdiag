package cmd

// fleet_run_test.go covers resolveHosts (pure) and runFleet's flag-wiring,
// including one real (but read-only) SSH attempt against a non-routable
// address (192.0.2.1, TEST-NET-1 per RFC 5737) with a short connect-timeout
// so it fails fast without ever reaching a real network — same shell-out-to-
// real-tooling precedent as fleet's own package tests and net_test.go.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestResolveHosts(t *testing.T) {
	t.Parallel()
	t.Run("args only", func(t *testing.T) {
		t.Parallel()
		hosts, err := resolveHosts([]string{"web1", "web2"}, "")
		if err != nil {
			t.Fatalf("resolveHosts: %v", err)
		}
		if len(hosts) != 2 || hosts[0] != "web1" || hosts[1] != "web2" {
			t.Errorf("got %v, want [web1 web2]", hosts)
		}
	})

	t.Run("dedupes and skips blank/comment lines from args", func(t *testing.T) {
		t.Parallel()
		hosts, err := resolveHosts([]string{"web1", "", "web1", "#comment"}, "")
		if err != nil {
			t.Fatalf("resolveHosts: %v", err)
		}
		if len(hosts) != 1 || hosts[0] != "web1" {
			t.Errorf("got %v, want [web1] (deduped, blank/comment skipped)", hosts)
		}
	})

	t.Run("merges args and hosts-file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "hosts.txt")
		content := "web2\n# a comment\n\nweb3\nweb1\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		hosts, err := resolveHosts([]string{"web1"}, path)
		if err != nil {
			t.Fatalf("resolveHosts: %v", err)
		}
		want := []string{"web1", "web2", "web3"}
		if len(hosts) != len(want) {
			t.Fatalf("got %v, want %v", hosts, want)
		}
		for i, h := range want {
			if hosts[i] != h {
				t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], h)
			}
		}
	})

	t.Run("nonexistent hosts-file errors", func(t *testing.T) {
		t.Parallel()
		_, err := resolveHosts(nil, filepath.Join(t.TempDir(), "does-not-exist.txt"))
		if err == nil {
			t.Fatal("expected an error for a missing --hosts-file")
		}
	})
}

// newBareFleetCmd builds a bare cobra.Command with the flags runFleet reads.
func newBareFleetCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.String("hosts-file", "", "")
	f.String("bin", "", "")
	f.String("remote-cmd", "dsd health --json", "")
	f.Duration("connect-timeout", 8*time.Second, "")
	f.Duration("timeout", 45*time.Second, "")
	f.Int("concurrency", 8, "")
	c.SetContext(context.Background())
	return c
}

func TestRunFleetNoHosts(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareFleetCmd()
	err := runFleet(c, nil)
	if err == nil || !strings.Contains(err.Error(), "no hosts given") {
		t.Errorf("expected 'no hosts given' error, got: %v", err)
	}
}

func TestRunFleetBadBinPath(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareFleetCmd()
	_ = c.Flags().Set("bin", filepath.Join(t.TempDir(), "no-such-binary"))
	err := runFleet(c, []string{"web1"})
	if err == nil || !strings.Contains(err.Error(), "--bin") {
		t.Errorf("expected a --bin stat error, got: %v", err)
	}
}

// TestRunFleetUnreachableHost drives runFleet end to end against a
// non-routable address so it exercises the full happy path (fleet.Run,
// fleet.Summarize, printFleetTable, recordExitCode) without ever reaching a
// real host. A short connect-timeout keeps this fast.
func TestRunFleetUnreachableHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow real-ssh-attempt test in short mode")
	}
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareFleetCmd()
	_ = c.Flags().Set("plain", "true")
	_ = c.Flags().Set("connect-timeout", "1s")
	_ = c.Flags().Set("timeout", "3s")
	_ = c.Flags().Set("concurrency", "1")
	out := captureStdout(t, func() {
		if err := runFleet(c, []string{"192.0.2.1"}); err != nil {
			t.Fatalf("runFleet: %v", err)
		}
	})
	if !strings.Contains(out, "192.0.2.1") {
		t.Errorf("the fleet table should list the host, got:\n%s", out)
	}
	if !strings.Contains(out, "UNREACHABLE") {
		t.Errorf("a non-routable host should be reported UNREACHABLE, got:\n%s", out)
	}
	if pendingExitCode != 2 {
		t.Errorf("an unreachable host should record exit code 2, got %d", pendingExitCode)
	}
}

// TestRunFleetJSONMode covers the --json branch of runFleet against the same
// non-routable address.
func TestRunFleetJSONMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow real-ssh-attempt test in short mode")
	}
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	c := newBareFleetCmd()
	_ = c.Flags().Set("json", "true")
	_ = c.Flags().Set("connect-timeout", "1s")
	_ = c.Flags().Set("timeout", "3s")
	_ = c.Flags().Set("concurrency", "1")
	out := captureStdout(t, func() {
		if err := runFleet(c, []string{"192.0.2.1"}); err != nil {
			t.Fatalf("runFleet --json: %v", err)
		}
	})
	if !strings.Contains(out, `"host"`) {
		t.Errorf("--json should emit the summary as JSON, got:\n%s", out)
	}
}
