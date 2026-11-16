//go:build linux

package readonly

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// plantedCollector is a RED test fixture: a collector that deliberately violates
// the read-only / no-network claim three ways. It is test-only and never added to
// allCollectors() — it exists solely so each oracle can be watched failing, then
// passing when the violation is absent (cleanCollector). "A guard nobody has
// watched fail is not a guard."
type plantedCollector struct {
	mutate, dial, write bool
}

func (plantedCollector) Name() string           { return "ro1-planted" }
func (plantedCollector) Timeout() time.Duration { return 5 * time.Second }

func (p plantedCollector) Collect(ctx context.Context) (any, error) {
	if p.mutate {
		// A mutating command via dsd's own hardened exec path, so platform.ExecHook
		// records it exactly as it would a real collector exec. `rm -rf` is not on
		// the read-only allowlist at all.
		if cmd, err := platform.RunHardened(ctx, "rm", "-rf", "/tmp/ro1-should-never-run"); err == nil && cmd != nil {
			_ = cmd.Run()
		}
	}
	if p.dial {
		// A non-loopback HTTP dial through http.DefaultClient (-> guarded transport).
		// 10.255.255.1 is non-loopback; the guard records+denies before any packet.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.255.255.1:80/", nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}
	if p.write {
		// A write under the pinned $HOME — the read-only-tree fingerprint must catch it.
		home := os.Getenv("HOME")
		_ = os.WriteFile(filepath.Join(home, "pwned.txt"), []byte("side effect\n"), 0o600)
	}
	return nil, nil
}

// cleanCollector is the GREEN counterpart: it does nothing observable.
type cleanCollector struct{}

func (cleanCollector) Name() string                         { return "ro1-clean" }
func (cleanCollector) Timeout() time.Duration               { return time.Second }
func (cleanCollector) Collect(context.Context) (any, error) { return nil, nil }

// probeResult is what runOneCollector observes, WITHOUT fataling — so the
// red/green test can assert on it directly.
type probeResult struct {
	treeChanged bool
	hostChanged bool
	execViol    string
	dialCount   int
	shimViol    string
}

// runOneProbe runs a single collector under the same pinned/denied environment as
// the fuzz target and returns the oracle observations without asserting.
func runOneProbe(t *testing.T, c runner.Collector) probeResult {
	t.Helper()
	runMu.Lock()
	defer runMu.Unlock()

	root := t.TempDir()
	watchedRoot := filepath.Join(root, "watched")
	home := filepath.Join(watchedRoot, "home")
	for _, d := range []string{home, filepath.Join(watchedRoot, "tmp"), filepath.Join(watchedRoot, "cwd")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	restore := envOverride(map[string]string{"HOME": home, "TMPDIR": filepath.Join(watchedRoot, "tmp")})
	defer restore()

	beforeTree := resource.Fingerprint(t, watchedRoot)
	beforeHost := resource.Fingerprint(t, watchedHostDir)

	recorder.reset()
	dialBase := guard.count()
	_ = readShimTrace()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range runner.RunAll(ctx, []runner.Collector{c}) {
	}

	afterTree := resource.Fingerprint(t, watchedRoot)
	afterHost := resource.Fingerprint(t, watchedHostDir)

	return probeResult{
		treeChanged: afterTree != beforeTree,
		hostChanged: afterHost != beforeHost,
		execViol:    execOracleViolation(recorder.snapshot()),
		dialCount:   guard.count() - dialBase,
		shimViol:    shimOracleViolation(readShimTrace()),
	}
}

// TestRedGreenPlantedCollectorIsCaught plants all three violations and asserts
// each independent oracle fires.
func TestRedGreenPlantedCollectorIsCaught(t *testing.T) {
	r := runOneProbe(t, plantedCollector{mutate: true, dial: true, write: true})
	if r.execViol == "" {
		t.Error("RED/exec: planted `rm -rf` was NOT caught by the exec oracle")
	} else {
		t.Logf("RED/exec caught: %s", r.execViol)
	}
	if r.dialCount == 0 {
		t.Error("RED/net: planted non-loopback dial was NOT caught by the net guard")
	} else {
		t.Logf("RED/net caught: %d non-loopback dial(s)", r.dialCount)
	}
	if !r.treeChanged {
		t.Error("RED/fs: planted $HOME write was NOT caught by the read-only fingerprint")
	} else {
		t.Logf("RED/fs caught: watched tree fingerprint changed")
	}
}

// TestRedGreenCleanCollectorPasses is the GREEN half: with the violations absent,
// every oracle stays silent — proving the guards are not firing spuriously.
func TestRedGreenCleanCollectorPasses(t *testing.T) {
	r := runOneProbe(t, cleanCollector{})
	if r.execViol != "" {
		t.Errorf("GREEN/exec: clean collector tripped exec oracle: %s", r.execViol)
	}
	if r.dialCount != 0 {
		t.Errorf("GREEN/net: clean collector recorded %d dials", r.dialCount)
	}
	if r.treeChanged {
		t.Error("GREEN/fs: clean collector changed the watched tree fingerprint")
	}
	if r.hostChanged {
		t.Error("GREEN/fs: clean collector changed the watched host fingerprint")
	}
	if r.shimViol != "" {
		t.Errorf("GREEN/shim: clean collector tripped shim oracle: %s", r.shimViol)
	}
}

// TestRedGreenExecOracleUnit exercises the exec oracle's verdicts directly over
// crafted traces — the pure-function half of the red/green proof.
func TestRedGreenExecOracleUnit(t *testing.T) {
	red := []struct {
		name string
		tr   execTrace
	}{
		{"unlisted binary", execTrace{Name: "/bin/rm", Args: []string{"-rf", "/x"}}},
		{"mutating verb on allowlisted binary", execTrace{Name: "/usr/bin/systemctl", Args: []string{"stop", "foo"}}},
		{"denyAnywhere token after read-only prefix", execTrace{Name: "/usr/bin/journalctl", Args: []string{"-u", "ssh", "--rotate"}}},
		{"dmesg clear", execTrace{Name: "/usr/bin/dmesg", Args: []string{"-C"}}},
	}
	for _, c := range red {
		if v := execOracleViolation([]execTrace{c.tr}); v == "" {
			t.Errorf("RED/exec-unit: %s was NOT caught", c.name)
		}
	}
	green := []execTrace{
		{Name: "/usr/bin/systemctl", Args: []string{"show", "sshd", "--property=ActiveEnterTimestamp", "--value"}},
		{Name: "/usr/bin/journalctl", Args: []string{"--verify", "--file=/var/log/journal/x.journal~"}},
		{Name: "/usr/bin/ps", Args: []string{"aux"}},
	}
	if v := execOracleViolation(green); v != "" {
		t.Errorf("GREEN/exec-unit: clean read-only traces tripped the oracle: %s", v)
	}
}

// TestRedGreenFingerprintUnit proves the DL1 fingerprint oracle distinguishes a
// touched tree from an untouched one.
func TestRedGreenFingerprintUnit(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o600)
	before := resource.Fingerprint(t, dir)
	if resource.Fingerprint(t, dir) != before {
		t.Fatal("GREEN/fs-unit: fingerprint of an untouched tree changed")
	}
	_ = os.WriteFile(filepath.Join(dir, "b"), []byte("2"), 0o600)
	if resource.Fingerprint(t, dir) == before {
		t.Fatal("RED/fs-unit: fingerprint did NOT change after adding a file")
	}
}
