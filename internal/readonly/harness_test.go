//go:build linux

package readonly

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// allCollectors instantiates every collector the harness drives, directly via its
// exported constructor, with a zero ContainerContext/Profile. This is a SUPERSET
// of a real `dsd health` run: cmd.buildHealthRegistry gates many of these behind
// a probe (no GPU -> no GPU collector), but for the read-only claim we WANT to run
// each one unconditionally — a collector that only ever mutates on a host where
// its probe passes is still a collector that must be proven read-only. Each is
// run through runner.RunAll exactly as production does.
//
// It is intentionally explicit (not reflection-driven) so a reviewer can see
// precisely what is and is not exercised; collectors needing a non-trivial
// constructor argument the harness cannot synthesise safely (e.g. NewProcCollector
// for a specific live PID) are omitted and listed in the report's coverage gap.
func allCollectors() []collectors.Collector {
	cc := platform.ContainerContext{}
	return []collectors.Collector{
		// --- always-on resource / host introspection ---
		collectors.NewMemoryCollector(cc),
		collectors.NewSwapCollector(cc),
		collectors.NewDiskCollector(cc),
		collectors.NewDiskDeepCollector(),
		collectors.NewCPUCollector(cc),
		collectors.NewIOCollector(),
		collectors.NewClockCollector(),
		collectors.NewFDLimitsCollector(),
		collectors.NewProcessesCollector(),
		collectors.NewSysctlCollector(),
		collectors.NewKernelSecurityCollector(),
		collectors.NewEntropyCollector(),
		collectors.NewHugePagesCollector(),
		collectors.NewPressureCollector(),
		collectors.NewNUMACollector(),
		collectors.NewHardwareCollector(),
		collectors.NewFirmwareCollector(),
		collectors.NewThermalCollector(),
		collectors.NewSessionsCollector(),
		collectors.NewRootFSCollector(),
		collectors.NewFstabDriftCollector(),
		collectors.NewFirmwareCollector(),
		// --- services / system state ---
		collectors.NewSystemdCollector(),
		collectors.NewServicesCollector(),
		collectors.NewServicesDeepCollector(),
		collectors.NewDBusCollector(),
		collectors.NewAuthCollector(),
		collectors.NewLogsCollector(),
		collectors.NewSecurityCollector(),
		collectors.NewPostBootCollector(),
		collectors.NewCronCollector(),
		collectors.NewAuditCollector(),
		// --- exec-heavy (every external command is denied by ExecHook) ---
		collectors.NewPackagesCollector(),
		collectors.NewPackagesDeepCollector(),
		collectors.NewFirewallCollector(),
		collectors.NewGPUCollector(),
		collectors.NewGPUDeepCollector(),
		collectors.NewNVMeCollector(),
		collectors.NewRAIDCollector(),
		collectors.NewHWRaidCollector(),
		collectors.NewZFSCollector(),
		collectors.NewLVMCollector(),
		collectors.NewMultipathCollector(),
		collectors.NewCephCollector(),
		collectors.NewDRBDCollector(),
		collectors.NewBondingCollector(),
		collectors.NewVLANCollector(),
		collectors.NewInfiniBandCollector(),
		collectors.NewSRIOVCollector(),
		collectors.NewISCSICollector(),
		collectors.NewHBACollector(),
		collectors.NewCPUFreqCollector(),
		collectors.NewBatteryCollector(),
		collectors.NewNUMACollector(),
		// --- network-dialing (exercise the net guard) ---
		collectors.NewNetworkCollector(),
		collectors.NewNetworkDeepCollector(),
		collectors.NewDNSCollector(),
		collectors.NewDNSResolverCollector(),
		collectors.NewCloudMetaCollector(),
		collectors.NewNFSCollector(),
		collectors.NewAWSCollector(),
		collectors.NewAzureCollector(),
		collectors.NewGCPCollector(),
		collectors.NewOCICollector(),
		collectors.NewVMwareCollector(),
		collectors.NewNetworkdConfigCollector(),
		// --- container / virt ---
		collectors.NewDockerCollector(),
		collectors.NewDockerDeepCollector(),
		collectors.NewKVMCollector(),
		collectors.NewPVECollector(),
		collectors.NewContainerdCollector(),
		collectors.NewNspawnCollector(),
		collectors.NewHACollector(),
		collectors.NewContainerGuestCollector(),
		collectors.NewKVMGuestCollector(),
		// --- DB clients ---
		collectors.NewPostgresCollector(),
		collectors.NewMySQLCollector(),
		collectors.NewMongoDBCollector(),
		collectors.NewRedisCollector(),
		// --- web / infra services ---
		collectors.NewNginxCollector(),
		collectors.NewApacheCollector(),
		collectors.NewHAProxyCollector(),
		collectors.NewTraefikCollector(),
		collectors.NewPrometheusCollector(),
		collectors.NewGrafanaCollector(),
		collectors.NewVaultCollector(),
		collectors.NewElasticsearchCollector(),
		collectors.NewKafkaCollector(),
		collectors.NewRabbitMQCollector(),
		collectors.NewMemcachedCollector(),
		collectors.NewAlertmanagerCollector(),
		collectors.NewEnvoyCollector(),
		collectors.NewBINDCollector(),
		// --- maintenance / misc ---
		collectors.NewTunedCollector(),
		collectors.NewKdumpCollector(cc),
		collectors.NewKernelPatchCollector(cc),
		collectors.NewKernelRetentionCollector(cc),
		collectors.NewLivePatchCollector(cc),
		collectors.NewTransactionalCollector(cc),
		collectors.NewServiceRestartCollector(),
		collectors.NewSUSEConnectCollector(),
		collectors.NewSnapperCollector(),
		collectors.NewCVEHealthCollector(),
		collectors.NewMTECollector(),
		collectors.NewOOMCollector(),
		collectors.NewSteamOSCollector(),
		collectors.NewCloudInitCollector(),
		collectors.NewTLSCollector(),
	}
}

// watchedHostDir is a persistent sentinel tree, populated once, that lives
// OUTSIDE every per-input temp dir. It stands in for "arbitrary host paths dsd
// has no business touching": any write into it during a collector run is caught
// by its before/after fingerprint. Set in the first call to setupWatchedHostDir.
// watchedHostDir is created once in TestMain (NOT via a per-subtest t.Cleanup,
// which would delete it after the first input and break every later input).
var watchedHostDir string

// buildWatchedHostDir is called from TestMain. It populates a persistent sentinel
// tree outside every per-input temp dir.
func buildWatchedHostDir() (string, error) {
	dir, err := os.MkdirTemp("", "ro1-watched-host-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "sentinel-a"), []byte("do not touch A\n"), 0o644); err != nil { //nolint:gosec
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "sentinel-b"), []byte("do not touch B\n"), 0o644); err != nil { //nolint:gosec
		return "", err
	}
	return dir, nil
}

// procFixtureNames are the /proc entries gopsutil-backed collectors may read when
// HOST_PROC redirects them. They are filled with fuzzed content.
var procFixtureNames = []string{
	"meminfo", "swaps", "vmstat", "mounts", "stat", "loadavg", "cpuinfo",
	"diskstats", "uptime", "filefd", "sys/kernel/hostname", "sys/kernel/osrelease",
	"net/dev", "net/tcp", "self/status", "self/stat", "self/cgroup",
}

// sysFixtureNames are the /sys entries that HOST_SYS redirects for gopsutil.
var sysFixtureNames = []string{
	"class/net/eth0/statistics/rx_bytes",
	"class/thermal/thermal_zone0/temp",
	"block/sda/queue/rotational",
	"fs/cgroup/memory.current",
}

// writeFuzzedTree lays down a /proc or /sys tree whose file contents are slices of
// the fuzzed blob, so the tree is huge/negative/truncated/garbage as the fuzzer
// explores. It never writes outside root.
func writeFuzzedTree(t *testing.T, root string, names []string, blob []byte) {
	t.Helper()
	for i, name := range names {
		p := filepath.Join(root, filepath.Clean("/"+name)) // clamp any traversal in name (names are static, defensive)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
		}
		var content []byte
		if len(blob) > 0 {
			// Different slice per file so they are not all identical.
			start := (i * 7) % len(blob)
			content = blob[start:]
			if len(content) > 1<<16 {
				content = content[:1<<16]
			}
		}
		if err := os.WriteFile(p, content, 0o644); err != nil { //nolint:gosec // fixture file
			t.Fatalf("write %s: %v", p, err)
		}
	}
}

// envOverride sets each k=v, remembers the prior value, and returns a restore
// func. Used under runMu, so the process env is single-writer for the run.
func envOverride(pairs map[string]string) func() {
	type prev struct {
		val string
		set bool
	}
	saved := make(map[string]prev, len(pairs))
	for k, v := range pairs {
		old, ok := os.LookupEnv(k)
		saved[k] = prev{val: old, set: ok}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, p := range saved {
			if p.set {
				_ = os.Setenv(k, p.val)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}
}

// parseEnvBlob turns a fuzzed "K=V\nK2=V2" blob into a bounded map of extra env
// vars. It drops the network-policy and path-pinning keys the harness owns, so a
// fuzzed DSD_ALLOW_NETWORK can't flip the run out of the default read-only mode
// whose claim is under test, and a fuzzed HOME/TMPDIR/PATH can't un-pin the dirs.
func parseEnvBlob(blob string) map[string]string {
	reserved := map[string]bool{
		"DSD_ALLOW_NETWORK": true, "DSD_OFFLINE": true,
		"HOME": true, "TMPDIR": true, "TMP": true, "TEMP": true,
		"PATH": true, "HOST_PROC": true, "HOST_SYS": true,
		"DSD_RO1_SHIM_TRACE": true, "DSD_FUZZ_EXEC_TRACE": true,
	}
	out := make(map[string]string)
	for _, line := range strings.Split(blob, "\n") {
		if len(out) >= 32 {
			break
		}
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" || reserved[k] || strings.ContainsAny(k, "\x00=") {
			continue
		}
		out[k] = v
	}
	return out
}

// runAllCollectorsOnce drives every collector through the real runner with a
// bounded parent context. Returns nothing; its side effects (exec attempts, dials,
// writes) are what the oracles inspect.
func runAllCollectorsOnce() { runCollectorsOnce(allRunnerCollectors(), 4*time.Second) }

// allRunnerCollectors adapts allCollectors() to []runner.Collector.
func allRunnerCollectors() []runner.Collector {
	src := allCollectors()
	out := make([]runner.Collector, len(src))
	for i, c := range src {
		out[i] = c
	}
	return out
}

// runCollectorsOnce drives the given collectors through the real runner under a
// bounded parent context. The cap only trims a blocking collector's idle wait;
// every external command is denied instantly by ExecHook and every non-loopback
// dial instantly by the guard, so the attempt-phase work the oracles inspect is
// complete well before the deadline.
func runCollectorsOnce(cols []runner.Collector, maxWait time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()
	for range runner.RunAll(ctx, cols) {
		// drain; a collector error/panic is captured in the Result, not our concern
	}
}

// fastCollectors is the input-sensitive, non-blocking subset: collectors that read
// /proc, /sys or the environment and return quickly (no multi-second sampling, no
// network probe, no statfs-on-stale-mount). FuzzReadOnlyClaimFast drives these at
// high throughput so the fuzzed env/proc/sys content is actually explored, while
// FuzzReadOnlyClaim drives the full superset for breadth (lower throughput).
func fastCollectors() []runner.Collector {
	cc := platform.ContainerContext{}
	src := []collectors.Collector{
		collectors.NewMemoryCollector(cc),
		collectors.NewSwapCollector(cc),
		collectors.NewDiskCollector(cc),
		collectors.NewCPUCollector(cc),
		collectors.NewFDLimitsCollector(),
		collectors.NewSysctlCollector(),
		collectors.NewKernelSecurityCollector(),
		collectors.NewEntropyCollector(),
		collectors.NewHugePagesCollector(),
		collectors.NewPressureCollector(),
		collectors.NewNUMACollector(),
		collectors.NewSessionsCollector(),
		collectors.NewSteamOSCollector(),
		collectors.NewClockCollector(),
		collectors.NewRootFSCollector(),
		collectors.NewFstabDriftCollector(),
	}
	out := make([]runner.Collector, len(src))
	for i, c := range src {
		out[i] = c
	}
	return out
}

// oracleResult carries what one input produced, for optional reporting.
type oracleResult struct {
	execs     []execTrace
	dials     []dialViolation
	shimLines []string
}

// execOracleViolation returns a non-empty message if any recorded exec is NOT an
// allowlisted, read-only, non-mutating command. Identical semantics to
// cmd.FuzzCommandAllowlist's checkAllowlist, applied to the in-process ExecHook
// trace. Returning (rather than t.Fatalf) makes the oracle directly testable by
// the red/green proof.
func execOracleViolation(execs []execTrace) string {
	for _, rec := range execs {
		base := filepath.Base(rec.Name)
		rule, known := execAllowlistContract[base]
		if !known {
			return fmt.Sprintf("EXEC ALLOWLIST: dsd attempted to execute %q (args=%v) — binary not on the read-only allowlist", rec.Name, rec.Args)
		}
		if len(rule.prefixes) == 0 {
			return fmt.Sprintf("EXEC ALLOWLIST: %q has zero prefixes — every binary must list at least one allowed shape", base)
		}
		matched := false
		for _, pfx := range rule.prefixes {
			if argsHavePrefix(rec.Args, pfx) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Sprintf("EXEC ALLOWLIST (mutating/unknown arg): dsd executed %q with args %v — no read-only verb prefix matches", rec.Name, rec.Args)
		}
		if bad := argsContainAny(rec.Args, rule.denyAnywhere); bad != "" {
			return fmt.Sprintf("EXEC ALLOWLIST (mutating arg): dsd executed %q with args %v — %q is a denied token for this binary", rec.Name, rec.Args, bad)
		}
	}
	return ""
}

// shimOracleViolation returns a non-empty message if any PATH recording shim
// fired for a binary outside the read-only allowlist, or with a mutating argument.
// A shim firing at all means an exec bypassed platform.ExecHook
// (stdlib/cgo/third-party).
func shimOracleViolation(lines []string) string {
	for _, ln := range lines {
		name, args, _ := strings.Cut(ln, "\t")
		base := filepath.Base(strings.TrimSpace(name))
		if !readOnlyBinaries[base] {
			return fmt.Sprintf("PATH SHIM: a command outside the read-only allowlist ran via $PATH: %q (args=%q)", base, args)
		}
		for _, m := range []string{"-C", "--clear", "--rotate", "--vacuum"} {
			if strings.Contains(args, m) {
				return fmt.Sprintf("PATH SHIM (mutating arg): allowlisted %q ran via $PATH with mutating arg in %q", base, args)
			}
		}
	}
	return ""
}

// exercise runs one fuzzed input end to end under all oracles. Shared by the seed
// unit test and the fuzz target.
func exercise(t *testing.T, envBlob, hostname string, procBlob []byte, cols []runner.Collector, maxWait time.Duration) oracleResult {
	t.Helper()

	runMu.Lock()
	defer runMu.Unlock()

	hostDir := watchedHostDir

	root := t.TempDir()
	watchedRoot := filepath.Join(root, "watched")
	home := filepath.Join(watchedRoot, "home")
	tmp := filepath.Join(watchedRoot, "tmp")
	cwd := filepath.Join(watchedRoot, "cwd")
	procDir := filepath.Join(root, "proc")
	sysDir := filepath.Join(root, "sys")
	for _, d := range []string{home, tmp, cwd, procDir, sysDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	writeFuzzedTree(t, procDir, procFixtureNames, procBlob)
	writeFuzzedTree(t, sysDir, sysFixtureNames, procBlob)

	// Pin HOME/TMPDIR/cwd/HOST_PROC/HOST_SYS + apply fuzzed env, default-offline.
	envPairs := parseEnvBlob(envBlob)
	envPairs["HOME"] = home
	envPairs["TMPDIR"] = tmp
	envPairs["HOST_PROC"] = procDir
	envPairs["HOST_SYS"] = sysDir
	envPairs["HOSTNAME"] = sanitizeHostname(hostname)
	restoreEnv := envOverride(envPairs)
	defer restoreEnv()
	// Force default read-only network mode regardless of fuzzed env.
	_ = os.Unsetenv("DSD_ALLOW_NETWORK")
	_ = os.Unsetenv("DSD_OFFLINE")

	prevWd, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if prevWd != "" {
			_ = os.Chdir(prevWd)
		}
	}()

	// Fingerprint before.
	beforeTree := resource.Fingerprint(t, watchedRoot)
	beforeHost := resource.Fingerprint(t, hostDir)

	// Reset per-input traces, then run every collector.
	recorder.reset()
	dialBase := guard.count()
	_ = readShimTrace() // clear
	runCollectorsOnce(cols, maxWait)

	// Oracles.
	resource.AssertUnchanged(t, watchedRoot, beforeTree)
	resource.AssertUnchanged(t, hostDir, beforeHost)

	execs := recorder.snapshot()
	if v := execOracleViolation(execs); v != "" {
		t.Fatal(v)
	}

	dials := guard.since(dialBase)
	if len(dials) > 0 {
		t.Fatalf("NETWORK: %d non-loopback dial(s) during collector run: %+v", len(dials), dials)
	}

	shimLines := readShimTrace()
	if v := shimOracleViolation(shimLines); v != "" {
		t.Fatal(v)
	}

	return oracleResult{execs: execs, dials: dials, shimLines: shimLines}
}

// sanitizeHostname keeps a fuzzed hostname to a single safe-ish line so setting it
// as $HOSTNAME env can't inject a newline into other vars.
func sanitizeHostname(h string) string {
	h = strings.ReplaceAll(h, "\n", "")
	h = strings.ReplaceAll(h, "\x00", "")
	if len(h) > 255 {
		h = h[:255]
	}
	return h
}

// TestDiscoverExecs is a discovery aid (run with -run TestDiscoverExecs): it runs
// every collector once under the pinned/denied environment and logs the full set
// of (basename, args) dsd attempted, plus which ones the allowlist does NOT match.
// It never fails — it exists to enumerate the exec surface this host exercises so
// the contract port can be completed from one run instead of many assert cycles.
func TestDiscoverExecs(t *testing.T) {
	if os.Getenv("DSD_RO1_DISCOVER") == "" {
		t.Skip("discovery aid; set DSD_RO1_DISCOVER=1 to run")
	}
	runMu.Lock()
	defer runMu.Unlock()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	tmp := filepath.Join(root, "tmp")
	cwd := filepath.Join(root, "cwd")
	for _, d := range []string{home, tmp, cwd} {
		_ = os.MkdirAll(d, 0o755)
	}
	restore := envOverride(map[string]string{"HOME": home, "TMPDIR": tmp})
	defer restore()
	prevWd, _ := os.Getwd()
	_ = os.Chdir(cwd)
	defer func() { _ = os.Chdir(prevWd) }()
	recorder.reset()
	runAllCollectorsOnce()
	execs := recorder.snapshot()
	for _, e := range execs {
		base := filepath.Base(e.Name)
		match := "OK"
		rule, known := execAllowlistContract[base]
		if !known {
			match = "UNLISTED-BINARY"
		} else {
			m := false
			for _, p := range rule.prefixes {
				if argsHavePrefix(e.Args, p) {
					m = true
					break
				}
			}
			if !m {
				match = "NO-PREFIX-MATCH"
			} else if bad := argsContainAny(e.Args, rule.denyAnywhere); bad != "" {
				match = "DENY:" + bad
			}
		}
		if match != "OK" {
			t.Logf("[%s] %s %v", match, base, e.Args)
		}
	}
	t.Logf("total execs attempted: %d; distinct binaries: %v", len(execs), sortedExecNames(execs))
}

// FuzzReadOnlyClaim fuzzes the environment, hostname and fake procfs/sysfs content
// that feed every collector, asserting the read-only + no-network claim each time.
func FuzzReadOnlyClaim(f *testing.F) {
	f.Add("LANG=C", "host-a", []byte("MemTotal: 1024 kB\n"))
	f.Add("", "", []byte{})
	f.Add("XDG_SESSION_DESKTOP=gamescope\nTERM=xterm", "steamdeck", []byte("MemTotal: -1 kB\nSwapTotal: 999999999999999\n"))
	f.Add("FOO=bar\nBAZ=qux", "x", []byte(strings.Repeat("A", 70000)))
	f.Add("DSD_ALLOW_NETWORK=1", "evil", []byte("Hugepagesize: 2048 kB\n"))
	f.Add("SSH_CONNECTION=1.2.3.4 22 5.6.7.8 22", "n", []byte("0\n0\n0\n"))

	f.Fuzz(func(t *testing.T, envBlob, hostname string, procBlob []byte) {
		_ = exercise(t, envBlob, hostname, procBlob, allRunnerCollectors(), 4*time.Second)
	})
}

// FuzzReadOnlyClaimFast fuzzes the same inputs against the input-sensitive,
// non-blocking collector subset at high throughput, so the fuzzed env/proc/sys
// space is actually explored. FuzzReadOnlyClaim remains the breadth target over
// the full superset.
func FuzzReadOnlyClaimFast(f *testing.F) {
	f.Add("LANG=C", "host-a", []byte("MemTotal: 1024 kB\n"))
	f.Add("", "", []byte{})
	f.Add("XDG_SESSION_DESKTOP=gamescope\nSteamDeck=1", "steamdeck", []byte("MemTotal: -1 kB\nSwapTotal: 999999999999999\nSwapFree: -5\n"))
	f.Add("FOO=bar", "x", []byte(strings.Repeat("MemFree: 9 kB\n", 5000)))
	f.Add("", "n", []byte("Hugepagesize:\x00\x00 2048 kB\nAnonHugePages: 999999999999999999999999 kB\n"))

	f.Fuzz(func(t *testing.T, envBlob, hostname string, procBlob []byte) {
		_ = exercise(t, envBlob, hostname, procBlob, fastCollectors(), 1500*time.Millisecond)
	})
}

// TestReadOnlyClaimSeeds runs the seed corpus deterministically so a plain
// `go test ./internal/readonly` (no -fuzz) still exercises the whole harness and
// all oracles — the guard is watched working on every CI run, not only under fuzz.
func TestReadOnlyClaimSeeds(t *testing.T) {
	seeds := []struct {
		env, host string
		proc      []byte
	}{
		{"LANG=C", "host-a", []byte("MemTotal: 1024 kB\n")},
		{"", "", nil},
		{"FOO=bar", "steamdeck", []byte("MemTotal: -1 kB\n")},
		{"BAZ=qux", "x", []byte(strings.Repeat("A", 70000))},
	}
	for i, s := range seeds {
		t.Run(fmt.Sprintf("seed-%d", i), func(t *testing.T) {
			res := exercise(t, s.env, s.host, s.proc, allRunnerCollectors(), 4*time.Second)
			t.Logf("seed %d: execs=%d dials=%d shims=%d", i, len(res.execs), len(res.dials), len(res.shimLines))
		})
	}
}

// sortedExecNames is a small helper used by reporting tests.
func sortedExecNames(execs []execTrace) []string {
	seen := map[string]bool{}
	for _, e := range execs {
		seen[filepath.Base(e.Name)] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
