package cmd

// root_test.go covers cmd/root.go: applyBrand, the PersistentPreRun banner /
// --out redirect wiring, and the custom HelpFunc. rootCmd.PersistentPreRun and
// rootCmd.HelpFunc() are plain func values that take the *cobra.Command as a
// parameter — calling them with a bare, purpose-built *cobra.Command exercises
// the real logic without mutating the shared global rootCmd's own flag state.
//
// Execute() itself is intentionally NOT exercised: it runs the real rootCmd.Execute()
// (the whole CLI dispatch tree) and ends in os.Exit — both untestable in this
// harness without spawning a subprocess (which smoke_test.go already covers
// at the binary level).
//
// Not t.Parallel() anywhere here: these tests swap the shared os.Stdout/os.Stderr.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/spf13/cobra"
)

func newBareRootPreRunCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.String("out", "", "")
	f.String("brand", "", "")
	f.String("logo", "", "")
	f.Bool("network", false, "")
	return c
}

func TestApplyNetworkPolicy_NetworkFlagOptsIn(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "")
	t.Setenv("DSD_ALLOW_NETWORK", "")
	c := newBareRootPreRunCmd()
	_ = c.Flags().Set("network", "true")

	applyNetworkPolicy(c)

	if !platform.NetworkAllowed() {
		t.Error("--network should opt in to network calls via DSD_ALLOW_NETWORK")
	}
}

func TestApplyNetworkPolicy_NoFlagStaysOffByDefault(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "")
	t.Setenv("DSD_ALLOW_NETWORK", "")
	c := newBareRootPreRunCmd()

	applyNetworkPolicy(c)

	if platform.NetworkAllowed() {
		t.Error("network must stay off by default when --network is not passed")
	}
}

// TestApplyNetworkPolicy_DSDOfflineOverridesEverything is the security-relevant
// invariant the census's gap-B fix hinges on: DSD_OFFLINE must win even when
// BOTH the --network flag AND a pre-existing DSD_ALLOW_NETWORK=1 (e.g. from a
// shared CI image's environment) say "allow network." A conflicting pair of
// opt-in signals must never override an explicit request to go offline — this
// exercises the full wiring (the real rootCmd.PersistentPreRun, which calls
// applyNetworkPolicy, feeding into the real platform.NetworkAllowed()), not
// just the policy function in isolation (see also
// internal/platform/network_policy_test.go for the narrower unit test).
func TestApplyNetworkPolicy_DSDOfflineOverridesEverything(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")
	t.Setenv("DSD_ALLOW_NETWORK", "1") // simulates an already-exported CI env var
	c := newBareRootPreRunCmd()
	_ = c.Flags().Set("network", "true") // simulates the operator also passing --network
	_ = c.Flags().Set("json", "true")    // suppress the banner side-effect

	rootCmd.PersistentPreRun(c, nil)

	if platform.NetworkAllowed() {
		t.Fatal("DSD_OFFLINE=1 must force offline even with --network AND DSD_ALLOW_NETWORK=1 both set — zero network calls must result")
	}
}

func TestApplyBrand_NoPanic(t *testing.T) {
	c := &cobra.Command{}
	f := c.Flags()
	f.String("brand", "", "")
	f.String("logo", "", "")

	applyBrand(c) // neither set

	_ = f.Set("brand", "Acme Corp")
	applyBrand(c) // company only

	_ = f.Set("brand", "")
	_ = f.Set("logo", "/tmp/logo.png")
	applyBrand(c) // logo only

	_ = f.Set("brand", "Acme Corp")
	applyBrand(c) // both
}

func TestRootPersistentPreRun_BannerPrinted(t *testing.T) {
	c := newBareRootPreRunCmd()
	stderr := captureStderr(t, func() { rootCmd.PersistentPreRun(c, nil) })
	if !strings.Contains(stderr, "DashDiag (dsd)") {
		t.Errorf("default (no plain/json/out) should print the banner, got: %q", stderr)
	}
}

func TestRootPersistentPreRun_PlainSuppressesBanner(t *testing.T) {
	c := newBareRootPreRunCmd()
	_ = c.Flags().Set("plain", "true")
	stderr := captureStderr(t, func() { rootCmd.PersistentPreRun(c, nil) })
	if strings.Contains(stderr, "DashDiag (dsd)") {
		t.Errorf("--plain should suppress the banner, got: %q", stderr)
	}
}

func TestRootPersistentPreRun_JSONSuppressesBanner(t *testing.T) {
	c := newBareRootPreRunCmd()
	_ = c.Flags().Set("json", "true")
	stderr := captureStderr(t, func() { rootCmd.PersistentPreRun(c, nil) })
	if strings.Contains(stderr, "DashDiag (dsd)") {
		t.Errorf("--json should suppress the banner, got: %q", stderr)
	}
}

func TestRootPersistentPreRun_OutRedirectsStdout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	c := newBareRootPreRunCmd()
	_ = c.Flags().Set("out", path)
	_ = c.Flags().Set("json", "true") // also suppress the banner side-effect

	old := os.Stdout
	defer func() { os.Stdout = old }()

	rootCmd.PersistentPreRun(c, nil)
	if os.Stdout == old {
		t.Fatal("expected --out to redirect os.Stdout to the target file")
	}
	if _, err := os.Stdout.WriteString("hello\n"); err != nil {
		t.Fatalf("writing to redirected stdout: %v", err)
	}
	redirected := os.Stdout
	os.Stdout = old
	_ = redirected.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading --out target file: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Errorf("expected the redirected write to land in the file, got: %q", data)
	}
}

// TestCreateOutFile_SymlinkRefused is the regression guard for a symlink-
// following overwrite: --out only cobra-validates that a string flag was
// given, never that the target isn't a symlink. If dsd runs privileged (root,
// a service account, a scheduled job writing to a predictable path) and an
// attacker pre-creates a symlink at that path pointing at a file they don't
// own, a plain os.Create would silently truncate and overwrite the SYMLINK'S
// TARGET. createOutFile must refuse, and must leave the symlink's target file
// untouched.
func TestCreateOutFile_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(target, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := createOutFile(link); err == nil {
		t.Fatal("createOutFile accepted a symlink target")
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not touch" {
		t.Errorf("symlink target was modified: got %q", data)
	}
}

// TestCreateOutFile_RegularFileOverwritten is the contrast case: re-running
// dsd with the same --out path must still succeed and truncate dsd's own
// prior REGULAR-file output — the fix must not be overly conservative and
// break the common "overwrite my last report" case.
func TestCreateOutFile_RegularFileOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("stale content from a prior run"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := createOutFile(path)
	if err != nil {
		t.Fatalf("createOutFile on a pre-existing regular file: %v", err)
	}
	if _, err := f.WriteString("fresh"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "fresh" {
		t.Errorf("expected the regular file to be truncated and overwritten, got %q", data)
	}
}

func TestRootHelpFunc(t *testing.T) {
	hf := rootCmd.HelpFunc()

	withLong := &cobra.Command{Use: "withlong", Long: "Long form description."}
	var buf bytes.Buffer
	withLong.SetOut(&buf)
	withLong.SetErr(&buf)
	hf(withLong, nil)
	if !strings.Contains(buf.String(), "Long form description.") {
		t.Errorf("expected Long text in help output, got: %q", buf.String())
	}

	shortOnly := &cobra.Command{Use: "shortonly", Short: "Short form."}
	var buf2 bytes.Buffer
	shortOnly.SetOut(&buf2)
	shortOnly.SetErr(&buf2)
	hf(shortOnly, nil)
	if !strings.Contains(buf2.String(), "Short form.") {
		t.Errorf("expected Short fallback text in help output, got: %q", buf2.String())
	}

	neither := &cobra.Command{Use: "neither"}
	var buf3 bytes.Buffer
	neither.SetOut(&buf3)
	neither.SetErr(&buf3)
	hf(neither, nil) // must not panic with no Long/Short
	if !strings.Contains(buf3.String(), "Usage:") {
		t.Errorf("expected the usage block still printed, got: %q", buf3.String())
	}
}

// TestRootHelpFunc_NetworkExemptCommandOmitsFlag covers the
// networkFlagExempt branch: fleetCmd is a real child of rootCmd (registered
// via fleet.go's own init()), so it inherits rootCmd's --network persistent
// flag — the help output must omit it (printUsageWithoutNetworkFlag), unlike
// a non-exempt command.
func TestRootHelpFunc_NetworkExemptCommandOmitsFlag(t *testing.T) {
	hf := rootCmd.HelpFunc()

	var buf bytes.Buffer
	fleetCmd.SetOut(&buf)
	fleetCmd.SetErr(&buf)
	hf(fleetCmd, nil)
	out := buf.String()
	if strings.Contains(out, "--network ") {
		t.Errorf("fleet is network-flag-exempt — --network must not appear in its help, got:\n%s", out)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("expected the usage block still printed (minus --network), got:\n%s", out)
	}

	// Contrast: a non-exempt command (historyCmd, also a real rootCmd child)
	// must still advertise --network.
	var buf2 bytes.Buffer
	historyCmd.SetOut(&buf2)
	historyCmd.SetErr(&buf2)
	hf(historyCmd, nil)
	if !strings.Contains(buf2.String(), "--network ") {
		t.Errorf("history is NOT network-flag-exempt — expected --network in its help, got:\n%s", buf2.String())
	}
}
