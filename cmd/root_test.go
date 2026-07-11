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
	return c
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
