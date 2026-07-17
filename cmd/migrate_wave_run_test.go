package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newBareWaveCmd returns a cobra.Command with the flags that runMigrateWave reads.
// applyBrand reads "brand" and "logo"; the rest are the wave-specific flags.
func newBareWaveCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.String("pairs-file", "", "")
	f.String("brand", "", "")
	f.String("logo", "", "")
	f.String("name", "", "")
	f.Bool("force", false, "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	f.Bool("json", false, "")
	f.Bool("report-html", false, "")
	return c
}

// TestRunMigrateWave_NoPairs covers the "no pairs given" early return in
// runMigrateWave. On any host with no args and no --pairs-file the function
// returns after the pairs check without touching the network or filesystem.
func TestRunMigrateWave_NoPairs(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with no pairs, got nil")
	}
	if !strings.Contains(err.Error(), "no pairs given") {
		t.Errorf("expected 'no pairs given' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_BadPairsFile covers the resolvePairs file-open error path:
// --pairs-file set to a path that does not exist causes resolvePairs to return
// a "reading --pairs-file: …" error, which runMigrateWave propagates.
func TestRunMigrateWave_BadPairsFile(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	dir := t.TempDir()
	missing := filepath.Join(dir, "does_not_exist.txt")
	if err := cmd.Flags().Set("pairs-file", missing); err != nil {
		t.Fatal(err)
	}
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with non-existent --pairs-file")
	}
	if !strings.Contains(err.Error(), "reading --pairs-file") {
		t.Errorf("expected 'reading --pairs-file' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_BadArgFormat covers the resolvePairs positional-arg parse
// error path: a positional arg without a colon returns an error from resolvePairs
// before runMigrateWave reaches the len(pairs)==0 guard.
func TestRunMigrateWave_BadArgFormat(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	// "noseparator" has no colon → resolvePairs returns an error.
	err := runMigrateWave(cmd, []string{"noseparator"})
	if err == nil {
		t.Fatal("expected error from runMigrateWave with malformed pair arg")
	}
	if !strings.Contains(err.Error(), "expected src:dst") {
		t.Errorf("expected 'expected src:dst' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_PairsFileWithBadLine covers the pairs-file parse error
// path: a file with a line that has too many fields causes resolvePairs to
// return an error before any bundle files are touched.
func TestRunMigrateWave_PairsFileWithBadLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pf := filepath.Join(dir, "pairs.txt")
	// Three fields on one line → "expected two fields" error.
	if err := os.WriteFile(pf, []byte("a.tar.gz b.tar.gz extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareWaveCmd()
	if err := cmd.Flags().Set("pairs-file", pf); err != nil {
		t.Fatal(err)
	}
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with a bad pairs-file line")
	}
	if !strings.Contains(err.Error(), "expected two fields") {
		t.Errorf("expected 'expected two fields' error, got %q", err.Error())
	}
}
