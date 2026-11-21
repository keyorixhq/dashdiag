package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConfigDeepNestingAllocationIsBounded pins the measured behaviour behind
// the PD1 allocation factor: a config that is only opening brackets or braces
// costs about 600 B per level until the YAML parser's own depth cap rejects it,
// and the cost stops growing there. A 64 KB input must stay under 8 MiB, so a
// hostile config cannot make Load's memory grow with input size on this shape.
// If a dependency update removes the cap, this fails and the budget needs a
// decision, not a bump.
func TestConfigDeepNestingAllocationIsBounded(t *testing.T) {
	const ceiling = 8 << 20
	for _, open := range []string{"{", "["} {
		in := strings.Repeat(open, 64000)
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(in), 0o600); err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := Load(p)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("Load accepted %d nested %q", len(in), open)
		}
		if got := after.TotalAlloc - before.TotalAlloc; got > ceiling {
			t.Fatalf("Load of %d B of %q allocated %d B, want <= %d", len(in), open, got, ceiling)
		}
	}
}
