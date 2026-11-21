package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// Resource-oracle calibration (PD1). config.Load drives spf13/viper +
// go.yaml.in/yaml. Measured baseline amplifications: a flat valid config ~1065x
// at 32 B (fixed viper overhead, absorbed by the 1 MiB AllocFloor), a 2000-entry
// services config ~103x, a 200 KB scalar value ~9x, a degenerate `[[[[` nest
// ~371x at 4 KB, a degenerate `{{{` flow-mapping nest ~616x raw / 504x effective
// (net of floor) peaking at 10 KB then plateauing at ~6.1 MB (go-yaml's internal
// nesting-depth limit). factor 640 tolerates every one of those legitimate shapes
// while tripping the go.yaml #510 duplicate-key QUADRATIC the loader is NOT
// guarded against: a duplicate-key config allocates O(n^2) — 1 KB → 11 MB, well
// above the 640x budget of 1.7 MB — so it breaches by 6.7x at the smallest size.
// The `{{{` nesting is a distinct mechanism from #510 (linear depth cost, O(n),
// vs quadratic sibling-key cost, O(n^2)); the plateau bounds its worst-case
// allocation regardless of input size. See the DSCFG1 report. Load spawns no
// goroutines (measured Δ=0); the disk oracle fingerprints the temp config dir to
// prove Load writes nothing back.
const (
	pd1ConfigAllocFactor = 640
	pd1MaxGoroutineDiff  = 16
)

// FuzzConfigLoadFailClosed fuzzes Load — the ~/.dsd.yaml / --config loader —
// which feeds untrusted YAML to a third-party stack dashdiag calls: spf13/viper
// (ReadInConfig) and go-viper/mapstructure (Unmarshal into Config). Config is a
// documented trust boundary (the task lists "YAML or JSON config") and
// cfg.Services drives real outbound TCP/HTTP dials, so a hostile config is not
// hypothetical.
//
// Oracle (fail-closed verdict, not crash-only): Load must NEVER return a
// (cfg, nil) whose cfg would be rejected by its own Validate(). Validate is the
// one guard that rejects a NaN/Inf/negative threshold or an out-of-range port —
// values that, if they slipped through, silently break every WARN/CRIT
// comparison that reads them (e.g. a .nan disk_crit_pct makes a full disk read
// as healthy — a WRONG VERDICT that hides a failing disk). If Load ever returns
// nil error with an invalid config, the fail-closed contract is broken.
//
// INVARIANT (see INVARIANTS.d note): Load(path) returning a nil error implies
// the returned *Config passes Validate(); a config that cannot be validated is
// surfaced as an error, never as a silently-accepted default-shadowing config.
//
// What this oracle does NOT verify: the implicit-$HOME security gating
// (symlink/owner/size checks in implicitConfigSafe — exercised only on the
// implicit path, while this fuzzes an explicit --config file), nor that a
// REJECTED config leaves behaviour on safe defaults (Load's documented
// defaults-on-error fallback is not asserted here), nor viper's precedence
// across env/flags.

func FuzzConfigLoadFailClosed(f *testing.F) {
	f.Add("thresholds:\n  disk_warn_pct: 80\n  disk_crit_pct: 95\n")
	f.Add("thresholds:\n  disk_crit_pct: .nan\n")                      // NaN trap
	f.Add("thresholds:\n  disk_crit_pct: .inf\n")                      // Inf trap
	f.Add("thresholds:\n  ram_warn_pct: -5\n")                         // negative trap
	f.Add("services:\n  - name: web\n    host: h\n    port: 999999\n") // bad port
	f.Add("security:\n  allowed_ports: [0, 70000]\n")
	f.Add("a: &x [*x]\n")      // self-referential anchor (bounded-work probe)
	f.Add("not: [valid: yaml") // malformed
	f.Add("")
	f.Add("42")

	f.Fuzz(func(t *testing.T, yaml string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		// Resource oracle: bound Load's allocation/time (the #510 quadratic guard),
		// prove it writes nothing to the config dir, and record goroutine growth.
		// The fail-closed Validate() assertion below is unchanged.
		before := resource.Fingerprint(t, dir)
		var cfg *Config
		var err error
		rr := resource.Check(t, len(yaml), pd1ConfigAllocFactor, func() {
			cfg, err = Load(p)
		})
		resource.AssertUnchanged(t, dir, before)
		if rr.GoroutineDiff > pd1MaxGoroutineDiff {
			t.Fatalf("goroutine growth: Load left %d extra goroutines (input=%d B)", rr.GoroutineDiff, len(yaml))
		}
		if err != nil {
			return // rejecting a bad config is the correct, safe outcome
		}
		if cfg == nil {
			t.Fatalf("Load returned (nil, nil)")
		}
		if verr := cfg.Validate(); verr != nil {
			t.Fatalf("Load accepted a config that fails its own Validate(): %v", verr)
		}
	})
}
