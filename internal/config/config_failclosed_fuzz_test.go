package config

import (
	"os"
	"path/filepath"
	"testing"
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
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := Load(p)
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
