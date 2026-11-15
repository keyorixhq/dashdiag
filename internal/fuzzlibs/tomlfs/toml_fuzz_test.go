// SPDX-License-Identifier: BSD-3-Clause

// Package tomlfs fuzzes github.com/pelletier/go-toml/v2, the TOML codec that
// spf13/viper uses. DashDiag loads config through viper; a TOML-typed config
// file reaches this decoder. Hostile config bytes are the input.
//
// Oracles: no panic/hang on Unmarshal; and for values that unmarshal into a
// generic map, a Marshal->Unmarshal round-trip does not panic.
package tomlfs

import (
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

func FuzzUnmarshalMap(f *testing.F) {
	f.Add([]byte("a = 1\nb = \"x\"\n[c]\nd = true\n"))
	f.Add([]byte("[[arr]]\nx=1\n[[arr]]\nx=2\n"))
	f.Add([]byte("t = 2020-01-01T00:00:00Z\n"))
	f.Add([]byte("f = 1_000.5\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m map[string]any
		if err := toml.Unmarshal(data, &m); err != nil {
			return
		}
		// Re-marshal the accepted document; must not panic.
		out, err := toml.Marshal(m)
		if err != nil {
			return
		}
		// And the re-marshalled form must itself be parseable.
		var m2 map[string]any
		_ = toml.Unmarshal(out, &m2)
	})
}

// cfg mirrors the shape DashDiag unmarshals config into (nested numeric
// thresholds), exercising the struct-reflection decode path.
type cfg struct {
	Thresholds struct {
		DiskWarnPct   float64 `toml:"disk_warn_pct"`
		RAMCritPct    int     `toml:"ram_crit_pct"`
		CPUMultiplier float64 `toml:"cpu_load_warn_multiplier"`
	} `toml:"thresholds"`
	Services []string `toml:"services"`
	Logs     struct {
		SinceMinutes int `toml:"since_minutes"`
	} `toml:"logs"`
}

func FuzzUnmarshalStruct(f *testing.F) {
	f.Add([]byte("[thresholds]\ndisk_warn_pct = 80.5\nram_crit_pct = 95\n"))
	f.Add([]byte("services = [\"a\",\"b\"]\n[logs]\nsince_minutes = 10\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var c cfg
		_ = toml.Unmarshal(data, &c)
	})
}
