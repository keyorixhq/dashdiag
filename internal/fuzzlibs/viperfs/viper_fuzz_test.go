// SPDX-License-Identifier: BSD-3-Clause

// Package viperfs fuzzes github.com/spf13/viper's config read + unmarshal
// path, the way DashDiag uses it (internal/config/config.go: viper.New,
// ReadInConfig, then decode into a thresholds/services struct). A hostile
// config file is the input. Both the YAML (DashDiag's real format) and TOML
// codecs are exercised, plus viper's key-flattening via AllSettings.
//
// Oracle: no panic, no hang.
package viperfs

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
)

type cfg struct {
	Thresholds map[string]float64 `mapstructure:"thresholds"`
	Services   []string           `mapstructure:"services"`
	Logs       struct {
		SinceMinutes int `mapstructure:"since_minutes"`
	} `mapstructure:"logs"`
}

func fuzzType(t *testing.T, typ string, data []byte) {
	v := viper.New()
	v.SetConfigType(typ)
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return
	}
	// Exercise key-flattening / delimiter handling and the decode path.
	_ = v.AllSettings()
	_ = v.AllKeys()
	var c cfg
	_ = v.Unmarshal(&c)
}

func FuzzReadYAML(f *testing.F) {
	f.Add([]byte("thresholds:\n  disk_warn_pct: 80\nservices:\n  - a\nlogs:\n  since_minutes: 10\n"))
	f.Add([]byte("a: {b: {c: 1}}\n"))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzType(t, "yaml", data) })
}

func FuzzReadTOML(f *testing.F) {
	f.Add([]byte("[thresholds]\ndisk_warn_pct = 80\n[logs]\nsince_minutes = 10\n"))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzType(t, "toml", data) })
}

func FuzzReadJSON(f *testing.F) {
	f.Add([]byte(`{"thresholds":{"disk_warn_pct":80},"services":["a"],"logs":{"since_minutes":10}}`))
	f.Fuzz(func(t *testing.T, data []byte) { fuzzType(t, "json", data) })
}
