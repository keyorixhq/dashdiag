// Package viperconf holds the MC1 third-party fuzz target for
// github.com/spf13/viper on DashDiag's config-load path. It has no production
// code of its own; it exists only to host the fuzz target in its own directory
// (one directory per third-party library, per the MC1 conventions). See
// mc1_viper_config_fuzz_test.go for the invariants.
package viperconf

import (
	"bytes"

	"github.com/spf13/viper"
)

// readConfigBytes decodes data into v using v's already-set config type — the
// same decode backend internal/config.Load reaches through ReadInConfig, minus
// the disk read. Kept as a named helper so the red-proof (swap in a parser that
// drops a key) is a one-line edit documented in the report.
func readConfigBytes(v *viper.Viper, data []byte) error {
	return v.ReadConfig(bytes.NewReader(data))
}
