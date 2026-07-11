//go:build !linux && !darwin

package cmd

import (
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func appendDockerCollector(cols []collectors.Collector, _ platform.Profile, _ bool) []collectors.Collector {
	return cols
}
