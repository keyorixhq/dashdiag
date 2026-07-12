//go:build linux || darwin

package cmd

import (
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// appendDockerCollector adds the Docker/Podman collector to cols when a
// container socket or Podman quadlets are detected on this host.
func appendDockerCollector(cols []collectors.Collector, profile platform.Profile, deep bool) []collectors.Collector {
	if sock, _ := collectors.DetectContainerSocket(); sock != "" || collectors.PodmanQuadletsPresent() {
		dockerCol := collectors.NewDockerCollectorWithProfile(profile)
		dockerCol.Deep = deep
		return append(cols, dockerCol)
	}
	return cols
}
