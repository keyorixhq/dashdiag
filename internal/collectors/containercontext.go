package collectors

import "github.com/keyorixhq/dashdiag/internal/platform"

// ContainerContextViaSource returns the process's container-context routed through
// the active source: RECORDED at capture and REPLAYED from the bundle. The context
// (InContainer, cgroup limits, runtime) feeds the CPU/Memory/Disk/Swap/Thermal
// collectors and the ApplyThresholds heuristic, so under replay it must reflect the
// CAPTURED host — otherwise replaying a container capture shows the bare-metal view
// (cgroup CPU/mem limits and container-throttle context silently lost), and a
// gated collector (PostBoot) reads the replaying machine's nature.
//
// `dsd replay` previously hardcoded a zero-value ContainerContext, so a captured
// container's context never replayed. The zero-value fallback below keeps that exact
// behavior for older bundles with no recording (and for live runs the live value is
// returned unchanged), so only fresh captures gain faithful container replay.
func ContainerContextViaSource() platform.ContainerContext {
	var cc platform.ContainerContext
	if err := cachedJSON("platform/container-context", func() (any, error) {
		return platform.DetectContainerContext(), nil
	}, &cc); err != nil {
		return platform.ContainerContext{}
	}
	return cc
}
