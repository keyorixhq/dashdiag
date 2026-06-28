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

// CloudEnvironmentViaSource returns the detected cloud (AWS/Azure/GCP/none) routed
// through the active source. It feeds ApplyThresholds (cloud-aware verdicts, e.g.
// the NVMe-timeout downgrade on virtual-disk cloud guests), so under replay it must
// reflect the CAPTURED host — `dsd replay` previously hardcoded "none", so a cloud
// capture lost its cloud context on replay. Gap fallback = none (the prior hardcoded
// value), so existing bundles/goldens are unaffected.
func CloudEnvironmentViaSource() platform.CloudEnvironment {
	var ce platform.CloudEnvironment
	if err := cachedJSON("platform/cloud-env", func() (any, error) {
		return platform.DetectCloudEnvironment(), nil
	}, &ce); err != nil {
		return platform.CloudEnvironment(0)
	}
	return ce
}

// ProfileViaSource returns the normalized platform profile (distro, init system,
// package manager, security module, …) routed through the active source. It feeds
// buildHealthCollectors and distro-specific collector behavior, so under replay it
// must reflect the CAPTURED host — `dsd replay` previously called platform.Detect()
// live, so a Debian capture replayed on an Alpine box ran Alpine's profile. Gap
// fallback = a live Detect() (the prior behavior), so existing bundles are unaffected.
func ProfileViaSource() platform.Profile {
	var p platform.Profile
	if err := cachedJSON("platform/profile", func() (any, error) {
		return platform.Detect(), nil
	}, &p); err != nil {
		return platform.Detect()
	}
	return p
}
