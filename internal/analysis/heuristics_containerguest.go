package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	containerThrottleWarnPct = 10.0 // share of scheduler periods throttled at the quota
	containerMemNearPct      = 90.0 // memory.current as a share of memory.max
)

// ContainerGuestInsights is the exported entry point for `dsd guest` (container
// case). It returns exactly what `dsd health` would evaluate (checkContainerGuest),
// so the standalone verdict can't drift.
func ContainerGuestInsights(v models.ContainerGuestInfo) []models.Insight {
	return AdaptHostHints(checkContainerGuest(v))
}

// checkContainerGuest reports guest-side health for a workload inside a container.
// Two themes: container spec the deployer controls (limits, user, rootfs) and the
// resource limits being enforced against the workload (throttling, OOM) — the
// container analog of the VM guest-vs-host split.
func checkContainerGuest(v models.ContainerGuestInfo) []models.Insight {
	if !v.InContainer {
		return nil
	}
	var out []models.Insight

	// ── Container spec — the deployer can fix ──
	if v.MemLimitBytes <= 0 {
		out = append(out, insight("WARN", "ContainerGuest",
			"no memory limit set — a leak can consume the host's RAM and the host won't OOM-protect this container",
			[]string{
				"to fix (docker): docker run --memory=<size> …",
				"to fix (k8s): set resources.limits.memory in the pod spec",
			}))
	}
	if v.RunAsRoot {
		out = append(out, insight("WARN", "ContainerGuest",
			"container runs as root (uid 0) — a breakout has host-root-adjacent privileges; run as a non-root user",
			[]string{
				"to fix (image): add a USER directive and chown the app dir",
				"to fix (k8s): set securityContext.runAsNonRoot: true",
			}))
	}
	if v.CPUQuotaCores <= 0 {
		out = append(out, insight("INFO", "ContainerGuest",
			"no CPU limit set — the container can be starved by noisy neighbours and isn't schedulable by quota",
			[]string{"to set (k8s): resources.requests/limits.cpu; (docker): --cpus=<n>"}))
	}
	if v.WritableRootfs {
		out = append(out, insight("INFO", "ContainerGuest",
			"root filesystem is writable — a read-only root (with writable volumes for state) is more tamper-resistant",
			[]string{"to fix (docker): --read-only; (k8s): securityContext.readOnlyRootFilesystem: true"}))
	}

	// ── Resource limits — being enforced against you ──
	out = append(out, containerThrottleInsight(v)...)
	if v.OOMKills > 0 {
		out = append(out, insight("WARN", "ContainerGuest",
			fmt.Sprintf("%d OOM-kill(s) — a process was killed for exceeding the memory limit (%s); raise the limit if it's yours to set, or this is your platform's cap",
				v.OOMKills, containerHumanBytes(v.MemLimitBytes)),
			[]string{
				"to inspect: cat /sys/fs/cgroup/memory.events; dmesg | grep -i oom",
				"to fix: raise memory.max (docker --memory / k8s limits.memory), or fix the leak",
			}))
	}
	if pct := containerMemPct(v); pct >= containerMemNearPct {
		out = append(out, insight("WARN", "ContainerGuest",
			fmt.Sprintf("memory at %.0f%% of the limit (%s of %s) — an OOM-kill is close",
				pct, containerHumanBytes(v.MemCurrentBytes), containerHumanBytes(v.MemLimitBytes)),
			[]string{"to inspect: cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max"}))
	}

	// cgroup v1: throttle/OOM live under per-controller dirs (memory.oom_control /
	// cpu.stat), which the collector now reads — so a throttled/OOM-killed v1 container
	// IS caught by the checks above. Only when those reads failed (CgroupV1Measured
	// false — old kernel / controller not mounted) are the signals unverified; say so
	// rather than letting the summary imply "no throttling or OOM-kills".
	if v.InContainer && !v.CgroupV2 && !v.CgroupV1Measured {
		out = append(out, insight("INFO", "ContainerGuest",
			"CPU-throttle and OOM-kill could not be read on this cgroup v1 host — those signals are unverified",
			[]string{"note: needs the cpu + memory v1 controllers mounted and a kernel exposing memory.oom_control"}))
	}

	if len(out) == 0 {
		out = append(out, insight("INFO", "ContainerGuest",
			fmt.Sprintf("%s container — memory + CPU limits set, non-root, no throttling or OOM-kills%s",
				containerRuntimeLabel(v), containerUnderlaySuffix(v)),
			nil))
	}
	return out
}

func containerThrottleInsight(v models.ContainerGuestInfo) []models.Insight {
	if v.ThrottledPct < containerThrottleWarnPct {
		return nil
	}
	quota := "the CPU quota"
	if v.CPUQuotaCores > 0 {
		quota = fmt.Sprintf("the CPU quota (%.2f cores)", v.CPUQuotaCores)
	}
	return []models.Insight{insight("WARN", "ContainerGuest",
		fmt.Sprintf("CPU throttled %.0f%% of scheduler periods — the container keeps hitting %s; this is the usual hidden cause of a 'slow' container", v.ThrottledPct, quota),
		[]string{
			"raise the limit if it's yours to set (docker --cpus / k8s limits.cpu), or this is your platform's cap — ask them",
			"to inspect: cat /sys/fs/cgroup/cpu.stat   (nr_throttled / throttled_usec)",
		})}
}

func containerMemPct(v models.ContainerGuestInfo) float64 {
	if v.MemLimitBytes <= 0 || v.MemCurrentBytes <= 0 {
		return 0
	}
	return float64(v.MemCurrentBytes) / float64(v.MemLimitBytes) * 100
}

func containerRuntimeLabel(v models.ContainerGuestInfo) string {
	if v.Runtime == "" {
		return "container"
	}
	return v.Runtime
}

func containerUnderlaySuffix(v models.ContainerGuestInfo) string {
	if v.UnderlyingVM == "" {
		return ""
	}
	return fmt.Sprintf(" (on a %s VM)", v.UnderlyingVM)
}

// containerHumanBytes renders a byte count compactly; "unset" for 0 (no limit).
func containerHumanBytes(b int64) string {
	if b <= 0 {
		return "unset"
	}
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.0f MB", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.0f KB", float64(b)/k)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
