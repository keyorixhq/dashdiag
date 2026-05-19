package collectors

import (
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// timelineHintRule maps a message substring to a structured hint.
// Rules are checked in order — first match wins.
// Keep entries specific enough to avoid false matches.
type timelineHintRule struct {
	contains string // case-insensitive substring to match in event message
	unit     string // optional: also match against unit name (empty = any unit)
	hint     models.TimelineHint
}

// timelineHintRules is the ordered lookup table of known event patterns.
// Each entry follows the dsd health contract: explain → inspect → fix → persist.
var timelineHintRules = []timelineHintRule{
	// ── kernel networking ─────────────────────────────────────────────────────
	{
		contains: "no buffer space available",
		hint: models.TimelineHint{
			Explain: "kernel netlink buffer exhausted — container veth events flooding faster than the kernel can drain (common with k3s/rapid pod scheduling)",
			Inspect: "sysctl net.core.rmem_max net.core.wmem_max",
			Fix:     "sysctl -w net.core.rmem_max=134217728 && sysctl -w net.core.wmem_max=134217728",
			Persist: "echo -e 'net.core.rmem_max=134217728\\nnet.core.wmem_max=134217728' >> /etc/sysctl.d/99-dsd.conf && sysctl -p /etc/sysctl.d/99-dsd.conf",
		},
	},
	{
		contains: "neighbour table overflow",
		hint: models.TimelineHint{
			Explain: "ARP/neighbour cache full — too many unique IPs seen, kernel dropping new entries (common in large container deployments)",
			Inspect: "ip neigh show | wc -l && sysctl net.ipv4.neigh.default.gc_thresh3",
			Fix:     "sysctl -w net.ipv4.neigh.default.gc_thresh1=1024 && sysctl -w net.ipv4.neigh.default.gc_thresh2=4096 && sysctl -w net.ipv4.neigh.default.gc_thresh3=8192",
			Persist: "echo -e 'net.ipv4.neigh.default.gc_thresh1=1024\\nnet.ipv4.neigh.default.gc_thresh2=4096\\nnet.ipv4.neigh.default.gc_thresh3=8192' >> /etc/sysctl.d/99-dsd.conf",
		},
	},
	{
		contains: "nf_conntrack: table full",
		hint: models.TimelineHint{
			Explain: "conntrack table full — new connections are being dropped; often caused by high container traffic or DDoS",
			Inspect: "sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max",
			Fix:     "sysctl -w net.netfilter.nf_conntrack_max=524288",
			Persist: "echo 'net.netfilter.nf_conntrack_max=524288' >> /etc/sysctl.d/99-dsd.conf",
		},
	},
	// ── kernel OOM ───────────────────────────────────────────────────────────
	{
		contains: "out of memory",
		hint: models.TimelineHint{
			Explain: "kernel OOM killer fired — a process was killed because the system ran out of memory",
			Inspect: "journalctl -k --since '1 hour ago' | grep -i 'killed process'",
			Fix:     "ps aux --sort=-%mem | head -10",
			Persist: "set memory limits on containers: podman run --memory=512m ...",
		},
	},
	{
		contains: "killed process",
		hint: models.TimelineHint{
			Explain: "kernel OOM killer terminated a process — system hit a hard memory ceiling",
			Inspect: "free -h && ps aux --sort=-%mem | head -10",
			Fix:     "identify and restart the killed service: journalctl -k | grep 'Killed process'",
		},
	},
	// ── filesystem ───────────────────────────────────────────────────────────
	{
		contains: "ext4-fs error",
		hint: models.TimelineHint{
			Explain: "EXT4 filesystem error — possible disk corruption or hardware fault",
			Inspect: "dmesg | grep -i 'ext4\\|blk_update\\|I/O error' | tail -20",
			Fix:     "unmount filesystem and run: fsck -n /dev/<device>  (use -n for dry-run first)",
		},
	},
	{
		contains: "xfs_log_force",
		hint: models.TimelineHint{
			Explain: "XFS journal flush timed out — usually indicates disk I/O latency or hardware issue",
			Inspect: "iostat -x 1 5 && dmesg | grep -i 'xfs\\|I/O error' | tail -20",
			Fix:     "check disk health: dsd disk --plain && smartctl -H /dev/<device>",
		},
	},
	{
		contains: "i/o error",
		hint: models.TimelineHint{
			Explain: "disk I/O error — storage device returning errors; may indicate imminent disk failure",
			Inspect: "dmesg | grep -i 'i/o error\\|blk_update' | tail -20 && smartctl -H /dev/<device>",
			Fix:     "check SMART status: dsd disk --plain",
		},
	},
	// ── container / veth ─────────────────────────────────────────────────────
	{
		contains: "failed to get link information",
		unit:     "systemd-udevd",
		hint: models.TimelineHint{
			Explain: "udevd cannot query container veth interface — kernel netlink buffer exhausted by rapid container creation/deletion",
			Inspect: "sysctl net.core.rmem_max net.core.wmem_max",
			Fix:     "sysctl -w net.core.rmem_max=134217728 && sysctl -w net.core.wmem_max=134217728",
			Persist: "echo -e 'net.core.rmem_max=134217728\\nnet.core.wmem_max=134217728' >> /etc/sysctl.d/99-dsd.conf",
		},
	},
	// ── systemd ───────────────────────────────────────────────────────────────
	{
		contains: "start limit hit",
		hint: models.TimelineHint{
			Explain: "service reached systemd restart limit — it crashed too many times too quickly and is now stopped",
			Inspect: "systemctl status <unit> && journalctl -u <unit> -n 50 --no-pager",
			Fix:     "systemctl reset-failed <unit> && systemctl start <unit>",
		},
	},
	{
		contains: "failed with result 'core-dump'",
		hint: models.TimelineHint{
			Explain: "service crashed with a segfault — check for core dump and binary issues",
			Inspect: "journalctl -u <unit> -n 30 --no-pager && coredumpctl list",
			Fix:     "coredumpctl debug <unit>  (requires gdb)",
		},
	},
	{
		contains: "failed with result 'oom-kill'",
		hint: models.TimelineHint{
			Explain: "service was killed by the OOM killer — it exceeded available memory",
			Inspect: "journalctl -u <unit> -n 30 --no-pager && free -h",
			Fix:     "set MemoryMax= in the service unit or reduce memory usage",
			Persist: "systemctl edit <unit>  # add [Service] MemoryMax=512M",
		},
	},
	// ── hardware ─────────────────────────────────────────────────────────────
	{
		contains: "hardware error",
		hint: models.TimelineHint{
			Explain: "hardware error reported by the kernel — may indicate failing RAM, CPU, or peripheral",
			Inspect: "mcelog --client 2>/dev/null || journalctl -k | grep -i 'mce\\|hardware error' | tail -20",
			Fix:     "run memory test: memtest86+ (requires reboot) or check IPMI/iDRAC SEL",
		},
	},
	{
		contains: "mce:",
		hint: models.TimelineHint{
			Explain: "Machine Check Exception — hardware fault detected by CPU (memory, cache, or bus error)",
			Inspect: "mcelog --client 2>/dev/null && journalctl -k | grep -i mce | tail -20",
			Fix:     "check RAM: memtest86+ at next maintenance window; check SMART on all disks",
		},
	},
	// ── NFS ──────────────────────────────────────────────────────────────────
	{
		contains: "nfs: server",
		hint: models.TimelineHint{
			Explain: "NFS server unreachable or not responding — mounts may hang",
			Inspect: "showmount -e <server> && ping <server> && mount | grep nfs",
			Fix:     "check NFS server status and network connectivity; consider lazy unmount: umount -l <mountpoint>",
		},
	},
	// ── CPU / thermal ────────────────────────────────────────────────────────
	{
		contains: "cpu clock throttled",
		hint: models.TimelineHint{
			Explain: "CPU thermal throttling active — core temperature too high, performance intentionally reduced",
			Inspect: "cat /sys/class/hwmon/hwmon*/temp*_input && sensors",
			Fix:     "check cooling: clean vents, reseat heatsink, verify thermal paste",
		},
	},
	{
		contains: "soft lockup",
		hint: models.TimelineHint{
			Explain: "CPU soft lockup — a CPU core was not able to run the scheduler for >20s, usually a runaway kernel thread",
			Inspect: "dmesg | grep -i 'lockup\\|hung_task' | tail -20 && ps aux | grep D",
			Fix:     "identify blocked processes: cat /proc/*/wchan | sort | uniq -c | sort -rn | head",
		},
	},
}

// annotateHints walks events and attaches a hint to any that match a known pattern.
func annotateHints(events []models.TimelineEvent) []models.TimelineEvent {
	for i := range events {
		events[i].Hint = matchHint(events[i].Unit, events[i].Message)
	}
	return events
}

// matchHint returns the first matching hint for the given unit and message, or nil.
func matchHint(unit, message string) *models.TimelineHint {
	lowerMsg := strings.ToLower(message)
	lowerUnit := strings.ToLower(unit)
	for _, rule := range timelineHintRules {
		if !strings.Contains(lowerMsg, rule.contains) {
			continue
		}
		if rule.unit != "" && !strings.Contains(lowerUnit, strings.ToLower(rule.unit)) {
			continue
		}
		h := rule.hint // copy
		return &h
	}
	return nil
}
