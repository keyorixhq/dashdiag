package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkAWS reports guest-side health for a Linux EC2 instance. The headline checks
// are the *silent throttles* — ENA network allowance and EBS performance limits that
// drop packets / cap IOPS with no error anywhere else — plus IMDS security posture,
// the spot rebalance recommendation, Amazon Time Sync, and the SSM agent. Silent on
// every non-EC2 host (the collector only runs behind the DMI gate). When everything
// it could verify is clean it emits one INFO recognition line.
func checkAWS(a models.AWSInfo) []models.Insight {
	if !a.IsEC2 {
		return nil
	}
	var out []models.Insight
	out = append(out, awsENAInsights(a)...)
	out = append(out, awsEBSInsights(a)...)
	out = append(out, awsIMDSInsights(a)...)
	out = append(out, awsRebalanceInsights(a)...)
	out = append(out, awsTimeSyncInsights(a)...)
	out = append(out, awsSSMInsights(a)...)
	if len(out) == 0 {
		out = append(out, insight("INFO", "AWS", awsRecognitionLine(a), nil))
	}
	return out
}

// ---------- ENA network allowance ----------

type enaAllowance struct {
	key, label, effect, hint string
}

// enaAllowances is the stable iteration order and human framing for the five ENA
// allowance-exceeded counters.
var enaAllowances = []enaAllowance{
	{"bw_in", "inbound-bandwidth", "inbound packets shaped/dropped",
		"this is the instance's bandwidth ceiling — a larger instance type raises it"},
	{"bw_out", "outbound-bandwidth", "outbound packets shaped/dropped",
		"this is the instance's bandwidth ceiling — a larger instance type raises it"},
	{"pps", "packets-per-second", "packets dropped",
		"high small-packet rate — a larger instance type raises the PPS ceiling"},
	{"conntrack", "connection-tracking", "new connections dropped",
		"too many tracked connections — reduce concurrent connections or use a larger instance"},
	{"linklocal", "link-local-services", "DNS / IMDS / NTP traffic dropped",
		"link-local PPS limit hit — reduce the rate of DNS / metadata / NTP calls"},
}

func awsENAInsights(a models.AWSInfo) []models.Insight {
	var out []models.Insight
	for _, e := range a.ENA {
		for _, al := range enaAllowances {
			total := e.Total[al.key]
			var active uint64
			if e.Active != nil {
				active = e.Active[al.key]
			}
			hints := []string{al.hint, "to inspect: ethtool -S " + e.Iface + " | grep allowance_exceeded"}
			switch {
			case active > 0:
				out = append(out, insight("WARN", "AWS",
					fmt.Sprintf("%s: ENA %s allowance exceeded %d time(s) in the last second — %s right now",
						e.Iface, al.label, active, al.effect),
					hints))
			case total > 0:
				out = append(out, insight("INFO", "AWS",
					fmt.Sprintf("%s: ENA %s allowance has been exceeded %d time(s) since boot (none during this check) — %s when it fires",
						e.Iface, al.label, total, al.effect),
					hints))
			}
		}
	}
	return out
}

// ---------- EBS volume performance throttle ----------

func awsEBSInsights(a models.AWSInfo) []models.Insight {
	var out []models.Insight
	// Honest degrade: don't let a clean run imply EBS throttling was checked when the
	// vendor log page couldn't be read (false-OK rule — non-root must say so).
	switch {
	case a.EBSNeedsRoot:
		out = append(out, insight("INFO", "AWS",
			"EBS performance stats need root — run dsd as root to check whether EBS IOPS/throughput is being throttled",
			[]string{"note: the EBS NVMe vendor log page (0xD0) is root-only"}))
	case a.EBSReadFailed:
		out = append(out, insight("INFO", "AWS",
			"could not read EBS performance stats (nvme get-log on an EBS device failed or returned no EBS data) — EBS throttling NOT verified",
			[]string{"to inspect: nvme get-log /dev/nvme0n1 --log-id=0xd0 --log-len=4096 --raw-binary | xxd | head"}))
	}
	for _, d := range a.EBS {
		out = append(out, ebsThrottleInsight(d.Device, "volume IOPS",
			"the volume's provisioned IOPS is the bottleneck — raise IOPS (gp3/io2) or change volume type",
			d.ActiveVolumeIOPSUs, d.VolumeIOPSExceededUs)...)
		out = append(out, ebsThrottleInsight(d.Device, "volume throughput",
			"the volume's provisioned throughput is the bottleneck — raise MB/s (gp3) or change volume type",
			d.ActiveVolumeTPUs, d.VolumeTPExceededUs)...)
		out = append(out, ebsThrottleInsight(d.Device, "instance-aggregate EBS IOPS",
			"the instance's aggregate EBS IOPS limit (not the volume) — a larger / EBS-optimized instance type raises it",
			d.ActiveInstanceIOPSUs, d.InstanceIOPSExceededUs)...)
		out = append(out, ebsThrottleInsight(d.Device, "instance-aggregate EBS throughput",
			"the instance's aggregate EBS throughput limit (not the volume) — a larger / EBS-optimized instance type raises it",
			d.ActiveInstanceTPUs, d.InstanceTPExceededUs)...)
	}
	return out
}

// ebsThrottleInsight renders one EBS performance-exceeded counter: WARN when it is
// rising during the sample window (throttled right now), INFO when it is only a
// historical total, nothing when zero.
func ebsThrottleInsight(dev, label, hint string, active, total uint64) []models.Insight {
	inspect := fmt.Sprintf("to inspect: sudo nvme get-log /dev/%s --log-id=0xd0 --log-len=4096 --raw-binary", dev)
	switch {
	case active > 0:
		return []models.Insight{insight("WARN", "AWS",
			fmt.Sprintf("EBS %s: %s limit exceeded for %s in the last second — IO is being throttled right now",
				dev, label, microDur(active)),
			[]string{hint, inspect})}
	case total > 0:
		return []models.Insight{insight("INFO", "AWS",
			fmt.Sprintf("EBS %s: %s limit was exceeded for %s since attach (none during this check)",
				dev, label, microDur(total)),
			[]string{hint, inspect})}
	}
	return nil
}

// microDur renders a microsecond count as a short human duration.
func microDur(us uint64) string {
	switch {
	case us >= 1_000_000:
		return fmt.Sprintf("%.1fs", float64(us)/1_000_000)
	case us >= 1_000:
		return fmt.Sprintf("%dms", us/1_000)
	default:
		return fmt.Sprintf("%dµs", us)
	}
}

// ---------- IMDS posture / rebalance / time sync / SSM ----------

func awsIMDSInsights(a models.AWSInfo) []models.Insight {
	if a.IMDSChecked && a.IMDSv1Enabled {
		return []models.Insight{insight("WARN", "AWS",
			"IMDSv1 is enabled (HttpTokens=optional) — instance credentials are reachable via a token-less request, the SSRF path behind the Capital One breach class",
			[]string{
				"to fix: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled",
				"note: confirm no in-instance software still uses IMDSv1 before enforcing",
			})}
	}
	return nil
}

func awsRebalanceInsights(a models.AWSInfo) []models.Insight {
	if a.RebalanceChecked && a.RebalanceRecommended {
		return []models.Insight{insight("WARN", "AWS",
			"EC2 rebalance recommendation is active — AWS signals this spot instance is at elevated risk of interruption; drain/migrate before the termination notice",
			[]string{"to inspect: curl -s http://169.254.169.254/latest/meta-data/events/recommendations/rebalance"})}
	}
	return nil
}

func awsTimeSyncInsights(a models.AWSInfo) []models.Insight {
	if a.TimeSyncChecked && !a.UsesAmazonTimeSync {
		return []models.Insight{insight("INFO", "AWS",
			"NTP is not pointed at the Amazon Time Sync Service (169.254.169.123) — the link-local service avoids clock drift and egress latency",
			[]string{
				"to fix (chrony): add 'server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4' to /etc/chrony.conf, then restart chrony",
			})}
	}
	return nil
}

func awsSSMInsights(a models.AWSInfo) []models.Insight {
	if a.SSMInstalled && !a.SSMRunning {
		return []models.Insight{insight("WARN", "AWS",
			"amazon-ssm-agent is installed but not running — Systems Manager (Session Manager, patch, run-command) is unavailable on this instance",
			[]string{"to fix: systemctl enable --now amazon-ssm-agent   (snap: snap start amazon-ssm-agent.amazon-ssm-agent)"})}
	}
	return nil
}

// awsRecognitionLine summarises what dsd verified clean, asserting only the things it
// actually checked (never claiming EBS was OK when the stats couldn't be read).
func awsRecognitionLine(a models.AWSInfo) string {
	itype := a.InstanceType
	if itype == "" {
		itype = "instance"
	}
	parts := []string{}
	if len(a.ENA) > 0 {
		parts = append(parts, "ENA allowances clean")
	}
	switch {
	case len(a.EBS) > 0:
		parts = append(parts, "EBS performance OK")
	case a.EBSNeedsRoot:
		parts = append(parts, "EBS performance not checked (needs root)")
	}
	if a.IMDSChecked && !a.IMDSv1Enabled {
		parts = append(parts, "IMDSv2 enforced")
	}
	summary := "no guest-side throttling or posture issues found"
	if len(parts) > 0 {
		summary = strings.Join(parts, "; ")
	}
	return fmt.Sprintf("EC2 %s — %s", itype, summary)
}
