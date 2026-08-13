package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// hasAWSInsight reports whether any insight matches level and contains all substrings.
func hasAWSInsight(ins []models.Insight, level string, subs ...string) bool {
	for _, i := range ins {
		if i.Level != level {
			continue
		}
		ok := true
		for _, s := range subs {
			if !strings.Contains(i.Message, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// A DMI-confirmed EC2 host (IsEC2==true) where IMDSChecked/RebalanceChecked
// are false means the probe itself failed (firewalled IMDS, IMDSv2-only
// lockdown, token request error) — never "not on EC2", since that state
// never reaches this collector. Both must disclose, not silently drop out of
// the recognition line the way "EC2 t4g.small — ENA allowances clean" used to
// with zero mention that IMDS/rebalance posture was never actually read.
func TestCheckAWS_UncheckedIMDSAndRebalanceDisclose(t *testing.T) {
	if !hasAWSInsight(checkAWS(models.AWSInfo{IsEC2: true, IMDSChecked: false}), "INFO", "could not verify IMDS posture") {
		t.Error("IMDSChecked=false must disclose, not silently pass")
	}
	if !hasAWSInsight(checkAWS(models.AWSInfo{IsEC2: true, IMDSChecked: true, RebalanceChecked: false}), "INFO", "could not verify EC2 rebalance-recommendation status") {
		t.Error("RebalanceChecked=false must disclose, not silently pass")
	}
}

func TestCheckAWS_NonEC2Silent(t *testing.T) {
	if got := checkAWS(models.AWSInfo{}); got != nil {
		t.Errorf("non-EC2 should yield no insights, got %v", got)
	}
}

func TestCheckAWS_HealthyRecognition(t *testing.T) {
	// Clean instance: ENA read with zero allowances, EBS read OK with zero throttle,
	// IMDSv2 enforced. Expect exactly one INFO recognition line that asserts only what
	// was verified.
	a := models.AWSInfo{
		IsEC2:        true,
		InstanceType: "t4g.small",
		ENA: []models.ENAStats{{Iface: "ens5", Total: map[string]uint64{
			"bw_in": 0, "bw_out": 0, "pps": 0, "conntrack": 0, "linklocal": 0,
		}}},
		EBS:         []models.EBSStats{{Device: "nvme0n1"}},
		IMDSChecked: true, IMDSv1Enabled: false,
		RebalanceChecked: true,
	}
	got := checkAWS(a)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("healthy = %+v, want one INFO line", got)
	}
	for _, want := range []string{"t4g.small", "ENA allowances clean", "EBS performance OK", "IMDSv2 enforced"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("recognition line missing %q: %q", want, got[0].Message)
		}
	}
}

func TestCheckAWS_ENAActiveVsHistorical(t *testing.T) {
	// Active (delta in the sample window) → WARN; historical-only total → INFO.
	a := models.AWSInfo{
		IsEC2: true,
		ENA: []models.ENAStats{{
			Iface:  "ens5",
			Total:  map[string]uint64{"bw_out": 5000, "pps": 12},
			Active: map[string]uint64{"bw_out": 0, "pps": 12}, // pps rising now, bw_out only historical
		}},
	}
	got := checkAWS(a)
	if !hasAWSInsight(got, "WARN", "ens5", "packets-per-second", "in the last second") {
		t.Errorf("active pps throttle should WARN, got %+v", got)
	}
	if !hasAWSInsight(got, "INFO", "outbound-bandwidth", "since boot") {
		t.Errorf("historical bw_out should be INFO, got %+v", got)
	}
	// The active pps line must NOT also be reported as historical.
	if hasAWSInsight(got, "INFO", "packets-per-second", "since boot") {
		t.Errorf("active pps must not also fire as historical INFO: %+v", got)
	}
}

func TestCheckAWS_EBSActiveThrottle(t *testing.T) {
	a := models.AWSInfo{
		IsEC2: true,
		EBS: []models.EBSStats{{
			Device:               "nvme1n1",
			VolumeIOPSExceededUs: 2_000_000, ActiveVolumeIOPSUs: 350_000,
			InstanceTPExceededUs: 9_000, // historical only, no active
		}},
	}
	got := checkAWS(a)
	if !hasAWSInsight(got, "WARN", "nvme1n1", "volume IOPS", "throttled right now") {
		t.Errorf("active volume-IOPS throttle should WARN, got %+v", got)
	}
	if !hasAWSInsight(got, "INFO", "instance-aggregate EBS throughput", "since attach") {
		t.Errorf("historical instance-TP should be INFO, got %+v", got)
	}
}

// insightHintsContain reports whether any insight's Hints slice has an entry
// containing sub — used by the shell-metacharacter-injection regression
// tests, which must inspect Hints (the copy-pasteable "to inspect:" strings),
// not Message. Named distinctly from hintsContain (heuristics_vmware_steal_test.go),
// which takes a bare []string of hints rather than []models.Insight.
func insightHintsContain(ins []models.Insight, sub string) bool {
	for _, i := range ins {
		if hintsContain(i.Hints, sub) {
			return true
		}
	}
	return false
}

// TestCheckAWS_ENAHintOmitsShellMetachars is a regression test for the shell-
// metacharacter-injection class (distinct from the ANSI/control-escape class
// PR #991 fixed): awsENAInsights used to splice the ENA interface name
// unescaped into a copy-pasteable "to inspect: ethtool -S <iface> | ..."
// hint. A crafted interface name containing shell metacharacters must never
// appear verbatim in a hint.
func TestCheckAWS_ENAHintOmitsShellMetachars(t *testing.T) {
	a := models.AWSInfo{
		IsEC2: true,
		ENA: []models.ENAStats{{
			Iface:  "eth0; rm -rf /",
			Active: map[string]uint64{"pps": 5},
		}},
	}
	got := checkAWS(a)
	if insightHintsContain(got, "rm -rf /") {
		t.Errorf("ENA hint must not embed the raw shell-metacharacter interface name verbatim (copy-paste RCE risk): %+v", got)
	}
}

// TestCheckAWS_EBSHintOmitsShellMetachars covers ebsThrottleInsight, which
// used to splice the EBS device name unescaped into a copy-pasteable
// "to inspect: sudo nvme get-log /dev/<dev> ..." hint.
func TestCheckAWS_EBSHintOmitsShellMetachars(t *testing.T) {
	a := models.AWSInfo{
		IsEC2: true,
		EBS: []models.EBSStats{{
			Device:               "nvme1n1`whoami`",
			VolumeIOPSExceededUs: 2_000_000, ActiveVolumeIOPSUs: 350_000,
		}},
	}
	got := checkAWS(a)
	if insightHintsContain(got, "whoami") {
		t.Errorf("EBS hint must not embed the raw shell-metacharacter device name verbatim (copy-paste RCE risk): %+v", got)
	}
}

func TestCheckAWS_EBSNeedsRootDegrades(t *testing.T) {
	// EBS read failed non-root: must surface an explicit "needs root / NOT verified"
	// rather than a silent OK, and the recognition line must not claim EBS is fine.
	a := models.AWSInfo{IsEC2: true, EBSReadAttempted: true, EBSNeedsRoot: true, IMDSChecked: true}
	got := checkAWS(a)
	if !hasAWSInsight(got, "INFO", "EBS performance stats need root") {
		t.Fatalf("non-root EBS must degrade explicitly, got %+v", got)
	}
	for _, i := range got {
		if strings.Contains(i.Message, "EBS performance OK") {
			t.Errorf("must NOT claim EBS OK when it needs root: %q", i.Message)
		}
	}
}

func TestCheckAWS_IMDSv1Warn(t *testing.T) {
	got := checkAWS(models.AWSInfo{IsEC2: true, IMDSChecked: true, IMDSv1Enabled: true})
	if !hasAWSInsight(got, "WARN", "IMDSv1 is enabled") {
		t.Errorf("IMDSv1 enabled should WARN, got %+v", got)
	}
}

func TestCheckAWS_RebalanceWarn(t *testing.T) {
	got := checkAWS(models.AWSInfo{IsEC2: true, RebalanceChecked: true, RebalanceRecommended: true})
	if !hasAWSInsight(got, "WARN", "rebalance recommendation") {
		t.Errorf("rebalance recommendation should WARN, got %+v", got)
	}
}

func TestCheckAWS_SSMAndTimeSync(t *testing.T) {
	got := checkAWS(models.AWSInfo{
		IsEC2:        true,
		SSMInstalled: true, SSMRunning: false,
		TimeSyncChecked: true, UsesAmazonTimeSync: false,
	})
	if !hasAWSInsight(got, "WARN", "amazon-ssm-agent is installed but not running") {
		t.Errorf("SSM installed-not-running should WARN, got %+v", got)
	}
	if !hasAWSInsight(got, "INFO", "Amazon Time Sync Service") {
		t.Errorf("non-Amazon time sync should INFO, got %+v", got)
	}
}

func TestCheckAWS_TailRecognition(t *testing.T) {
	// ENA Express active + Nitro Enclaves present fold into the recognition line (no WARN).
	a := models.AWSInfo{
		IsEC2: true, InstanceType: "c6gn.medium",
		ENA:               []models.ENAStats{{Iface: "ens5", Total: map[string]uint64{"bw_in": 0}}},
		IMDSChecked:       true,
		RebalanceChecked:  true,
		ENAExpressChecked: true, ENAExpressActive: true,
		NitroEnclavesPresent: true,
	}
	got := checkAWS(a)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("tail recognition = %+v, want one INFO line", got)
	}
	for _, want := range []string{"ENA Express active", "Nitro Enclaves present"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("recognition line missing %q: %q", want, got[0].Message)
		}
	}
}
