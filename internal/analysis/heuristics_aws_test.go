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
