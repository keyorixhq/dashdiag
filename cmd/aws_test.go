package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// ec2Info has both self-serve posture issues (IMDSv1, SSM stopped, non-Amazon time
// sync) and AWS-imposed throttling evidence (ENA outbound-bandwidth allowance + EBS
// volume-IOPS, both active right now) — exercising both blocks of the split.
func ec2Info() *models.AWSInfo {
	return &models.AWSInfo{
		IsEC2: true, InstanceType: "m5.large",
		ENA: []models.ENAStats{{Iface: "eth0",
			Total: map[string]uint64{"bw_out": 10}, Active: map[string]uint64{"bw_out": 3}}},
		EBS:         []models.EBSStats{{Device: "nvme1n1", ActiveVolumeIOPSUs: 1_500_000}},
		IMDSChecked: true, IMDSv1Enabled: true,
		SSMInstalled: true, SSMRunning: false,
		TimeSyncChecked: true, UsesAmazonTimeSync: false,
	}
}

func TestPrintAWSReport_TwoBlockSplit(t *testing.T) {
	var buf bytes.Buffer
	printAWSReport(&buf, ec2Info(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	guestHdr := "Your instance — you can fix these"
	provHdr := "AWS-imposed limits — evidence to share with AWS support"
	gi, pi := strings.Index(out, guestHdr), strings.Index(out, provHdr)
	if gi < 0 || pi < 0 {
		t.Fatalf("both block headers must be present; got:\n%s", out)
	}
	if gi > pi {
		t.Errorf("self-serve block must come before the provider-evidence block")
	}
	guestBlock, provBlock := out[gi:pi], out[pi:]

	for _, want := range []string{"IMDSv1", "amazon-ssm-agent"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("self-serve block missing %q", want)
		}
	}
	for _, want := range []string{"allowance", "EBS"} {
		if !strings.Contains(provBlock, want) {
			t.Errorf("provider block missing %q", want)
		}
	}
	if strings.Contains(provBlock, "IMDSv1") {
		t.Errorf("IMDSv1 (self-serve) leaked into the provider block")
	}
	// IMDSv1 + SSM (self-serve WARN) + ENA + EBS (provider WARN) = 4; time sync is INFO.
	if c := awsConcerns(ec2Info()); c != 4 {
		t.Errorf("awsConcerns = %d, want 4 (IMDSv1 + SSM + ENA + EBS; time-sync is INFO)", c)
	}
	if !strings.Contains(out, "4 EC2 issue(s) found") {
		t.Errorf("summary should report 4 issues; got:\n%s", out)
	}
}

func TestPrintAWSReport_Healthy(t *testing.T) {
	clean := &models.AWSInfo{IsEC2: true, InstanceType: "t4g.small", IMDSChecked: true} // IMDSv2 enforced, nothing else
	var buf bytes.Buffer
	printAWSReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if awsConcerns(clean) != 0 {
		t.Fatalf("clean instance should have 0 concerns, got %d", awsConcerns(clean))
	}
	if !strings.Contains(out, "EC2 guest healthy") {
		t.Errorf("clean instance should print the healthy summary; got:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged'; got:\n%s", out)
	}
}
