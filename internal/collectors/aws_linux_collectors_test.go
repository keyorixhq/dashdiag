//go:build linux

package collectors

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withAWSFixture needs both dimensions the shared withCombinedFixture (see
// security_linux_source_test.go) provides: IMDS/lookPath results go through
// Cached, and NIC driver detection (enaInterfaces) resolves a sysfs symlink
// via Readlink.
func withAWSFixture(t *testing.T, cached map[string][]byte, links map[string]string, seed func(b *source.Bundle)) {
	t.Helper()
	withCombinedFixture(t, cached, links, seed)
}

// ebsLogPage builds a valid Amazon EBS stats log page (0xD0) with the four
// exceeded-µs counters at their real offsets, for feeding through PutCmd as
// the raw output of `nvme get-log ... --raw-binary`.
func ebsLogPage(volIOPS, volTP, instIOPS, instTP uint64) string {
	buf := make([]byte, 88)
	binary.LittleEndian.PutUint32(buf[0:4], ebsStatsMagic)
	binary.LittleEndian.PutUint64(buf[56:64], volIOPS)
	binary.LittleEndian.PutUint64(buf[64:72], volTP)
	binary.LittleEndian.PutUint64(buf[72:80], instIOPS)
	binary.LittleEndian.PutUint64(buf[80:88], instTP)
	return string(buf)
}

func TestAWSCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewAWSCollector()
	if c.Name() != "AWS" {
		t.Errorf("Name() = %q, want AWS", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestAWSGuestAvailable_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("Amazon EC2\n"))
	})
	if !AWSGuestAvailable() {
		t.Error("expected AWSGuestAvailable=true")
	}
}

func TestAWSGuestAvailable_False(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/sys_vendor", []byte("QEMU\n"))
	})
	if AWSGuestAvailable() {
		t.Error("expected AWSGuestAvailable=false")
	}
}

func TestNitroEnclaveState_PresentAndRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/dev/nitro_enclaves", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "nitro-enclaves-allocator"}, "active\n", 0)
	})
	present, running := nitroEnclaveState()
	if !present || !running {
		t.Errorf("present=%v running=%v, want true/true", present, running)
	}
}

func TestNitroEnclaveState_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	present, running := nitroEnclaveState()
	if present || running {
		t.Errorf("present=%v running=%v, want false/false", present, running)
	}
}

func TestIsReplaySource(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if !isReplaySource() {
		t.Error("expected true under a Replay source")
	}
}

func TestSleepCtx_Completes(t *testing.T) {
	t.Parallel()
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Error("expected true when the timer fires before cancellation")
	}
}

func TestSleepCtx_ContextCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, time.Second) {
		t.Error("expected false when ctx is already cancelled")
	}
}

func TestEnaInterfaces(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
		"/sys/class/net/eth1/device/driver": "../../../bus/pci/drivers/virtio_net",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "eth1", "lo"})
	})
	ifaces := enaInterfaces()
	if len(ifaces) != 1 || ifaces[0] != "eth0" {
		t.Errorf("enaInterfaces() = %v, want [eth0]", ifaces)
	}
}

func TestEnaRead(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmd("ethtool", []string{"-S", "eth0"},
			"NIC statistics:\n     bw_in_allowance_exceeded: 5\n     pps_allowance_exceeded: 0\n", 0)
	})
	got := enaRead(context.Background())
	if len(got) != 1 || got["eth0"]["bw_in"] != 5 {
		t.Errorf("enaRead() = %v, want eth0.bw_in=5", got)
	}
}

// TestEnaRead_EthtoolFails covers the runCmd error branch — an interface whose
// ethtool -S invocation fails must be skipped, not surfaced as an empty-but-OK
// reading.
func TestEnaRead_EthtoolFails(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmdNotFound("ethtool", []string{"-S", "eth0"})
	})
	got := enaRead(context.Background())
	if len(got) != 0 {
		t.Errorf("enaRead() = %v, want empty map when ethtool fails", got)
	}
}

func TestEnaAnyNonzero(t *testing.T) {
	t.Parallel()
	if enaAnyNonzero(map[string]map[string]uint64{"eth0": {"bw_in": 0}}) {
		t.Error("expected false — all zero")
	}
	if !enaAnyNonzero(map[string]map[string]uint64{"eth0": {"bw_in": 1}}) {
		t.Error("expected true — one nonzero")
	}
}

func TestEnaComputeDelta(t *testing.T) {
	t.Parallel()
	first := map[string]map[string]uint64{"eth0": {"bw_in": 5}}
	second := map[string]map[string]uint64{"eth0": {"bw_in": 8}}
	delta := enaComputeDelta(first, second)
	if delta["eth0"]["bw_in"] != 3 {
		t.Errorf("delta = %v, want eth0.bw_in=3", delta)
	}
}

func TestEnaComputeDelta_Saturates(t *testing.T) {
	t.Parallel()
	first := map[string]map[string]uint64{"eth0": {"bw_in": 10}}
	second := map[string]map[string]uint64{"eth0": {"bw_in": 2}} // counter reset
	delta := enaComputeDelta(first, second)
	if delta["eth0"]["bw_in"] != 0 {
		t.Errorf("delta = %v, want eth0.bw_in=0 (saturated)", delta)
	}
}

func TestEnaAssemble(t *testing.T) {
	t.Parallel()
	totals := map[string]map[string]uint64{
		"eth1": {"bw_in": 1},
		"eth0": {"bw_in": 2},
	}
	delta := map[string]map[string]uint64{"eth0": {"bw_in": 1}}
	got := enaAssemble(totals, delta)
	if len(got) != 2 || got[0].Iface != "eth0" || got[1].Iface != "eth1" {
		t.Fatalf("expected sorted [eth0, eth1], got %+v", got)
	}
	if got[0].Active["bw_in"] != 1 {
		t.Errorf("eth0.Active = %v, want bw_in=1", got[0].Active)
	}
	if got[1].Active != nil {
		t.Errorf("eth1.Active = %v, want nil (no delta entry)", got[1].Active)
	}
}

func TestEnaAssemble_Empty(t *testing.T) {
	t.Parallel()
	if got := enaAssemble(nil, nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestEbsDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/block", []string{"nvme0n1", "nvme1n1", "sda"})
		b.PutFile("/sys/block/nvme0n1/device/model", []byte("Amazon Elastic Block Store\n"))
		b.PutFile("/sys/block/nvme1n1/device/model", []byte("Amazon EC2 NVMe Instance Storage\n"))
	})
	devs := ebsDevices()
	if len(devs) != 1 || devs[0] != "nvme0n1" {
		t.Errorf("ebsDevices() = %v, want [nvme0n1] (instance-store and non-nvme excluded)", devs)
	}
}

func TestEbsRead_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/block", []string{"nvme0n1"})
		b.PutFile("/sys/block/nvme0n1/device/model", []byte("Amazon Elastic Block Store\n"))
		b.PutCmd("nvme", []string{"get-log", "/dev/nvme0n1", "--log-id=0xd0", "--log-len=4096", "--raw-binary"},
			ebsLogPage(100, 200, 300, 400), 0)
	})
	raw, meta := ebsRead(context.Background())
	if !meta.attempted || meta.needsRoot || meta.failed {
		t.Errorf("meta = %+v, want attempted only", meta)
	}
	r, ok := raw["nvme0n1"]
	if !ok || r.volIOPS != 100 || r.instTP != 400 {
		t.Errorf("raw[nvme0n1] = %+v, ok=%v", r, ok)
	}
}

func TestEbsRead_NoDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	raw, meta := ebsRead(context.Background())
	if len(raw) != 0 || meta.attempted {
		t.Errorf("expected empty/unattempted, got raw=%v meta=%+v", raw, meta)
	}
}

func TestEbsRead_UnparseableFlagsFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/block", []string{"nvme0n1"})
		b.PutFile("/sys/block/nvme0n1/device/model", []byte("Amazon Elastic Block Store\n"))
		b.PutCmd("nvme", []string{"get-log", "/dev/nvme0n1", "--log-id=0xd0", "--log-len=4096", "--raw-binary"},
			"garbage-not-a-log-page", 0)
	})
	raw, meta := ebsRead(context.Background())
	if len(raw) != 0 || !meta.failed {
		t.Errorf("expected empty raw + failed=true, got raw=%v meta=%+v", raw, meta)
	}
}

// TestEbsRead_NvmeGetLogFails covers the runCmd error branch. This sandbox
// runs as non-root (os.Geteuid() != 0), so the failure is attributed to
// needsRoot rather than a generic failure — mirroring the real-world "can't
// read the vendor log page without root" case, which must report "couldn't
// measure", never a silent empty-but-OK reading.
func TestEbsRead_NvmeGetLogFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/block", []string{"nvme0n1"})
		b.PutFile("/sys/block/nvme0n1/device/model", []byte("Amazon Elastic Block Store\n"))
		b.PutCmdNotFound("nvme", []string{"get-log", "/dev/nvme0n1", "--log-id=0xd0", "--log-len=4096", "--raw-binary"})
	})
	raw, meta := ebsRead(context.Background())
	if len(raw) != 0 {
		t.Errorf("raw = %v, want empty", raw)
	}
	if !meta.attempted {
		t.Error("expected attempted=true")
	}
	if os.Geteuid() != 0 {
		if !meta.needsRoot || meta.failed {
			t.Errorf("meta = %+v, want needsRoot=true failed=false (non-root sandbox)", meta)
		}
	} else if !meta.failed || meta.needsRoot {
		t.Errorf("meta = %+v, want failed=true needsRoot=false (root sandbox)", meta)
	}
}

func TestEbsAnyNonzero(t *testing.T) {
	t.Parallel()
	if ebsAnyNonzero(map[string]ebsRaw{"a": {volIOPS: 0, volTP: 0, instIOPS: 0, instTP: 0}}) {
		t.Error("expected false")
	}
	if !ebsAnyNonzero(map[string]ebsRaw{"a": {instTP: 1}}) {
		t.Error("expected true")
	}
}

func TestEbsComputeDelta(t *testing.T) {
	t.Parallel()
	first := map[string]ebsRaw{"nvme0n1": {volIOPS: 10}}
	second := map[string]ebsRaw{"nvme0n1": {volIOPS: 15}}
	delta := ebsComputeDelta(first, second)
	if delta["nvme0n1"].volIOPS != 5 {
		t.Errorf("delta.volIOPS = %d, want 5", delta["nvme0n1"].volIOPS)
	}
}

func TestEbsAssemble(t *testing.T) {
	t.Parallel()
	totals := map[string]ebsRaw{"nvme1n1": {volIOPS: 1}, "nvme0n1": {volIOPS: 2}}
	delta := map[string]ebsRaw{"nvme0n1": {volIOPS: 1}}
	got := ebsAssemble(totals, delta)
	if len(got) != 2 || got[0].Device != "nvme0n1" || got[1].Device != "nvme1n1" {
		t.Fatalf("expected sorted [nvme0n1, nvme1n1], got %+v", got)
	}
	if got[0].ActiveVolumeIOPSUs != 1 {
		t.Errorf("nvme0n1.ActiveVolumeIOPSUs = %d, want 1", got[0].ActiveVolumeIOPSUs)
	}
}

// TestSortEBS_MultiSwapCascade drives sortEBS directly with a fully
// reverse-sorted slice so the inner insertion-sort loop swaps more than once
// per outer iteration (j walks past 0), which the map-iteration-order-dependent
// coverage via ebsAssemble does not reliably exercise.
func TestSortEBS_MultiSwapCascade(t *testing.T) {
	t.Parallel()
	s := []models.EBSStats{{Device: "c"}, {Device: "b"}, {Device: "a"}}
	sortEBS(s)
	if s[0].Device != "a" || s[1].Device != "b" || s[2].Device != "c" {
		t.Errorf("sortEBS() = %+v, want [a b c]", s)
	}
}

func TestEbsAssemble_Empty(t *testing.T) {
	t.Parallel()
	if got := ebsAssemble(nil, nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestEnaExpressState_ActiveTraffic(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmd("ethtool", []string{"-S", "eth0"},
			"NIC statistics:\n     ena_srd_tx_pkts: 42\n     ena_srd_rx_pkts: 0\n", 0)
	})
	checked, active := enaExpressState(context.Background())
	if !checked || !active {
		t.Errorf("checked=%v active=%v, want true/true", checked, active)
	}
}

func TestEnaExpressState_NoENAInterfaces(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, active := enaExpressState(context.Background())
	if checked || active {
		t.Errorf("checked=%v active=%v, want false/false", checked, active)
	}
}

// TestEnaExpressState_EthtoolFails guards the runCmd-error "continue" branch:
// an ENA interface whose `ethtool -S` invocation fails must be skipped
// (never counted toward checked) rather than aborting the whole scan, so a
// second, healthy interface is still reported.
func TestEnaExpressState_EthtoolFails(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmdNotFound("ethtool", []string{"-S", "eth0"})
	})
	checked, active := enaExpressState(context.Background())
	if checked || active {
		t.Errorf("checked=%v active=%v, want false/false (ethtool failure must not count as checked)", checked, active)
	}
}

func TestAwsInstanceType(t *testing.T) {
	withAWSFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok123"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type": []byte("t4g.small"),
	}, nil, func(b *source.Bundle) {})
	if got := awsInstanceType(context.Background()); got != "t4g.small" {
		t.Errorf("awsInstanceType() = %q, want t4g.small", got)
	}
}

func TestAwsInstanceType_NoToken(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := awsInstanceType(context.Background()); got != "" {
		t.Errorf("awsInstanceType() = %q, want empty", got)
	}
}

func TestAwsIMDSv1Open_Open(t *testing.T) {
	withAWSFixture(t, map[string][]byte{"aws-imdsv1-probe": []byte("open")}, nil, nil)
	checked, open := awsIMDSv1Open(context.Background())
	if !checked || !open {
		t.Errorf("checked=%v open=%v, want true/true", checked, open)
	}
}

func TestAwsIMDSv1Open_Blocked(t *testing.T) {
	withAWSFixture(t, map[string][]byte{"aws-imdsv1-probe": []byte("blocked")}, nil, nil)
	checked, open := awsIMDSv1Open(context.Background())
	if !checked || open {
		t.Errorf("checked=%v open=%v, want true/false", checked, open)
	}
}

func TestAwsIMDSv1Open_Unreachable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, open := awsIMDSv1Open(context.Background())
	if checked || open {
		t.Errorf("checked=%v open=%v, want false/false", checked, open)
	}
}

func TestAwsRebalance_Recommended(t *testing.T) {
	withAWSFixture(t, map[string][]byte{
		"imds-aws-token":      []byte("tok123"),
		"aws-rebalance-probe": []byte("yes"),
	}, nil, nil)
	checked, recommended := awsRebalance(context.Background())
	if !checked || !recommended {
		t.Errorf("checked=%v recommended=%v, want true/true", checked, recommended)
	}
}

func TestAwsRebalance_NoToken(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	checked, recommended := awsRebalance(context.Background())
	if checked || recommended {
		t.Errorf("checked=%v recommended=%v, want false/false", checked, recommended)
	}
}

func TestSsmState_InstalledAndRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/amazon-ssm-agent", source.FileMeta{})
		b.PutCmd("systemctl", []string{"is-active", "amazon-ssm-agent"}, "active\n", 0)
	})
	installed, running := ssmState(context.Background())
	if !installed || !running {
		t.Errorf("installed=%v running=%v, want true/true", installed, running)
	}
}

func TestSsmState_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	installed, running := ssmState(context.Background())
	if installed || running {
		t.Errorf("installed=%v running=%v, want false/false", installed, running)
	}
}

func TestSsmState_InstalledNotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/amazon-ssm-agent", source.FileMeta{})
		b.PutCmdNotFound("systemctl", []string{"is-active", "amazon-ssm-agent"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "snap.amazon-ssm-agent.amazon-ssm-agent"})
	})
	installed, running := ssmState(context.Background())
	if !installed || running {
		t.Errorf("installed=%v running=%v, want true/false", installed, running)
	}
}

// TestSsmState_InstalledViaLookPath covers the lookPath("amazon-ssm-agent")
// success branch — installed via $PATH resolution rather than one of the
// hardcoded file locations.
func TestSsmState_InstalledViaLookPath(t *testing.T) {
	withAWSFixture(t, map[string][]byte{
		"lookpath/amazon-ssm-agent": []byte("/usr/local/bin/amazon-ssm-agent"),
	}, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "amazon-ssm-agent"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "snap.amazon-ssm-agent.amazon-ssm-agent"})
	})
	installed, running := ssmState(context.Background())
	if !installed || running {
		t.Errorf("installed=%v running=%v, want true/false", installed, running)
	}
}

// TestSsmState_RunningViaProcComm covers the procCommRunning("amazon-ssm-agent")
// true branch — the agent is found live in /proc without needing the systemctl
// fallback.
func TestSsmState_RunningViaProcComm(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/amazon-ssm-agent", source.FileMeta{})
		b.PutDir("/proc", []string{"100"})
		b.PutDir("/proc/100", []string{"comm", "cgroup"})
		b.PutFile("/proc/100/comm", []byte("amazon-ssm-agent\n"))
		// /proc/100/cgroup intentionally unseeded: unreadable -> host, not container.
	})
	installed, running := ssmState(context.Background())
	if !installed || !running {
		t.Errorf("installed=%v running=%v, want true/true", installed, running)
	}
}

// TestAWSCollector_Collect_FullHappyPath drives the whole Collect() wiring —
// ENA/EBS single-snapshot read (no second sample: isReplaySource() is true
// under any test fixture, so the ~1s delta sleep never runs), IMDS posture,
// and the local daemon checks.
func TestAWSCollector_Collect_FullHappyPath(t *testing.T) {
	withAWSFixture(t, map[string][]byte{
		"imds-aws-token": []byte("tok123"),
		"imds/http://169.254.169.254/latest/meta-data/instance-type": []byte("m5.large"),
		"aws-imdsv1-probe":    []byte("blocked"),
		"aws-rebalance-probe": []byte("no"),
	}, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmd("ethtool", []string{"-S", "eth0"}, "NIC statistics:\n     bw_in_allowance_exceeded: 0\n", 0)
		b.PutDir("/sys/block", []string{"nvme0n1"})
		b.PutFile("/sys/block/nvme0n1/device/model", []byte("Amazon Elastic Block Store\n"))
		b.PutCmd("nvme", []string{"get-log", "/dev/nvme0n1", "--log-id=0xd0", "--log-len=4096", "--raw-binary"},
			ebsLogPage(0, 0, 0, 0), 0)
	})

	got, err := NewAWSCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.AWSInfo)
	if !info.IsEC2 {
		t.Error("expected IsEC2=true")
	}
	if info.InstanceType != "m5.large" {
		t.Errorf("InstanceType = %q, want m5.large", info.InstanceType)
	}
	if info.Sampled {
		t.Error("expected Sampled=false — all-zero counters skip the second snapshot")
	}
	if !info.EBSReadAttempted {
		t.Error("expected EBSReadAttempted=true")
	}
	if !info.IMDSChecked || info.IMDSv1Enabled {
		t.Errorf("IMDS = checked=%v v1=%v, want true/false", info.IMDSChecked, info.IMDSv1Enabled)
	}
	if !info.RebalanceChecked || info.RebalanceRecommended {
		t.Errorf("Rebalance = checked=%v rec=%v, want true/false", info.RebalanceChecked, info.RebalanceRecommended)
	}
}

// TestAWSCollector_Collect_SampledOnNonzeroCounter drives the second-snapshot
// path: a nonzero ENA allowance counter on the first read, combined with a
// non-Replay active source (fakeCombinedSource, not *source.Replay), so
// isReplaySource() is false and the ~1s delta sample actually runs. Guards
// the Sampled=true wiring that TestAWSCollector_Collect_FullHappyPath
// deliberately avoids by keeping every counter at zero.
func TestAWSCollector_Collect_SampledOnNonzeroCounter(t *testing.T) {
	withAWSFixture(t, nil, map[string]string{
		"/sys/class/net/eth0/device/driver": "../../../bus/pci/drivers/ena",
	}, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0"})
		b.PutCmd("ethtool", []string{"-S", "eth0"},
			"NIC statistics:\n     bw_in_allowance_exceeded: 5\n", 0)
	})

	got, err := NewAWSCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.AWSInfo)
	if !info.Sampled {
		t.Error("expected Sampled=true — nonzero counter under a non-replay source must trigger the delta sample")
	}
}
