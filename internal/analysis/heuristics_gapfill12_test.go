package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestAWSRecognitionLine_EBSNeedsRoot covers two uncovered blocks in one call:
//   - the `if itype == ""` branch (InstanceType is zero-value → "instance")
//   - the `case a.EBSNeedsRoot:` body (adds "EBS performance not checked (needs root)")
//
// awsRecognitionLine is only reached via checkAWS when out==0, so we call it directly.
func TestAWSRecognitionLine_EBSNeedsRoot(t *testing.T) {
	t.Parallel()
	line := awsRecognitionLine(models.AWSInfo{EBSNeedsRoot: true})
	if !strings.Contains(line, "instance") {
		t.Errorf("empty InstanceType must fall back to 'instance', got %q", line)
	}
	if !strings.Contains(line, "needs root") {
		t.Errorf("EBSNeedsRoot must add 'needs root' to recognition line, got %q", line)
	}
}

// TestAzureRecognitionLine_DisksChecked covers the `a.DisksChecked && len(a.Disks) > 0`
// branch in azureRecognitionLine — when disk host-caching was verified, the count
// must appear in the summary.
func TestAzureRecognitionLine_DisksChecked(t *testing.T) {
	t.Parallel()
	line := azureRecognitionLine(models.AzureInfo{
		DisksChecked: true,
		Disks:        []models.AzureDisk{{}},
	})
	if !strings.Contains(line, "host caching OK") {
		t.Errorf("DisksChecked with one disk must say 'host caching OK', got %q", line)
	}
}

// TestGCPRecognitionLine_NICDriverFallback covers the `case g.NICDriver != ""`
// branch in gcpRecognitionLine — when UsesGVNIC is false but a driver name is known,
// the driver must appear in the summary.
func TestGCPRecognitionLine_NICDriverFallback(t *testing.T) {
	t.Parallel()
	line := gcpRecognitionLine(models.GCPInfo{NICDriver: "virtio_net"})
	if !strings.Contains(line, "virtio_net") {
		t.Errorf("NICDriver fallback must name the driver, got %q", line)
	}
}

// TestCheckCloudInit_ErrorsCapAt3 covers the `i >= 3 { break }` branch in
// checkCloudInit's error-hints loop — only the first 3 errors must appear in
// the hints even when 4 are present.
func TestCheckCloudInit_ErrorsCapAt3(t *testing.T) {
	t.Parallel()
	got := checkCloudInit(models.CloudInitInfo{
		Available: true,
		Status:    "error",
		Errors:    []string{"e1", "e2", "e3", "e4"},
	})
	if len(got) == 0 {
		t.Fatal("cloud-init error must produce a CRIT insight, got none")
	}
	ins := got[0]
	if ins.Level != "CRIT" {
		t.Errorf("expected CRIT, got %q", ins.Level)
	}
	count := 0
	for _, h := range ins.Hints {
		if strings.HasPrefix(h, "error: ") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("error hints must be capped at 3, got %d", count)
	}
}

// TestCheckDNS_ModerateLatencyInfo covers the `else if d.ExternalResolvesOK &&
// d.ExternalLatencyMs > 200` INFO branch — latency between 200 and 500ms must
// produce an INFO, not a WARN (which fires at > 500ms).
func TestCheckDNS_ModerateLatencyInfo(t *testing.T) {
	t.Parallel()
	got := checkDNS(models.DNSResolverInfo{Available: true, ExternalResolvesOK: true, ExternalLatencyMs: 300})
	if !hasInsightMsg(got, "INFO", "DNS latency") {
		t.Errorf("300ms DNS latency must produce an INFO, got %+v", got)
	}
	if hasInsightMsg(got, "WARN", "DNS resolution is slow") {
		t.Errorf("300ms DNS latency must NOT be a WARN (>500ms threshold), got %+v", got)
	}
}

// TestCheckSnapper_UnknownLastSnapshotTime covers the `case s.LastSnapshotH < 0`
// branch in checkSnapper — when snapshots exist but the timestamp could not be
// read (LastSnapshotH == -1), a WARN about unverifiable staleness must fire.
func TestCheckSnapper_UnknownLastSnapshotTime(t *testing.T) {
	t.Parallel()
	got := checkSnapper(models.SnapperInfo{
		Available:     true,
		SnapshotCount: 5,
		LastSnapshotH: -1,
	})
	if !hasInsightMsg(got, "WARN", "could not be determined") {
		t.Errorf("LastSnapshotH < 0 must WARN that timestamp is unknown, got %+v", got)
	}
}

// TestCheckHA_StoppedResources covers the `len(d.StoppedResources) > 0` WARN
// branch in checkHA — a cleanly-stopped (not failed) cluster resource must
// surface as a WARN so the operator can decide whether it should be running.
func TestCheckHA_StoppedResources(t *testing.T) {
	t.Parallel()
	got := checkHA(models.HAInfo{
		Available:        true,
		Running:          true,
		StatusReadable:   true,
		StoppedResources: []string{"rsc_vip"},
	})
	if !hasInsightMsg(got, "WARN", "rsc_vip") {
		t.Errorf("stopped resource must appear in a WARN insight, got %+v", got)
	}
}

// TestCheckHardware_SATAHotDriveWarn covers the
// `case d.Type != hwDriveTypeNVMe && d.TempC >= 50` WARN branch in checkHardware
// — a SATA drive at 55°C must WARN about elevated temperature.
func TestCheckHardware_SATAHotDriveWarn(t *testing.T) {
	t.Parallel()
	got := checkHardware(models.HardwareInfo{
		Drives: []models.HardwareDrive{{
			SmartctlAvailable: true,
			SmartRead:         true,
			SmartOK:           true,
			Type:              "sata",
			TempC:             55,
		}},
	})
	if !hasInsightMsg(got, "WARN", "running hot") {
		t.Errorf("SATA drive at 55°C must WARN 'running hot', got %+v", got)
	}
}

// TestCheckHWRaid_VirtualDiskRebuilding covers the `case vd.Rebuilding:` WARN
// branch in checkHWRaid — a virtual disk mid-rebuild must warn that redundancy
// is not yet restored.
func TestCheckHWRaid_VirtualDiskRebuilding(t *testing.T) {
	t.Parallel()
	got := checkHWRaid(models.HWRaidInfo{
		Available: true,
		Controllers: []models.HWRaidController{{
			VirtualDrives: []models.HWRaidVD{{
				Name:       "VD0",
				Rebuilding: true,
			}},
		}},
	})
	if !hasInsightMsg(got, "WARN", "REBUILDING") {
		t.Errorf("rebuilding VD must produce a WARN, got %+v", got)
	}
}

// TestCheckKafka_URPDetailAppended covers the `if k.URPDetail != ""` branch in
// checkKafka — when under-replicated partitions are found AND the detail string
// is non-empty, it must be appended to the summary message.
func TestCheckKafka_URPDetailAppended(t *testing.T) {
	t.Parallel()
	got := checkKafka(models.KafkaInfo{
		Detected:                  true,
		MetricsRead:               true,
		UnderReplicatedRead:       true,
		UnderReplicatedPartitions: 1,
		URPDetail:                 "my-topic-0",
	})
	if !hasInsightMsg(got, "WARN", "my-topic-0") {
		t.Errorf("URPDetail must be appended to the URP WARN message, got %+v", got)
	}
}

// TestCheckNetwork_TimeWaitWarn covers the `if lv := TimeWaitLevel(...); lv != ""`
// branch in checkNetwork — 2000 TIME_WAIT sockets exceeds the WARN threshold (1000)
// and must produce a WARN insight.
func TestCheckNetwork_TimeWaitWarn(t *testing.T) {
	t.Parallel()
	got := checkNetwork(models.NetworkInfo{TimeWaitCount: 2000})
	if !hasInsightMsg(got, "WARN", "TIME_WAIT") {
		t.Errorf("2000 TIME_WAIT sockets must produce a WARN, got %+v", got)
	}
}

// TestCheckPackageIntegrity_VerifyTimedOut covers the `if pi.VerifyTimedOut`
// branch — when rpm --verify timed out, a WARN must explain the situation rather
// than silently passing integrity as unverified.
func TestCheckPackageIntegrity_VerifyTimedOut(t *testing.T) {
	t.Parallel()
	got := checkPackageIntegrity(models.PackageIntegrity{VerifyTimedOut: true})
	if !hasInsightMsg(got, "WARN", "timed out") {
		t.Errorf("VerifyTimedOut must produce a WARN, got %+v", got)
	}
}

// TestCheckNVMe_UnsafeShutdownsWarn covers the `if dev.UnsafeShutdowns > 100`
// WARN branch in checkNVMe — an NVMe drive with 101 unsafe shutdowns must warn
// about potential filesystem corruption risk.
func TestCheckNVMe_UnsafeShutdownsWarn(t *testing.T) {
	t.Parallel()
	got := checkNVMe(models.NVMeInfo{
		Devices: []models.NVMeDevice{{
			Name:              "nvme0",
			SmartRead:         true,
			AvailableSparePct: 100,
			SpareThresholdPct: 10,
			UnsafeShutdowns:   101,
		}},
	})
	if !hasInsightMsg(got, "WARN", "unsafe shutdown") {
		t.Errorf("101 unsafe shutdowns must produce a WARN, got %+v", got)
	}
}

// TestCheckNVMe_SATAPendingSectorsWarn covers the `if dev.PendingSectors > 0`
// WARN branch in checkNVMe's SATA path — a SATA drive with a plausible
// SMART read and one pending sector must warn about unreadable sectors.
func TestCheckNVMe_SATAPendingSectorsWarn(t *testing.T) {
	t.Parallel()
	got := checkNVMe(models.NVMeInfo{
		SATADevices: []models.SATADevice{{
			Name:           "sda",
			Type:           "sata",
			SmartRead:      true,
			SmartOK:        true,
			TempC:          40, // within TempCeilNVMe, plausible
			PendingSectors: 1,
		}},
	})
	if !hasInsightMsg(got, "WARN", "pending sector") {
		t.Errorf("1 pending sector must produce a WARN, got %+v", got)
	}
}

// TestCheckMultipath_EmptyStatusReason covers the `if reason == ""` branch in
// checkMultipath — when Status=="error" but StatusReason is empty, the function
// must substitute a generic "multipath paths unreadable" explanation.
func TestCheckMultipath_EmptyStatusReason(t *testing.T) {
	t.Parallel()
	got := checkMultipath(models.MultipathInfo{
		Available:    true,
		Status:       "error",
		StatusReason: "",
	})
	if !hasInsightMsg(got, "WARN", "multipath paths unreadable") {
		t.Errorf("empty StatusReason must fall back to generic explanation, got %+v", got)
	}
}

// TestCheckKVMVMs_CrashedWithLastLogError covers the `if vm.LastLogError != ""`
// branch inside the KVMCrashed loop in checkKVMVMs — a crashed VM that recorded
// its last log error must prepend that error to the hint list.
func TestCheckKVMVMs_CrashedWithLastLogError(t *testing.T) {
	t.Parallel()
	got := checkKVMVMs(models.KVMInfo{
		VMs: []models.KVMVM{{
			Name:         "vm01",
			State:        models.KVMCrashed,
			LastLogError: "disk I/O error on /dev/vda",
		}},
	})
	if len(got) == 0 {
		t.Fatal("crashed VM must produce a CRIT insight, got none")
	}
	if got[0].Level != "CRIT" {
		t.Errorf("expected CRIT, got %q", got[0].Level)
	}
	found := false
	for _, h := range got[0].Hints {
		if strings.Contains(h, "disk I/O error") {
			found = true
		}
	}
	if !found {
		t.Errorf("LastLogError must appear in hints, got %v", got[0].Hints)
	}
}
