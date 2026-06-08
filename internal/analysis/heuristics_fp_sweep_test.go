package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// hasLevelCat reports whether any insight has the given level (helper local to
// this file to avoid colliding with other test helpers).
func fpHasLevel(ins []models.Insight, level string) bool {
	for _, i := range ins {
		if i.Level == level {
			return true
		}
	}
	return false
}

// A spinning HDD sitting at 100% %util during a sequential workload (backup,
// large copy) is normal — util is not a saturation signal for HDDs (AWAIT is).
// SSD/NVMe at 100% util is still flagged.
func TestIOUtilHDDNotFalsePositive(t *testing.T) {
	hdd := models.IOInfo{Devices: []models.IODeviceInfo{
		{Name: "sda", DriveType: "hdd", UtilPct: 100, AwaitMs: 8}, // busy but low latency = healthy HDD
	}}
	if got := checkIO(hdd, defaultThresh); fpHasLevel(got, "WARN") || fpHasLevel(got, "CRIT") {
		t.Errorf("HDD at 100%% util with low await must not alarm on util, got %+v", got)
	}

	// HDD with high latency still alarms via the await path — saturation is real.
	hddSlow := models.IOInfo{Devices: []models.IODeviceInfo{
		{Name: "sda", DriveType: "hdd", UtilPct: 100, AwaitMs: 250},
	}}
	if got := checkIO(hddSlow, defaultThresh); !fpHasLevel(got, "CRIT") && !fpHasLevel(got, "WARN") {
		t.Errorf("HDD with 250ms await must still alarm (await path), got %+v", got)
	}

	// SSD at 100% util is genuinely abnormal — must still fire.
	ssd := models.IOInfo{Devices: []models.IODeviceInfo{
		{Name: "nvme0n1", DriveType: "nvme", UtilPct: 100, AwaitMs: 1},
	}}
	if got := checkIO(ssd, defaultThresh); !fpHasLevel(got, "CRIT") {
		t.Errorf("NVMe at 100%% util should CRIT, got %+v", got)
	}
}

// An internal-only / air-gapped host resolves its internal names but not
// external ones — that's intentional, not a broken resolver. WARN, not CRIT.
func TestDNSInternalOnlyNotCrit(t *testing.T) {
	internalOnly := models.DNSResolverInfo{
		Manager: "systemd-resolved", ExternalResolvesOK: false, InternalResolvesOK: true,
	}
	got := checkDNS(internalOnly)
	if fpHasLevel(got, "CRIT") {
		t.Errorf("internal-only DNS must not CRIT, got %+v", got)
	}
	if !fpHasLevel(got, "WARN") {
		t.Errorf("internal-only DNS should WARN, got %+v", got)
	}

	// Genuinely broken resolver (neither internal nor external) is still CRIT.
	broken := models.DNSResolverInfo{
		Manager: "systemd-resolved", ExternalResolvesOK: false, InternalResolvesOK: false,
	}
	if got := checkDNS(broken); !fpHasLevel(got, "CRIT") {
		t.Errorf("fully broken DNS should still CRIT, got %+v", got)
	}
}

// rpcbind is an NFSv3 concern; an NFSv4-only host legitimately runs without it.
func TestNFSRpcbindV4OnlyNotFlagged(t *testing.T) {
	v4only := models.NFSInfo{
		RpcbindActive: false,
		Mounts:        []models.NFSMount{{Mount: "/data", FSType: "nfs4"}},
	}
	if got := checkNFS(v4only); fpHasLevel(got, "WARN") {
		t.Errorf("NFSv4-only host without rpcbind must not WARN, got %+v", got)
	}

	// A v3 ("nfs") mount without rpcbind still warns.
	v3 := models.NFSInfo{
		RpcbindActive: false,
		Mounts:        []models.NFSMount{{Mount: "/data", FSType: "nfs"}},
	}
	if got := checkNFS(v3); !fpHasLevel(got, "WARN") {
		t.Errorf("NFSv3 mount without rpcbind should WARN, got %+v", got)
	}
}

// Once docker0 is in firewalld's trusted zone the nftables-backend problem is
// fixed — don't flag a host that already applied the remediation.
func TestDockerFirewalldZoneTrustedSuppressesWarn(t *testing.T) {
	fixed := models.DockerInfo{
		FirewalldActive: true, FirewalldBackend: "nftables", DockerZoneTrusted: true,
	}
	for _, ins := range checkDockerResources(fixed) {
		if strings.Contains(ins.Message, "nftables backend") {
			t.Errorf("docker0 in trusted zone must suppress the nftables WARN, got %q", ins.Message)
		}
	}

	// Still warns when docker0 is NOT trusted.
	unfixed := models.DockerInfo{
		FirewalldActive: true, FirewalldBackend: "nftables", DockerZoneTrusted: false,
	}
	found := false
	for _, ins := range checkDockerResources(unfixed) {
		if strings.Contains(ins.Message, "nftables backend") {
			found = true
		}
	}
	if !found {
		t.Error("untrusted docker0 with nftables backend should still WARN")
	}
}

// On Proxmox VE root SSH is required for cluster management — surface it as
// INFO, not a false CRIT on the operator's own management session.
func TestSessionsRootSSHPVEExemption(t *testing.T) {
	pve := models.SessionsInfo{TotalCount: 1, RootSSH: true, IsPVE: true}
	got := checkSessions(pve)
	if fpHasLevel(got, "CRIT") {
		t.Errorf("root SSH on PVE must not CRIT, got %+v", got)
	}
	if !fpHasLevel(got, "INFO") {
		t.Errorf("root SSH on PVE should be INFO, got %+v", got)
	}

	// Non-PVE host: root SSH is still CRIT.
	nonPVE := models.SessionsInfo{TotalCount: 1, RootSSH: true, IsPVE: false}
	if got := checkSessions(nonPVE); !fpHasLevel(got, "CRIT") {
		t.Errorf("root SSH on a non-PVE host should CRIT, got %+v", got)
	}
}
