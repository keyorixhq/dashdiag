package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// neverSilentCheck is one row of neverSilentChecks — see that var's doc comment.
type neverSilentCheck struct {
	name       string
	checkFn    string // the check<X> function name this row exercises — must match a real function; cross-checked by TestAllChecksRegistered
	run        func() []models.Insight
	wantSubstr string // must appear in at least one emitted insight's message
}

// neverSilentChecks is the regression guard for the false-clean bug class: a
// check function that could not measure/verify something must say so (an INFO
// insight) rather than returning an empty slice indistinguishable from
// "checked and found nothing wrong". Each entry's input reproduces a real
// "could not measure" state; TestChecksNeverSilentlySkip asserts that at
// least one insight is emitted and that its message names what could not be
// verified.
//
// Table-driven and explicit on purpose: a new check with a silent "give up"
// path does not fail TestChecksNeverSilentlySkip by construction — it has to
// be added here, which is itself the point (adding a check without adding a
// row is visible in review, not silently uncovered). TestAllChecksRegistered
// (checks_registry_governance_test.go) is the backstop for the "has to be
// added" half of that claim — it fails on any check function capable of this
// bug class that isn't a checkFn here or in checkExemptions.
//
// A package-level var (not inline in the test func) so TestAllChecksRegistered
// can read the covered function names without re-parsing the test body.
var neverSilentChecks = []neverSilentCheck{
	{
		name:    "checkMemory: cgroup memory unmeasurable in a limited container",
		checkFn: "checkMemory",
		run: func() []models.Insight {
			ctr := platform.ContainerContext{InContainer: true, MemLimitMB: 2048}
			mem := models.MemoryInfo{UsedPct: 95, TotalGB: 2, FreeGB: 0.1, CgroupMemMeasured: false}
			return checkMemory(mem, defaultThresh, ctr)
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkAppArmorDenials: journalctl scan itself failed",
		checkFn: "checkAppArmorDenials",
		run: func() []models.Insight {
			return checkAppArmorDenials(models.SecurityInfo{AppArmorDenialsUnreadable: true})
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkPackageDBHealth: DB/lock probe itself failed to run",
		checkFn: "checkPackageDBHealth",
		run: func() []models.Insight {
			return checkPackageDBHealth(models.PackagesInfo{PackageManager: "apt", DBHealthChecked: false})
		},
		wantSubstr: "could not be checked",
	},
	{
		name:    "checkLaunchd: launchctl list failed",
		checkFn: "checkLaunchd",
		run: func() []models.Insight {
			return checkLaunchd(models.LaunchdInfo{})
		},
		wantSubstr: "could not be checked",
	},
	{
		name:    "checkNVMe: drive enumeration failed (macOS diskutil list)",
		checkFn: "checkNVMe",
		run: func() []models.Insight {
			return checkNVMe(models.NVMeInfo{DrivesListUnreadable: true})
		},
		wantSubstr: "could not enumerate drives",
	},
	{
		name:    "checkDiskExtras: physical drive enumeration failed (macOS diskutil list)",
		checkFn: "checkDiskExtras",
		run: func() []models.Insight {
			return checkDiskExtras(models.DiskInfo{DrivesListUnreadable: true})
		},
		wantSubstr: "could not enumerate physical drives",
	},
	{
		name:    "checkNetwork: /proc/net/sockstat read failed",
		checkFn: "checkNetwork",
		run: func() []models.Insight {
			return checkNetwork(models.NetworkInfo{SockstatUnreadable: true})
		},
		wantSubstr: "could not read /proc/net/sockstat",
	},
	{
		name:    "checkNetwork: /proc/net/netstat read failed",
		checkFn: "checkNetwork",
		run: func() []models.Insight {
			return checkNetwork(models.NetworkInfo{NetstatUnreadable: true})
		},
		wantSubstr: "could not read /proc/net/netstat",
	},
	{
		name:    "checkAlertmanager: identity unverified",
		checkFn: "checkAlertmanager",
		run: func() []models.Insight {
			return checkAlertmanager(models.AlertmanagerInfo{Detected: true, StatusRead: true, ConfigReloadRead: true, ConfigReloadOK: true, IdentityUnverified: true})
		},
		wantSubstr: "identity could not be confirmed",
	},
	{
		name:    "checkEnvoy: identity unverified",
		checkFn: "checkEnvoy",
		run: func() []models.Insight {
			return checkEnvoy(models.EnvoyInfo{Detected: true, StatsRead: true, ClustersTotal: 1, UpstreamsTotal: 1, UpstreamsHealthy: 1, IdentityUnverified: true})
		},
		wantSubstr: "identity could not be confirmed",
	},
	{
		name:    "checkGrafana: identity unverified",
		checkFn: "checkGrafana",
		run: func() []models.Insight {
			return checkGrafana(models.GrafanaInfo{Detected: true, HealthRead: true, DatabaseOK: true, IdentityUnverified: true})
		},
		wantSubstr: "identity could not be confirmed",
	},
	{
		name:    "checkVault: identity unverified",
		checkFn: "checkVault",
		run: func() []models.Insight {
			return checkVault(models.VaultInfo{Available: true, Reachable: true, StatusRead: true, Initialized: true, TLSEnabled: true, IdentityUnverified: true})
		},
		wantSubstr: "identity could not be confirmed",
	},
	{
		name:    "checkOCI: on OCI but every sub-check unreachable",
		checkFn: "checkOCI",
		run: func() []models.Insight {
			return checkOCI(models.OCIInfo{IsOCI: true})
		},
		wantSubstr: "could not be verified",
	},
	{
		name:    "checkSessions: `w` unavailable",
		checkFn: "checkSessions",
		run: func() []models.Insight {
			return checkSessions(models.SessionsInfo{Checked: false})
		},
		wantSubstr: "could not be enumerated",
	},
	{
		name:    "checkContainerGuest: cgroup v1 throttle/OOM signals unread",
		checkFn: "checkContainerGuest",
		run: func() []models.Insight {
			v := models.ContainerGuestInfo{
				InContainer:      true,
				MemLimitBytes:    1 << 30,
				CPUQuotaCores:    1,
				CgroupV2:         false,
				CgroupV1Measured: false,
			}
			return checkContainerGuest(v)
		},
		wantSubstr: "could not be read on this cgroup v1 host",
	},
	{
		name:    "checkPostBoot: prior boot state unmeasurable",
		checkFn: "checkPostBoot",
		run: func() []models.Insight {
			return checkPostBoot(models.PostBootInfo{Available: true, State: "unmeasurable"})
		},
		wantSubstr: "forensics unavailable",
	},
	{
		name:    "checkOOM: kernel log scan truncated by a scanner error",
		checkFn: "checkOOM",
		run: func() []models.Insight {
			return checkOOM(models.OOMInfo{EventsCountUnverified: true})
		},
		wantSubstr: "may be incomplete",
	},
	{
		name:    "checkElasticsearch: reachable but cluster health unread",
		checkFn: "checkElasticsearch",
		run: func() []models.Insight {
			return checkElasticsearch(models.ElasticsearchInfo{Detected: true, HealthRead: false})
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkFirewall: query failed, reason given",
		checkFn: "checkFirewall",
		run: func() []models.Insight {
			return checkFirewall(models.FirewallInfo{Available: false, StatusReason: "nft query failed: permission denied"})
		},
		wantSubstr: "not verified",
	},
	{
		name:    "checkAuth: sshd present but auth log unreadable",
		checkFn: "checkAuth",
		run: func() []models.Insight {
			return checkAuth(models.AuthInfo{Available: true, Checked: false})
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkRHELSubscription: subscription-manager output unparseable",
		checkFn: "checkRHELSubscription",
		run: func() []models.Insight {
			return checkRHELSubscription(models.SUSEConnectInfo{StatusUnverified: true})
		},
		wantSubstr: "could not be determined",
	},
	{
		name:    "checkCloudMeta: on a cloud (IsCloudInstance gated) but metadata unreachable",
		checkFn: "checkCloudMeta",
		run: func() []models.Insight {
			return checkCloudMeta(models.CloudInfo{Available: false})
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkServiceRestart: stale libraries found by a partial non-root scan",
		checkFn: "checkServiceRestart",
		run: func() []models.Insight {
			return checkServiceRestart(models.ServiceRestartInfo{
				Available: true, StaleCount: 2, StaleNames: []string{"sshd", "dbus-broker"}, NeedsRoot: true,
			})
		},
		wantSubstr: "non-root and partial",
	},
	{
		name:    "checkAWS: on EC2 (IsEC2 gated) but IMDS posture unreachable",
		checkFn: "checkAWS",
		run: func() []models.Insight {
			return checkAWS(models.AWSInfo{IsEC2: true, IMDSChecked: false})
		},
		wantSubstr: "could not verify IMDS posture",
	},
	{
		name:    "checkAzure: on Azure (IsAzure gated) but storage profile unreachable",
		checkFn: "checkAzure",
		run: func() []models.Insight {
			return checkAzure(models.AzureInfo{IsAzure: true, DisksChecked: false})
		},
		wantSubstr: "could not verify",
	},
	{
		name:    "checkGCP: on GCP (IsGCP gated) but maintenance policy unreachable",
		checkFn: "checkGCP",
		run: func() []models.Insight {
			return checkGCP(models.GCPInfo{IsGCP: true, MaintenanceChecked: false})
		},
		wantSubstr: "could not verify",
	},
	{
		name:    "checkDRBD: partial /proc/drbd read after a resource was already parsed",
		checkFn: "checkDRBD",
		run: func() []models.Insight {
			return checkDRBD(models.DRBDInfo{
				Version:    "8.4.10",
				Unverified: true,
				Resources:  []models.DRBDResource{{Minor: 0, ConnState: "SplitBrain"}},
			})
		},
		wantSubstr: "incomplete",
	},
	{
		name:    "checkK8sOSLayerCoverageGaps: root run with KUBE-FORWARD/CNI tools missing",
		checkFn: "checkK8sOSLayerCoverageGaps",
		run: func() []models.Insight {
			return checkK8sOSLayerCoverageGaps(models.K8sOSLayer{KubeForwardChecked: false, CNIChecked: false})
		},
		wantSubstr: "checks limited",
	},
	{
		name:    "checkK8s: API unreachable but OS-layer facts (kubelet down) still surface",
		checkFn: "checkK8s",
		run: func() []models.Insight {
			return checkK8s(models.K8sInfo{
				Detected: true, APIReachable: false,
				OSLayer: &models.K8sOSLayer{KubeletChecked: true, KubeletActive: false},
			})
		},
		wantSubstr: "kubelet is not running",
	},
	{
		name:    "checkTransactional: btrfs read failed (commonly non-root)",
		checkFn: "checkTransactional",
		run: func() []models.Insight {
			return checkTransactional(models.TransactionalInfo{Available: true, Unverified: true})
		},
		wantSubstr: "could not verify",
	},
	{
		name:    "checkInfiniBand: /sys/class/infiniband unreadable (restricted /sys view)",
		checkFn: "checkInfiniBand",
		run: func() []models.Insight {
			return checkInfiniBand(models.InfiniBandInfo{ReadFailed: true})
		},
		wantSubstr: "could not be read",
	},
	{
		name:    "checkRAID: /proc/mdstat unreadable (non-ENOENT open failure)",
		checkFn: "checkRAID",
		run: func() []models.Insight {
			return checkRAID(models.RAIDInfo{ReadFailed: true})
		},
		wantSubstr: "could not be verified",
	},
	{
		name:    "checkKVMGuest: NIC/disk driver enumeration failed (unreadable /sys/class/net or /sys/block)",
		checkFn: "checkKVMGuest",
		run: func() []models.Insight {
			return checkKVMGuest(models.KVMGuestInfo{
				IsGuest: true, QGAChannelPresent: true, QGAInstalled: true, QGARunning: true,
				NICDriversChecked: false, DiskBusesChecked: false,
			})
		},
		wantSubstr: "could not verify",
	},
}

func TestChecksNeverSilentlySkip(t *testing.T) {
	for _, tt := range neverSilentChecks {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.run()
			if len(got) == 0 {
				t.Fatalf("silently returned zero insights for an unmeasurable state — this is the false-clean bug")
			}
			found := false
			for _, ins := range got {
				if strings.Contains(ins.Message, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no insight message contains %q, got %+v", tt.wantSubstr, got)
			}
		})
	}
}
