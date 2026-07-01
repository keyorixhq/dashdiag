package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-4 characterization tests: clock/NTP, TLS cert expiry, KVM VM health,
// health-deep, NIC bonding, FC HBA links, auth brute-force, battery, sessions,
// SSH MAC/KEX algorithms, and SELinux denials. Pure functions; thresholds off
// defaultThresh. Reuses assertLevel.

func TestCheckClock(t *testing.T) {
	tests := []struct {
		name  string
		clock models.ClockInfo
		want  string
	}{
		{"synced and accurate is clean", models.ClockInfo{Synced: true, OffsetMs: 0}, ""},
		{"unsynced is CRIT", models.ClockInfo{Synced: false}, "CRIT"},
		{"unsynced but RTC-local is WARN", models.ClockInfo{Synced: false, RTCInLocalTZ: true}, "WARN"},
		{"large offset is CRIT", models.ClockInfo{Synced: true, OffsetMs: 600}, "CRIT"},
		{"moderate offset is WARN", models.ClockInfo{Synced: true, OffsetMs: 200}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkClock(tt.clock, defaultThresh), tt.want)
		})
	}
}

func TestCheckTLS(t *testing.T) {
	cert := func(days int) models.TLSInfo {
		return models.TLSInfo{Certs: []models.CertInfo{{Path: "/c.pem", Subject: "cn=x", ExpiresIn: days}}}
	}
	assertLevel(t, checkTLS(models.TLSInfo{}), "") // no certs
	assertLevel(t, checkTLS(cert(-5)), "CRIT")     // expired
	assertLevel(t, checkTLS(cert(3)), "CRIT")      // expiring <=7d
	assertLevel(t, checkTLS(cert(20)), "WARN")     // expiring <=30d
	assertLevel(t, checkTLS(cert(90)), "")         // healthy
	// An unreadable cert must WARN, not read as healthy — even when it's the ONLY
	// thing found (no checkable certs).
	assertLevel(t, checkTLS(models.TLSInfo{Uncheckable: []models.TLSUncheckable{{Path: "/x.pem", Error: "permission denied"}}}), "WARN")
	// A not-yet-valid cert (NotBefore in the future) breaks handshakes now even
	// though its expiry is far off → CRIT, not a silent healthy.
	assertLevel(t, checkTLS(models.TLSInfo{Certs: []models.CertInfo{{Path: "/c.pem", Subject: "cn=x", ExpiresIn: 200, NotYetValid: true}}}), "CRIT")
}

func TestCheckKVM(t *testing.T) {
	tests := []struct {
		name string
		kvm  models.KVMInfo
		want string
	}{
		{"not detected is silent", models.KVMInfo{Detected: false}, ""},
		{"healthy is clean", models.KVMInfo{Detected: true}, ""},
		// libvirt up but `virsh list` failed → WARN, not a silent "no VMs / healthy".
		{"enumeration failed is WARN", models.KVMInfo{Detected: true, Status: "enum-failed", StatusReason: "libvirt is up but `virsh list` failed"}, "WARN"},
		{"crashed VM is CRIT", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMCrashed}}}, "CRIT"},
		{"paused VMs is WARN", models.KVMInfo{Detected: true, VMsPaused: 1}, "WARN"},
		{"disk IO errors is CRIT", models.KVMInfo{Detected: true, DiskIOErrors: 1}, "CRIT"},
		{
			name: "shut-off autostart is WARN",
			kvm:  models.KVMInfo{Detected: true, VMsDownAutostart: 1, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMShutOff, AutoStart: true}}},
			want: "WARN",
		},
		{
			name: "pmsuspended VM is WARN (was silent false-OK)",
			kvm:  models.KVMInfo{Detected: true, VMsAbnormal: 1, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMPMSuspended}}},
			want: "WARN",
		},
		{
			name: "in-shutdown VM is WARN",
			kvm:  models.KVMInfo{Detected: true, VMsAbnormal: 1, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMInShutdown}}},
			want: "WARN",
		},
		{
			name: "unreadable VM state is WARN (dominfo failed, not healthy)",
			kvm:  models.KVMInfo{Detected: true, VMsUnreadable: 1, VMs: []models.KVMVM{{Name: "vm1", State: ""}}},
			want: "WARN",
		},
		{
			name: "missing backing disk file (deep) is CRIT",
			kvm:  models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMShutOff, MissingDiskPath: "/var/lib/libvirt/images/vm1.qcow2"}}},
			want: "CRIT",
		},
		{
			name: "emulated NIC (deep) is WARN",
			kvm:  models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMRunning, EmulatedNICs: []string{"52:54:00:11:22:33 (e1000)"}}}},
			want: "WARN",
		},
		{
			name: "emulated disk bus (deep) is WARN",
			kvm:  models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMRunning, EmulatedDisks: []string{"sdb (sata)"}}}},
			want: "WARN",
		},
		{
			name: "all-VirtIO VM (deep, no findings) is clean",
			kvm:  models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMRunning}}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkKVM(tt.kvm), tt.want)
		})
	}
}

func TestCheckHealthDeep(t *testing.T) {
	assertLevel(t, checkHealthDeep(models.HealthDeepInfo{}), "")                 // clean
	assertLevel(t, checkHealthDeep(models.HealthDeepInfo{DirtyMB: 600}), "WARN") // dirty page backlog
}

func TestCheckBonding(t *testing.T) {
	slave := func(name, state string) models.BondSlave { return models.BondSlave{Name: name, State: state} }
	tests := []struct {
		name string
		b    models.BondingInfo
		want string
	}{
		{"no bonds is clean", models.BondingInfo{}, ""},
		{
			name: "single slave is WARN (no redundancy)",
			b:    models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", Slaves: []models.BondSlave{slave("eth0", "up")}}}},
			want: "WARN",
		},
		{
			name: "healthy two-slave is clean",
			b:    models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", Slaves: []models.BondSlave{slave("eth0", "up"), slave("eth1", "up")}}}},
			want: "",
		},
		{
			name: "one slave down is WARN",
			b:    models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", DownSlaves: 1, Slaves: []models.BondSlave{slave("eth0", "up"), slave("eth1", "down")}}}},
			want: "WARN",
		},
		{
			name: "all slaves down is CRIT",
			b:    models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", DownSlaves: 2, Slaves: []models.BondSlave{slave("eth0", "down"), slave("eth1", "down")}}}},
			want: "CRIT",
		},
		{
			// The false-OK: every slave MII-up (DownSlaves 0) but LACP not aggregating.
			name: "802.3ad MII-up but not aggregating is WARN",
			b: models.BondingInfo{Bonds: []models.BondInterface{{
				Name: "bond0", ModeShort: "802.3ad", NotAggregating: true,
				Slaves: []models.BondSlave{slave("eth0", "up"), slave("eth1", "up")},
			}}},
			want: "WARN",
		},
		{
			name: "802.3ad aggregating is clean",
			b: models.BondingInfo{Bonds: []models.BondInterface{{
				Name: "bond0", ModeShort: "802.3ad", NotAggregating: false,
				Slaves: []models.BondSlave{slave("eth0", "up"), slave("eth1", "up")},
			}}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBonding(tt.b), tt.want)
		})
	}
}

func TestCheckHBA(t *testing.T) {
	assertLevel(t, checkHBA(models.HBAInfo{}), "") // no ports
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online"}}}), "")
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Offline"}}}), "CRIT")
	// A few historical link failures (cable reseat / switch reboot at install) on a
	// cumulative since-boot counter must NOT warn — only a genuinely flapping link does.
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online", LinkFailures: 5}}}), "")
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online", LinkFailures: 11}}}), "WARN")
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online", LossOfSync: 150}}}), "WARN")
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: ""}}}), "WARN") // unreadable state must not read healthy
}

func TestCheckAuth(t *testing.T) {
	// Available=false → sshd not installed, row hidden.
	assertLevel(t, checkAuth(models.AuthInfo{}), "")
	// Read succeeded (Checked) with no failures → quiet.
	assertLevel(t, checkAuth(models.AuthInfo{Available: true, Checked: true, FailedLast24h: 0}), "")
	assertLevel(t, checkAuth(models.AuthInfo{Available: true, Checked: true, FailedLast24h: 1500}), "WARN")                // brute force
	assertLevel(t, checkAuth(models.AuthInfo{Available: true, Checked: true, FailedLast24h: 150}), "INFO")                 // notable
	assertLevel(t, checkAuth(models.AuthInfo{Available: true, Checked: true, FailedLast24h: 50, RootAttempts: 1}), "WARN") // root attempts
	// Auth source unreadable (e.g. non-root, no journal/auth.log access): must
	// surface as INFO, not pass silently as a clean "0 failures" (false-OK).
	assertLevel(t, checkAuth(models.AuthInfo{Available: true, Checked: false}), "INFO")
}

// TestCheckAuthConfigAware verifies the brute-force verdict is downgraded from
// WARN to INFO when sshd is authoritatively known (sshd -T) to reject the
// attempts: failed *password* attempts cannot succeed on a key-only host, so
// they are noise, not a credible threat. Found on the VMware tenant: dsd WARNed
// purely on the attempt count without checking PasswordAuthentication.
func TestCheckAuthConfigAware(t *testing.T) {
	maxLevel := func(ins []models.Insight) string {
		out := ""
		for _, i := range ins {
			if i.Level == "WARN" {
				return "WARN" // highest we produce here
			}
			if i.Level == "INFO" {
				out = "INFO"
			}
		}
		return out
	}

	base := models.AuthInfo{Available: true, Checked: true, FailedLast24h: 1500, RootAttempts: 20}

	// Unknown policy (config not read) → fail toward warning: keep WARN.
	if got := maxLevel(checkAuth(base)); got != "WARN" {
		t.Errorf("unknown policy: want WARN, got %q", got)
	}

	// Key-only (password auth off, authoritatively): both the brute-force flood
	// and the root attempts are futile → no WARN, INFO only.
	keyOnly := base
	keyOnly.SSHConfigChecked = true
	keyOnly.PasswordAuthEnabled = false
	if got := maxLevel(checkAuth(keyOnly)); got != "INFO" {
		t.Errorf("key-only host: want INFO (downgraded), got %q: %+v", got, checkAuth(keyOnly))
	}

	// Password auth ON + root login allowed (the VMware tenant minus the
	// without-password nuance) → genuine exposure, keep WARN.
	pwOpen := base
	pwOpen.SSHConfigChecked = true
	pwOpen.PasswordAuthEnabled = true
	pwOpen.RootPasswordLoginAllowed = true
	if got := maxLevel(checkAuth(pwOpen)); got != "WARN" {
		t.Errorf("password-open host: want WARN, got %q", got)
	}

	// Password auth ON for users but PermitRootLogin without-password (the actual
	// tenant): user brute-force WARN stays, but the root attempts are futile and
	// must be an INFO, not a WARN with stale "set PermitRootLogin no" advice.
	tenant := base
	tenant.SSHConfigChecked = true
	tenant.PasswordAuthEnabled = true
	tenant.RootPasswordLoginAllowed = false
	ins := checkAuth(tenant)
	var sawUserWARN, sawRootINFO, sawRootWARN bool
	for _, i := range ins {
		switch {
		case i.Level == "WARN" && strings.Contains(i.Message, "brute force"):
			sawUserWARN = true
		case i.Level == "INFO" && strings.Contains(i.Message, "root"):
			sawRootINFO = true
		case i.Level == "WARN" && strings.Contains(i.Message, "root"):
			sawRootWARN = true
		}
	}
	if !sawUserWARN {
		t.Errorf("tenant: expected brute-force WARN to remain, got: %+v", ins)
	}
	if !sawRootINFO || sawRootWARN {
		t.Errorf("tenant: root attempts should be INFO (futile, without-password), not WARN, got: %+v", ins)
	}
}

func TestCheckBattery(t *testing.T) {
	tests := []struct {
		name string
		b    models.BatteryInfo
		want string
	}{
		{"no battery is silent", models.BatteryInfo{Present: false}, ""},
		{"healthy charged is clean", models.BatteryInfo{Present: true, HealthPct: 90, Status: "Full"}, ""},
		{"worn battery is CRIT", models.BatteryInfo{Present: true, HealthPct: 50}, "CRIT"},
		{"degraded battery is WARN", models.BatteryInfo{Present: true, HealthPct: 70}, "WARN"},
		{"critically low charge is CRIT", models.BatteryInfo{Present: true, HealthPct: 90, Status: "Discharging", CapacityPct: 5}, "CRIT"},
		{"low charge is WARN", models.BatteryInfo{Present: true, HealthPct: 90, Status: "Discharging", CapacityPct: 15}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBattery(tt.b), tt.want)
		})
	}
}

func TestCheckSessions(t *testing.T) {
	tests := []struct {
		name string
		s    models.SessionsInfo
		want string
	}{
		{"no sessions is silent", models.SessionsInfo{TotalCount: 0}, ""},
		{"normal session is clean", models.SessionsInfo{TotalCount: 1}, ""},
		{"root via SSH is CRIT", models.SessionsInfo{TotalCount: 1, RootSSH: true}, "CRIT"},
		{"long-idle session is WARN", models.SessionsInfo{TotalCount: 1, LongIdle: []string{"bob"}}, "WARN"},
		{"many concurrent is WARN", models.SessionsInfo{TotalCount: 6}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSessions(tt.s), tt.want)
		})
	}
}

func TestCheckSSHWeakMACs(t *testing.T) {
	assertLevel(t, checkSSHWeakMACs(models.SecurityInfo{}), "")                                       // not configured
	assertLevel(t, checkSSHWeakMACs(models.SecurityInfo{SSHMACs: "hmac-sha2-512,hmac-sha2-256"}), "") // strong
	assertLevel(t, checkSSHWeakMACs(models.SecurityInfo{SSHMACs: "hmac-md5,hmac-sha2-256"}), "WARN")  // weak
}

func TestCheckSSHWeakKEX(t *testing.T) {
	assertLevel(t, checkSSHWeakKEX(models.SecurityInfo{}), "")                                                   // not configured
	assertLevel(t, checkSSHWeakKEX(models.SecurityInfo{SSHKexAlgorithms: "curve25519-sha256"}), "")              // strong
	assertLevel(t, checkSSHWeakKEX(models.SecurityInfo{SSHKexAlgorithms: "diffie-hellman-group1-sha1"}), "WARN") // Logjam-vulnerable
}

func TestCheckSELinuxDenials(t *testing.T) {
	tests := []struct {
		name string
		mac  models.KernelSecurityInfo
		want string
	}{
		{"unmeasured (-1) is silent", models.KernelSecurityInfo{SELinuxDenials: -1}, ""},
		{"zero denials is clean", models.KernelSecurityInfo{SELinuxDenials: 0}, ""},
		{"some denials is WARN", models.KernelSecurityInfo{SELinuxDenials: 1, SELinuxMode: "enforcing"}, "WARN"},
		{"many denials is CRIT", models.KernelSecurityInfo{SELinuxDenials: 10, SELinuxMode: "enforcing"}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSELinuxDenials(tt.mac, defaultThresh), tt.want)
		})
	}
}
