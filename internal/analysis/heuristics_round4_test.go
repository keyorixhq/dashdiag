package analysis

import (
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
}

func TestCheckKVM(t *testing.T) {
	tests := []struct {
		name string
		kvm  models.KVMInfo
		want string
	}{
		{"not detected is silent", models.KVMInfo{Detected: false}, ""},
		{"healthy is clean", models.KVMInfo{Detected: true}, ""},
		{"crashed VM is CRIT", models.KVMInfo{Detected: true, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMCrashed}}}, "CRIT"},
		{"paused VMs is WARN", models.KVMInfo{Detected: true, VMsPaused: 1}, "WARN"},
		{"disk IO errors is CRIT", models.KVMInfo{Detected: true, DiskIOErrors: 1}, "CRIT"},
		{
			name: "shut-off autostart is WARN",
			kvm:  models.KVMInfo{Detected: true, VMsDownAutostart: 1, VMs: []models.KVMVM{{Name: "vm1", State: models.KVMShutOff, AutoStart: true}}},
			want: "WARN",
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
	assertLevel(t, checkHBA(models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online", LinkFailures: 5}}}), "WARN")
}

func TestCheckAuth(t *testing.T) {
	assertLevel(t, checkAuth(models.AuthInfo{FailedLast24h: 0}), "")                       // hidden
	assertLevel(t, checkAuth(models.AuthInfo{FailedLast24h: 1500}), "WARN")                // brute force
	assertLevel(t, checkAuth(models.AuthInfo{FailedLast24h: 150}), "INFO")                 // notable
	assertLevel(t, checkAuth(models.AuthInfo{FailedLast24h: 50, RootAttempts: 1}), "WARN") // root attempts
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
