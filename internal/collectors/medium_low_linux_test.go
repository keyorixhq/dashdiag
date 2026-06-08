//go:build linux

package collectors

import (
	"testing"
)

// ── VLAN tests ──────────────────────────────────────────────────────────────

const vlanConfig = `Name-Type: VLAN_NAME_TYPE_PLUS_VID_NO_PAD
eth0.100      | 100  | eth0
eth0.200      | 200  | eth0
bond0.10      | 10   | bond0
`

func TestParseVLANConfig(t *testing.T) {
	ifaces := parseVLANConfig(vlanConfig)
	if len(ifaces) != 3 {
		t.Fatalf("got %d interfaces, want 3", len(ifaces))
	}
	if ifaces[0].Name != "eth0.100" {
		t.Errorf("ifaces[0].Name = %q, want eth0.100", ifaces[0].Name)
	}
	if ifaces[0].VLANID != 100 {
		t.Errorf("ifaces[0].VLANID = %d, want 100", ifaces[0].VLANID)
	}
	if ifaces[0].Parent != "eth0" {
		t.Errorf("ifaces[0].Parent = %q, want eth0", ifaces[0].Parent)
	}
	if ifaces[2].Parent != "bond0" {
		t.Errorf("ifaces[2].Parent = %q, want bond0", ifaces[2].Parent)
	}
}

// ── iSCSI tests ─────────────────────────────────────────────────────────────

const iscsiadmOutput = `tcp: [1] 10.0.0.1:3260,1 iqn.2019-01.com.example:storage1 (non-flash)
tcp: [2] 10.0.0.2:3260,2 iqn.2019-01.com.example:storage2 (non-flash)
tcp: [3] [fe80::1]:3260,1 iqn.2019-01.com.example:storage3 (non-flash)
`

func TestParseISCSISessions(t *testing.T) {
	sessions := parseISCSISessions(iscsiadmOutput)
	if len(sessions) != 3 {
		t.Fatalf("sessions = %d, want 3", len(sessions))
	}
	if sessions[0].Target != "iqn.2019-01.com.example:storage1" {
		t.Errorf("sessions[0].Target = %q", sessions[0].Target)
	}
	if sessions[0].State != "LOGGED_IN" {
		t.Errorf("sessions[0].State = %q, want LOGGED_IN", sessions[0].State)
	}
	if sessions[0].Portal != "10.0.0.1:3260" {
		t.Errorf("sessions[0].Portal = %q, want 10.0.0.1:3260", sessions[0].Portal)
	}
	// Non-default portal-group tag (",2") must be stripped, not left on.
	if sessions[1].Portal != "10.0.0.2:3260" {
		t.Errorf("sessions[1].Portal = %q, want 10.0.0.2:3260 (',2' tag stripped)", sessions[1].Portal)
	}
	// IPv6 portal: the tid comma is stripped but the address colons are kept.
	if sessions[2].Portal != "[fe80::1]:3260" {
		t.Errorf("sessions[2].Portal = %q, want [fe80::1]:3260", sessions[2].Portal)
	}
}

// ── NUMA tests ──────────────────────────────────────────────────────────────

func TestParseCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"0-3", []int{0, 1, 2, 3}},
		{"0,2,4", []int{0, 2, 4}},
		{"0-1,4-5", []int{0, 1, 4, 5}},
		{"0", []int{0}},
	}
	for _, c := range cases {
		got := parseCPUList(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseCPUList(%q)[%d] = %d, want %d", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// ── InfiniBand tests ─────────────────────────────────────────────────────────

func TestParseIBState(t *testing.T) {
	cases := []struct{ in, want string }{
		{"4: ACTIVE", "ACTIVE"},
		{"1: DOWN", "DOWN"},
		{"ACTIVE", "ACTIVE"},
		{"  POLLING  ", "POLLING"},
	}
	for _, c := range cases {
		got := parseIBState(c.in)
		if got != c.want {
			t.Errorf("parseIBState(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── nspawn tests ─────────────────────────────────────────────────────────────

const machinectlOutput = `web-frontend container nspawn running
db-backend   container nspawn running
test-env     container nspawn exited
`

func TestParseMachinectlList(t *testing.T) {
	containers := parseMachinectlList(machinectlOutput)
	if len(containers) != 3 {
		t.Fatalf("containers = %d, want 3", len(containers))
	}
	if containers[0].Name != "web-frontend" {
		t.Errorf("containers[0].Name = %q", containers[0].Name)
	}
	if containers[2].State != "exited" {
		t.Errorf("containers[2].State = %q, want exited", containers[2].State)
	}
}

// ── Auth tests ───────────────────────────────────────────────────────────────

func TestParseAuthLogLine(t *testing.T) {
	cases := []struct {
		line     string
		wantIP   string
		wantRoot bool
	}{
		{
			"May 17 09:00:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
			"1.2.3.4", true,
		},
		{
			"May 17 09:00:02 host sshd[1235]: Failed password for ubuntu from 5.6.7.8 port 54321 ssh2",
			"5.6.7.8", false,
		},
		{
			"May 17 09:00:03 host sshd[1236]: Invalid user admin from 9.10.11.12 port 11111",
			"9.10.11.12", false,
		},
	}
	for _, c := range cases {
		ip, isRoot := parseAuthLogLine(c.line)
		if ip != c.wantIP {
			t.Errorf("parseAuthLogLine IP = %q, want %q (line: %q)", ip, c.wantIP, c.line)
		}
		if isRoot != c.wantRoot {
			t.Errorf("parseAuthLogLine isRoot = %v, want %v (line: %q)", isRoot, c.wantRoot, c.line)
		}
	}
}

// ── auditd tests ─────────────────────────────────────────────────────────────

const auditctlRules = `-a always,exit -F arch=b64 -S open -k file_access
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
`

func TestParseAuditctlRules(t *testing.T) {
	n := parseAuditctlRules(auditctlRules)
	if n != 3 {
		t.Errorf("rule count = %d, want 3", n)
	}
}

const auditEvents = `type=SYSCALL msg=audit(1234:1): ...
type=PATH msg=audit(1234:1): ...
type=SYSCALL msg=audit(1235:2): ...
`

func TestParseAuditEventCount(t *testing.T) {
	n := parseAuditEventCount(auditEvents)
	if n != 3 {
		t.Errorf("event count = %d, want 3", n)
	}
}
