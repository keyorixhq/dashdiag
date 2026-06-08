//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestSudoGrantsAllCommands(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"ALL ALL=(ALL:ALL) NOPASSWD: ALL", true},                 // full passwordless root
		{"%wheel ALL=(ALL) NOPASSWD:ALL", true},                   // no space after colon
		{"ALL ALL=(ALL) NOPASSWD: ALL, /bin/systemctl", true},     // ALL first in list
		{"ALL ALL=(root) NOPASSWD: /usr/sbin/mintdrivers", false}, // specific command (Mint)
		{"deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app", false},
		{"# ALL ALL=(ALL) NOPASSWD: ALL", true}, // sudoGrantsAllCommands itself doesn't skip comments (caller does)
		{"no nopasswd here", false},
	}
	for _, c := range cases {
		if got := sudoGrantsAllCommands(c.line); got != c.want {
			t.Errorf("sudoGrantsAllCommands(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// A system-wide "NOPASSWD: ALL" (full passwordless root) must be flagged, while
// a Mint-style "ALL ... NOPASSWD: <specific command>" stays correctly skipped.
func TestParseSudoersFileFullEscalationFlagged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sudoers")
	content := "# comment line\n" +
		"ALL ALL=(root) NOPASSWD: /usr/sbin/mintdrivers\n" + // benign, must skip
		"deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n" + // specific user, captured
		"ALL ALL=(ALL:ALL) NOPASSWD: ALL\n" // full root, must be captured
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	info := &models.SecurityInfo{}
	parseSudoersFile(path, info)

	has := func(u string) bool {
		for _, e := range info.SudoNopasswd {
			if e == u {
				return true
			}
		}
		return false
	}
	if !has("ALL") {
		t.Errorf("full 'NOPASSWD: ALL' escalation must be flagged, got %v", info.SudoNopasswd)
	}
	if !has("deploy") {
		t.Errorf("specific-user NOPASSWD entry should be captured, got %v", info.SudoNopasswd)
	}
	// The Mint-style specific-command ALL line contributes only the full-root "ALL"
	// (one ALL entry), so there must be exactly two entries total: deploy + ALL.
	if len(info.SudoNopasswd) != 2 {
		t.Errorf("expected 2 entries (deploy, ALL), got %v", info.SudoNopasswd)
	}
}

// Characterization tests for previously-uncovered pure parsers in
// security_linux.go. They lock in current behavior so the parser-hardening work
// (BUG-024..035 class) can continue without silent regressions. No external
// commands or filesystem access — every function under test takes a string (or
// struct) and returns a value.
//
// NOTE: parseSSHDuration, sshAllowedNFT, sshAllowedIPT and the core sshd_config
// fields are already covered by ssh_config_linux_test.go and firewall_ssh_test.go.
// This file deliberately covers the surface those don't: the CIS-extended SSH
// fields, the SELinux/AppArmor audit-log parsers, the port-classification
// helpers, the firewall decision primitive, and the syslog timestamp parser.

// TestParseSSHFileContent_CISExtendedFields covers the hardening fields that the
// existing ssh_config tests don't assert: LogLevel casing, Banner case
// preservation, MaxSessions/MaxStartups, the algorithm lists, IgnoreRhosts,
// HostbasedAuthentication, and Protocol 1 detection.
func TestParseSSHFileContent_CISExtendedFields(t *testing.T) {
	content := `Protocol 2
LogLevel verbose
Banner /etc/issue.net
MaxSessions 4
MaxStartups 10:30:60
Ciphers aes256-gcm@openssh.com
MACs hmac-sha2-512
KexAlgorithms curve25519-sha256
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
AllowTcpForwarding no`

	var info models.SecurityInfo
	parseSSHFileContent(content, &info)

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"SSHProtocol1", info.SSHProtocol1, false},
		{"SSHLogLevel", info.SSHLogLevel, "VERBOSE"},    // uppercased
		{"SSHBanner", info.SSHBanner, "/etc/issue.net"}, // original case preserved
		{"SSHMaxSessions", info.SSHMaxSessions, 4},
		{"SSHMaxStartups", info.SSHMaxStartups, "10:30:60"}, // value preserved verbatim
		{"SSHCiphers", info.SSHCiphers, "aes256-gcm@openssh.com"},
		{"SSHMACs", info.SSHMACs, "hmac-sha2-512"},
		{"SSHKexAlgorithms", info.SSHKexAlgorithms, "curve25519-sha256"},
		{"SSHIgnoreRhosts", info.SSHIgnoreRhosts, true},
		{"SSHHostbasedAuth", info.SSHHostbasedAuth, false},
		{"SSHPermitUserEnv", info.SSHPermitUserEnv, false},
		{"SSHTCPForwarding", info.SSHTCPForwarding, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestParseSSHFileContent_Protocol1 confirms the deprecated Protocol 1 is flagged.
func TestParseSSHFileContent_Protocol1(t *testing.T) {
	var info models.SecurityInfo
	parseSSHFileContent("Protocol 1\n", &info)
	if !info.SSHProtocol1 {
		t.Error("Protocol 1 should set SSHProtocol1=true")
	}
}

// TestParseSSHFileContent_Port22Ignored confirms the default port is not recorded
// as a non-standard override (SSHPort stays 0).
func TestParseSSHFileContent_Port22Ignored(t *testing.T) {
	var info models.SecurityInfo
	parseSSHFileContent("Port 22\n", &info)
	if info.SSHPort != 0 {
		t.Errorf("Port 22 should leave SSHPort=0 (default), got %d", info.SSHPort)
	}
}

func TestIsExpectedPort(t *testing.T) {
	expected := []int{22, 80, 443, 9090, 6443, 10250, 2379, 2380}
	for _, p := range expected {
		if !isExpectedPort(p) {
			t.Errorf("isExpectedPort(%d) = false, want true", p)
		}
	}
	unexpected := []int{23, 8080, 3306, 5432, 6379, 0, 65535}
	for _, p := range unexpected {
		if isExpectedPort(p) {
			t.Errorf("isExpectedPort(%d) = true, want false", p)
		}
	}
}

func TestWellKnownPortName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{25, "postfix"},
		{9090, "cockpit"},
		{10250, "kubelet"},
		{6443, "kube-apiserver"},
		{80, ""}, // not in the socket-activation list
		{12345, ""},
	}
	for _, tt := range tests {
		if got := wellKnownPortName(tt.port); got != tt.want {
			t.Errorf("wellKnownPortName(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello…"},
		{"", 3, ""},
	}
	for _, tt := range tests {
		if got := truncate(tt.s, tt.maxLen); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
		}
	}
}

// TestExtractAAField covers the AppArmor audit-log field extractor.
func TestExtractAAField(t *testing.T) {
	tests := []struct {
		name string
		line string
		key  string
		want string
	}{
		{"quoted", `apparmor="DENIED" operation="open" profile="/usr/bin/foo"`, "profile=", "/usr/bin/foo"},
		{"unquoted", `pid=123 comm=nginx`, "comm=", "nginx"},
		{"missing key", `operation="open"`, "name=", ""},
		{"quoted no close", `name="incomplete`, "name=", `"incomplete`}, // current behavior: returns with leading quote
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractAAField(tt.line, tt.key); got != tt.want {
				t.Errorf("extractAAField(%q, %q) = %q, want %q", tt.line, tt.key, got, tt.want)
			}
		})
	}
}

// TestAVCField covers the SELinux AVC key=value extractor.
func TestAVCField(t *testing.T) {
	tests := []struct {
		name string
		line string
		key  string
		want string
	}{
		{"midline", `avc: denied { read } for scontext=init_t tclass=file`, "scontext=", "init_t"},
		{"end of line", `... tclass=file`, "tclass=", "file"},
		{"missing", `avc: denied`, "scontext=", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := avcField(tt.line, tt.key); got != tt.want {
				t.Errorf("avcField(%q, %q) = %q, want %q", tt.line, tt.key, got, tt.want)
			}
		})
	}
}

// TestAVCPerms covers extraction of the denied-permission list from an AVC line.
func TestAVCPerms(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"multi", `avc: denied { read write open } for ...`, []string{"read", "write", "open"}},
		{"single", `avc: denied { prog_run } for ...`, []string{"prog_run"}},
		{"no braces", `avc: denied read for ...`, nil},
		{"empty braces", `{  }`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := avcPerms(tt.line)
			if len(got) != len(tt.want) {
				t.Fatalf("avcPerms(%q) = %v, want %v", tt.line, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("avcPerms(%q)[%d] = %q, want %q", tt.line, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestLastPart covers SELinux context type extraction. Contexts are
// user:role:type[:level[:categories]], so the type is the 3rd field.
func TestLastPart(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"system_u:system_r:init_t:s0", "init_t"},                         // 4 parts -> type
		{"unconfined_u:unconfined_r:container_t:s0:c1,c2", "container_t"}, // 5 parts (MCS range) -> type
		{"system_u:system_r:init_t", "init_t"},                            // 3 parts (no MLS) -> type
		{"init_t:s0", "s0"},                                               // malformed/partial -> fallback to last field
		{"init_t", "init_t"},                                              // single field
	}
	for _, tt := range tests {
		if got := lastPart(tt.in, ":"); got != tt.want {
			t.Errorf("lastPart(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSSHPort(t *testing.T) {
	if got := sshPort(&models.SecurityInfo{SSHPort: 2222}); got != 2222 {
		t.Errorf("sshPort with SSHPort=2222 = %d, want 2222", got)
	}
	if got := sshPort(&models.SecurityInfo{}); got != 22 {
		t.Errorf("sshPort default = %d, want 22", got)
	}
}

// TestDecideSSHAllowed covers the firewall decision primitive shared by the
// nft and iptables SSH-reachability heuristics.
func TestDecideSSHAllowed(t *testing.T) {
	tests := []struct {
		name                           string
		accept, block, inputPolicyDrop bool
		want                           bool
	}{
		{"explicit accept wins over block", true, true, true, true},
		{"explicit block", false, true, false, false},
		{"default drop policy", false, false, true, false},
		{"no signal = reachable", false, false, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideSSHAllowed(tt.accept, tt.block, tt.inputPolicyDrop); got != tt.want {
				t.Errorf("decideSSHAllowed(%v,%v,%v) = %v, want %v",
					tt.accept, tt.block, tt.inputPolicyDrop, got, tt.want)
			}
		})
	}
}

// TestParseLogTimestamp confirms a syslog stamp (which carries no year) parses
// with the current year injected, and that malformed input errors.
func TestParseLogTimestamp(t *testing.T) {
	ts, err := parseLogTimestamp("Jan  2 15:04:05")
	if err != nil {
		t.Fatalf("parseLogTimestamp returned error: %v", err)
	}
	if ts.Month() != 1 || ts.Day() != 2 || ts.Hour() != 15 || ts.Minute() != 4 || ts.Second() != 5 {
		t.Errorf("parsed wrong fields: %v", ts)
	}
	if _, err := parseLogTimestamp("not a timestamp"); err == nil {
		t.Errorf("expected error for malformed stamp")
	}
}
