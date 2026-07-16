package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckSSHWeakCiphers_EffectiveConfSource covers the sshEffectiveConf branch
// (SSHAuditSource == sshCmdT) inside checkSSHWeakCiphers (line 39-41).
func TestCheckSSHWeakCiphers_EffectiveConfSource(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SSHCiphers:     "aes256-cbc,chacha20-poly1305@openssh.com",
		SSHAuditSource: "sshd -T",
	}
	got := checkSSHWeakCiphers(sec)
	if len(got) == 0 {
		t.Fatal("expected a WARN for CBC cipher, got no insights")
	}
	if !strings.Contains(got[0].Message, sshEffectiveConf) {
		t.Errorf("message must include effective-conf source label %q, got %q", sshEffectiveConf, got[0].Message)
	}
}

// TestCheckSSHWeakMACs_EffectiveConfSource covers the sshEffectiveConf branch
// in checkSSHWeakMACs (line 81-83).
func TestCheckSSHWeakMACs_EffectiveConfSource(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SSHMACs:        "hmac-md5,hmac-sha2-256",
		SSHAuditSource: "sshd -T",
	}
	got := checkSSHWeakMACs(sec)
	if len(got) == 0 {
		t.Fatal("expected a WARN for hmac-md5, got no insights")
	}
	if !strings.Contains(got[0].Message, sshEffectiveConf) {
		t.Errorf("message must include effective-conf source label %q, got %q", sshEffectiveConf, got[0].Message)
	}
}

// TestCheckSSHWeakKEX_EffectiveConfSource covers the sshEffectiveConf branch
// in checkSSHWeakKEX (line 116-118).
func TestCheckSSHWeakKEX_EffectiveConfSource(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{
		SSHKexAlgorithms: "diffie-hellman-group1-sha1,curve25519-sha256",
		SSHAuditSource:   "sshd -T",
	}
	got := checkSSHWeakKEX(sec)
	if len(got) == 0 {
		t.Fatal("expected a WARN for group1-sha1 KEX, got no insights")
	}
	if !strings.Contains(got[0].Message, sshEffectiveConf) {
		t.Errorf("message must include effective-conf source label %q, got %q", sshEffectiveConf, got[0].Message)
	}
}

// TestCheckStalePasswords_Truncation covers the >3 truncation branch in
// checkStalePasswords (lines 155-158): when more than 3 accounts are stale only
// the first 3 are named and a "(+N more)" suffix is appended.
func TestCheckStalePasswords_Truncation(t *testing.T) {
	t.Parallel()
	// Use 5 account names that are disjoint from message boilerplate words
	// to avoid false substring matches (e.g. "eve" inside "never").
	accounts := []string{"user1", "user2", "user3", "user4", "user5"}
	sec := models.SecurityInfo{StalePasswordAccounts: accounts}
	got := checkStalePasswords(sec)
	if len(got) == 0 {
		t.Fatal("expected a WARN for stale passwords, got no insights")
	}
	msg := got[0].Message
	if !strings.Contains(msg, "+2 more") {
		t.Errorf("message must mention +2 more when 5 accounts given, got %q", msg)
	}
	// The 4th and 5th accounts must NOT be named directly.
	if strings.Contains(msg, "user4") || strings.Contains(msg, "user5") {
		t.Errorf("truncated accounts (user4, user5) must not appear in message, got %q", msg)
	}
	// The first 3 must be present.
	if !strings.Contains(msg, "user1") || !strings.Contains(msg, "user2") || !strings.Contains(msg, "user3") {
		t.Errorf("first 3 accounts must appear in message, got %q", msg)
	}
}
