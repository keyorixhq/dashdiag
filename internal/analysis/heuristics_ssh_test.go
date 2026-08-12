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

// TestCheckSSHWeakMACs_Umac64EtmAndSha1_96 covers two real OpenSSH MAC names
// the matching logic previously missed entirely: umac-64-etm@openssh.com (the
// HasPrefix(m, "umac-64@") check never matches a string that starts with
// "umac-64-etm@" instead) and hmac-sha1-96 (only exact equality against the
// bare "hmac-sha1" was checked). Both are documented as weak by this file's
// own comment but were silently let through.
func TestCheckSSHWeakMACs_Umac64EtmAndSha1_96(t *testing.T) {
	t.Parallel()
	etm := checkSSHWeakMACs(models.SecurityInfo{SSHMACs: "umac-64-etm@openssh.com,hmac-sha2-256"})
	if len(etm) == 0 || !strings.Contains(etm[0].Message, "umac-64-etm@openssh.com") {
		t.Errorf("umac-64-etm@openssh.com must be flagged (short tag length regardless of ETM), got %+v", etm)
	}

	sha1_96 := checkSSHWeakMACs(models.SecurityInfo{SSHMACs: "hmac-sha1-96,hmac-sha2-256"})
	if len(sha1_96) == 0 || !strings.Contains(sha1_96[0].Message, "hmac-sha1-96") {
		t.Errorf("hmac-sha1-96 must be flagged, got %+v", sha1_96)
	}

	// hmac-sha1-96-etm@openssh.com stays borderline-acceptable, same as the
	// plain hmac-sha1-etm@openssh.com case — must NOT be flagged.
	sha1_96_etm := checkSSHWeakMACs(models.SecurityInfo{SSHMACs: "hmac-sha1-96-etm@openssh.com,hmac-sha2-256"})
	if len(sha1_96_etm) != 0 {
		t.Errorf("hmac-sha1-96-etm@openssh.com is ETM and must not be flagged, got %+v", sha1_96_etm)
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
