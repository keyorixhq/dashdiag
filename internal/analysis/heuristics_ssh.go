package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	sshConfigFile    = "sshd_config"
	sshCmdT          = "sshd -T"
	sshEffectiveConf = "sshd -T (effective config)"
)

// checkSSHWeakCiphers flags CBC-mode and arcfour ciphers.
// CBC-mode ciphers are vulnerable to BEAST and Lucky13 attacks.
// Data source: sshd -T (preferred, root) or sshd_config file parse.
func checkSSHWeakCiphers(sec models.SecurityInfo) []models.Insight {
	if sec.SSHCiphers == "" {
		return nil
	}
	weakPatterns := []string{"cbc", "arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
	var found []string
	for c := range strings.SplitSeq(sec.SSHCiphers, ",") {
		c = strings.TrimSpace(strings.ToLower(c))
		for _, weak := range weakPatterns {
			if strings.Contains(c, weak) {
				found = append(found, c)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := sshConfigFile
	if sec.SSHAuditSource == sshCmdT {
		source = sshEffectiveConf
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak cipher(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr in /etc/ssh/sshd_config",
			"note: CBC-mode ciphers are vulnerable to BEAST/Lucky13",
			"to verify: sshd -T | grep ciphers",
		},
	)}
}

// checkSSHWeakMACs flags legacy MAC algorithms.
// hmac-sha1 and hmac-md5 use broken hash functions. umac-64 has insufficient tag length.
// The *-etm variants of hmac-sha1 are marginally safer but still not recommended.
func checkSSHWeakMACs(sec models.SecurityInfo) []models.Insight {
	if sec.SSHMACs == "" {
		return nil
	}
	// Flag non-ETM weak MACs; ETM variants are accepted as borderline acceptable
	strictWeak := []string{"hmac-md5", "hmac-sha1,", "hmac-sha1 ", "umac-64@", "hmac-ripemd160"}
	// hmac-sha1 (non-ETM) — check as standalone token
	var found []string
	for m := range strings.SplitSeq(sec.SSHMACs, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		for _, weak := range strictWeak {
			// Match exact token or token followed by nothing (avoid matching hmac-sha1-etm)
			if m == strings.TrimRight(weak, ", ") ||
				strings.HasPrefix(m, "hmac-md5") ||
				strings.HasPrefix(m, "hmac-ripemd160") ||
				(strings.HasPrefix(m, "umac-64@") && !strings.Contains(m, "etm")) ||
				m == "hmac-sha1" {
				found = append(found, m)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := sshConfigFile
	if sec.SSHAuditSource == sshCmdT {
		source = sshEffectiveConf
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak MAC(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com in /etc/ssh/sshd_config",
			"note: hmac-sha1 uses SHA-1 which is cryptographically broken",
			"to verify: sshd -T | grep '^macs'",
		},
	)}
}

// checkSSHWeakKEX flags broken Diffie-Hellman key exchange algorithms.
// group1-sha1 uses 1024-bit DH (Logjam attack). group14-sha1 uses SHA-1.
func checkSSHWeakKEX(sec models.SecurityInfo) []models.Insight {
	if sec.SSHKexAlgorithms == "" {
		return nil
	}
	weakKEX := []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
	}
	var found []string
	for k := range strings.SplitSeq(sec.SSHKexAlgorithms, ",") {
		k = strings.TrimSpace(strings.ToLower(k))
		if slices.Contains(weakKEX, k) {
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := sshConfigFile
	if sec.SSHAuditSource == sshCmdT {
		source = sshEffectiveConf
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak KEX algorithm(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256 in /etc/ssh/sshd_config",
			"note: diffie-hellman-group1-sha1 is vulnerable to the Logjam attack (1024-bit DH)",
			"to verify: sshd -T | grep kexalgorithms",
		},
	)}
}

// ── User account hardening checks (Spec 14) ──────────────────────────────────

// These checks are appended to checkSecurity via calls inside that function.
// Keeping them as standalone functions makes them independently testable.

func checkEmptyPasswords(sec models.SecurityInfo) []models.Insight {
	if len(sec.EmptyPasswordAccounts) == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "Hardening",
		fmt.Sprintf("account(s) with no password set: %s — any user can log in without a password",
			strings.Join(sec.EmptyPasswordAccounts, ", ")),
		[]string{
			"to inspect: sudo awk -F: '($2==\"\"){print $1}' /etc/shadow",
			"to fix:     passwd <username>  (set a password)",
			"to lock:    passwd -l <username>  (lock until password is set)",
		},
	)}
}

func checkStalePasswords(sec models.SecurityInfo) []models.Insight {
	if len(sec.StalePasswordAccounts) == 0 {
		return nil
	}
	shown := sec.StalePasswordAccounts
	suffix := ""
	if len(shown) > 3 {
		shown = shown[:3]
		suffix = fmt.Sprintf(" (+%d more)", len(sec.StalePasswordAccounts)-3)
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("password never expires for human account(s): %s%s",
			strings.Join(shown, ", "), suffix),
		[]string{
			"to inspect: sudo chage -l <username>",
			"to fix:     chage -M 90 <username>  (expire after 90 days)",
			"to fix all: awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd | xargs -I{} chage -M 90 {}",
			"note: CIS benchmark recommends maximum password age ≤ 365 days",
		},
	)}
}

func checkWorldWritable(sec models.SecurityInfo) []models.Insight {
	if len(sec.WorldWritableDirs) == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "Hardening",
		fmt.Sprintf("world-writable director(y/ies) missing sticky bit: %s — any user can delete others' files",
			strings.Join(sec.WorldWritableDirs, ", ")),
		[]string{
			"to fix: chmod +t /tmp /var/tmp /dev/shm",
			"to verify: ls -ld /tmp /var/tmp /dev/shm",
			"note: sticky bit (t) prevents users from deleting files they don't own",
		},
	)}
}
