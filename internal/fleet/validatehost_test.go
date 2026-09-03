package fleet

import "testing"

// TestValidateHost_RejectsOptionInjection guards the fleet host trust
// boundary (docs/THREAT_MODEL.md): a host token must never be interpretable
// by ssh/scp as an option, and must not carry shell/whitespace
// metacharacters. A poisoned --hosts-file is the realistic delivery vector
// (checked into a repo / generated from inventory).
func TestValidateHost_RejectsOptionInjection(t *testing.T) {
	bad := []string{
		"-oProxyCommand=touch /tmp/pwned",
		"-oPermitLocalCommand=yes",
		"--",
		"-",
		"-l",
		"host with space",
		"host;rm -rf /",
		"host$(whoami)",
		"host`id`",
		"host\nmalicious",
		"host&background",
		"host|pipe",
		"",
	}
	for _, h := range bad {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want rejection", h)
		}
	}
}

// TestValidateHost_RejectsSlashAndBareColon guards the scp local/remote
// path-confusion defect (see ValidateHost's doc comment): a '/' anywhere in
// a host token silently misroutes an scp destination to a LOCAL path, and a
// bare (unbracketed) ':' lets a poisoned host string redirect the upload to
// an unlisted remote host via scp's first-':'-wins parsing.
func TestValidateHost_RejectsSlashAndBareColon(t *testing.T) {
	bad := []string{
		"/tmp/evil",           // scp: '/' before any ':' -> parsed as a local path
		"attacker.com:/tmp/x", // scp: first ':' wins -> uploads to attacker.com
		"host:with:colons",    // bare ':' outside brackets, not a valid IPv6 shape either
		"2001:db8::1",         // real IPv6 literal, but brackets are now required
		"fe80::1%eth0",        // same, with a zone id
		"user@attacker.com:/tmp/x",
	}
	for _, h := range bad {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want rejection", h)
		}
	}
}

// TestValidateHost_AcceptsLegitimate keeps the documented [user@]host forms
// working — regression guard so the structural rewrite never over-tightens.
func TestValidateHost_AcceptsLegitimate(t *testing.T) {
	good := []string{
		"server1",
		"web-01.prod.example.com",
		"root@10.0.0.5",
		"deploy@db1",
		"user@host.example",
		"192.168.10.20",
		"[fe80::1%eth0]",      // IPv6 with zone id, bracketed
		"[2001:db8::1]",       // IPv6, bracketed
		"my_ssh_config_alias", // ~/.ssh/config Host alias
	}
	for _, h := range good {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) = %v, want nil", h, err)
		}
	}
}

// TestValidateHost_RejectsMalformedBracketedIPv6 covers
// validateBracketedIPv6's three error branches directly — none of
// TestValidateHost_RejectsSlashAndBareColon's cases start with '[', so none
// of them route into this helper at all.
func TestValidateHost_RejectsMalformedBracketedIPv6(t *testing.T) {
	bad := []string{
		"[fe80::1",      // unterminated: no closing ']'
		"[]",            // too short after stripping brackets (len < 3)
		"[not-an-ip]",   // well-bracketed but not a parseable address
		"[192.168.1.1]", // parses, but is IPv4 -- brackets are IPv6-only
	}
	for _, h := range bad {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want rejection", h)
		}
	}
}

// TestRun_InvalidHostNeverReachesSSH confirms a bad host short-circuits to an
// ERROR result instead of being shelled out.
func TestRun_InvalidHostNeverReachesSSH(t *testing.T) {
	res, err := Run(t.Context(), []string{"-oProxyCommand=evil"}, Options{})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].Reachable || res[0].Worst != "ERROR" {
		t.Errorf("invalid host not rejected: %+v", res[0])
	}
}
