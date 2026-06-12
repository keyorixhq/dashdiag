package fleet

import "testing"

// TestValidateHost_RejectsOptionInjection guards THREAT_MODEL_CLI.md F-1:
// a host token must never be interpretable by ssh/scp as an option, and must
// not carry shell/whitespace metacharacters. A poisoned --hosts-file is the
// realistic delivery vector (checked into a repo / generated from inventory).
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

// TestValidateHost_AcceptsLegitimate keeps the documented [user@]host forms
// working — regression guard so the F-1 fix never over-tightens.
func TestValidateHost_AcceptsLegitimate(t *testing.T) {
	good := []string{
		"server1",
		"web-01.prod.example.com",
		"root@10.0.0.5",
		"deploy@db1",
		"192.168.10.20",
		"fe80::1%eth0",        // IPv6 with zone id
		"2001:db8::1",         // IPv6
		"my_ssh_config_alias", // ~/.ssh/config Host alias
	}
	for _, h := range good {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) = %v, want nil", h, err)
		}
	}
}

// TestRun_InvalidHostNeverReachesSSH confirms a bad host short-circuits to an
// ERROR result instead of being shelled out.
func TestRun_InvalidHostNeverReachesSSH(t *testing.T) {
	res := Run(t.Context(), []string{"-oProxyCommand=evil"}, Options{})
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].Reachable || res[0].Worst != "ERROR" {
		t.Errorf("invalid host not rejected: %+v", res[0])
	}
}
