package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// adaptHint rewrites a remedy command to the platform where dsd is running:
// macOS has no `ss` (use lsof); OpenRC/Alpine has no `systemctl` (use rc-service/
// rc-update). The diagnosis is unchanged — only the runnable "to inspect/fix" line.
func TestAdaptHint(t *testing.T) {
	cases := []struct {
		name       string
		hint       string
		goos, init string
		want       string
	}{
		// macOS: ss → lsof
		{"macos ss port grep", "to inspect: ss -tlnp | grep :8080", "darwin", "unknown", "to inspect: lsof -nP -iTCP:8080 -sTCP:LISTEN"},
		{"macos ss udp port grep", "to inspect: ss -tulnp | grep :53", "darwin", "unknown", "to inspect: lsof -nP -iTCP:53 -sTCP:LISTEN"},
		{"macos ss listen", "to inspect: ss -tlnp", "darwin", "unknown", "to inspect: lsof -nP -iTCP -sTCP:LISTEN"},
		{"macos leaves non-ss hint", "to fix: set PermitRootLogin no in /etc/ssh/sshd_config", "darwin", "unknown", "to fix: set PermitRootLogin no in /etc/ssh/sshd_config"},
		// OpenRC: systemctl → rc-service / rc-update
		{"openrc restart", "to fix: systemctl restart sshd", "linux", "openrc", "to fix: rc-service sshd restart"},
		{"openrc enable --now", "to fix: systemctl enable --now rpcbind", "linux", "openrc", "to fix: rc-update add rpcbind && rc-service rpcbind start"},
		{"openrc disable", "to fix: systemctl disable NetworkManager-wait-online.service", "linux", "openrc", "to fix: rc-update del NetworkManager-wait-online.service"},
		{"openrc leaves ss hint (ss exists on linux)", "to inspect: ss -tlnp", "linux", "openrc", "to inspect: ss -tlnp"},
		// systemd/linux: untouched (handled by the early return in adaptHintsToPlatform,
		// but adaptHint itself is a no-op too)
		{"linux systemd passthrough", "to fix: systemctl restart sshd", "linux", "systemd", "to fix: systemctl restart sshd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, drop := adaptHint(c.hint, c.goos, c.init)
			if drop {
				t.Fatalf("unexpected drop for %q", c.hint)
			}
			if got != c.want {
				t.Errorf("adaptHint(%q, %s, %s) = %q, want %q", c.hint, c.goos, c.init, got, c.want)
			}
		})
	}
}

// The wrapper must be a no-op on Linux/systemd (the common case) and rewrite in
// place on macOS/OpenRC.
func TestAdaptHintsToPlatform(t *testing.T) {
	ins := []models.Insight{{Level: "WARN", Check: "Hardening", Hints: []string{"to inspect: ss -tlnp | grep :22"}}}

	// Linux/systemd: untouched.
	out := adaptHintsToPlatform(cloneInsights(ins), "linux", "systemd")
	if out[0].Hints[0] != "to inspect: ss -tlnp | grep :22" {
		t.Errorf("linux/systemd should not rewrite, got %q", out[0].Hints[0])
	}
	// macOS: rewritten.
	out = adaptHintsToPlatform(cloneInsights(ins), "darwin", "unknown")
	if out[0].Hints[0] != "to inspect: lsof -nP -iTCP:22 -sTCP:LISTEN" {
		t.Errorf("macOS should rewrite ss→lsof, got %q", out[0].Hints[0])
	}
}

// PlatformServiceCmd is the choke point for subcommands (dsd docker/cron/kvm/proc)
// and correlation Actions that print service-management remedies directly, outside
// the insight pipeline. It must rewrite systemctl→rc-* on OpenRC and pass through
// unchanged on systemd/macOS — the same contract as adaptHint, which it delegates to.
func TestPlatformServiceCmd(t *testing.T) {
	cases := []struct {
		name       string
		systemd    string
		goos, init string
		want       string
	}{
		{"systemd restart passthrough", "systemctl restart docker", "linux", "systemd", "systemctl restart docker"},
		{"systemd enable passthrough", "systemctl enable --now crond", "linux", "systemd", "systemctl enable --now crond"},
		{"openrc restart", "systemctl restart docker", "linux", "openrc", "rc-service docker restart"},
		{"openrc enable --now", "systemctl enable --now crond", "linux", "openrc", "rc-update add crond && rc-service crond start"},
		{"openrc libvirtd", "systemctl enable --now libvirtd", "linux", "openrc", "rc-update add libvirtd && rc-service libvirtd start"},
		{"openrc placeholder service", "systemctl restart <service-name>", "linux", "openrc", "rc-service <service-name> restart"},
		// macOS has no systemctl rewrite target (Docker Desktop/launchd), so the
		// command is left as-is rather than emitting a wrong rc-*/lsof guess.
		{"macos leaves systemctl", "systemctl restart docker", "darwin", "unknown", "systemctl restart docker"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := platformServiceCmd(c.systemd, c.goos, c.init); got != c.want {
				t.Errorf("platformServiceCmd(%q, %s, %s) = %q, want %q", c.systemd, c.goos, c.init, got, c.want)
			}
		})
	}
}

func cloneInsights(in []models.Insight) []models.Insight {
	out := make([]models.Insight, len(in))
	for i, ins := range in {
		out[i] = ins
		out[i].Hints = append([]string(nil), ins.Hints...)
	}
	return out
}
