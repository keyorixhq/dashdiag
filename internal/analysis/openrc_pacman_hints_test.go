package analysis

import "testing"

// Finding 1: on a non-systemd (OpenRC) host the `to inspect:` lines that use
// systemd-only tools must adapt — `systemctl status <svc>` → rc-service, and
// timedatectl/journalctl/systemd-only-units drop (no runnable equivalent).
// Found live on an Artix (OpenRC) VMware guest.
func TestAdaptHintOpenRCInspect(t *testing.T) {
	cases := []struct {
		name, hint, want string
		wantDrop         bool
	}{
		{"systemctl status multi-svc → rc-service first", "to inspect: systemctl status chronyd ntpd", "to inspect: rc-service chronyd status", false},
		{"systemctl status single", "to inspect: systemctl status sshd", "to inspect: rc-service sshd status", false},
		{"systemd-resolved has no OpenRC equiv → drop", "to inspect: systemctl status systemd-resolved", "", true},
		{"systemd-journald → drop", "to inspect: systemctl status systemd-journald", "", true},
		{"timedatectl → drop", "to inspect: timedatectl status", "", true},
		{"journalctl → drop", "to inspect: journalctl -p err --since '1 hour ago' --no-pager", "", true},
		{"journalctl -k → drop", "to inspect: journalctl -k | grep -i 'out of memory'", "", true},
		{"plain inspect untouched", "to inspect: cat /etc/resolv.conf", "to inspect: cat /etc/resolv.conf", false},
		{"dig untouched", "to inspect: dig @8.8.8.8 google.com", "to inspect: dig @8.8.8.8 google.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, drop := adaptHint(c.hint, "linux", "openrc")
			if drop != c.wantDrop {
				t.Fatalf("adaptHint(%q) drop=%v, want %v (got %q)", c.hint, drop, c.wantDrop, got)
			}
			if !drop && got != c.want {
				t.Errorf("adaptHint(%q) = %q, want %q", c.hint, got, c.want)
			}
		})
	}
}

// Finding 2: distroFixHint must use the package manager's actual install verb —
// pacman uses `pacman -S`, apk uses `apk add`, not `<pm> install`.
func TestDistroFixHintPM(t *testing.T) {
	cases := []struct {
		name, hint, pm, want string
	}{
		{"pacman uses -S (open-vm-tools, Arch)", "to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)", "pacman", "to fix: pacman -S open-vm-tools"},
		{"apk uses add (rsyslog, Alpine)", "to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog", "apk", "to fix: apk add rsyslog"},
		{"dnf still uses install", "to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)", "dnf", "to fix: dnf install open-vm-tools"},
		{"pacman preserves && tail", "to fix: apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent", "pacman", "to fix: pacman -S qemu-guest-agent && systemctl enable --now qemu-guest-agent"},
		{"non-install hint passes through", "to inspect: nft list ruleset", "pacman", "to inspect: nft list ruleset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := distroFixHint(c.hint, c.pm); got != c.want {
				t.Errorf("distroFixHint(%q, %s) = %q, want %q", c.hint, c.pm, got, c.want)
			}
		})
	}
}

// pmInstallCmd renders the right verb per manager.
func TestPMInstallCmd(t *testing.T) {
	cases := map[string]string{
		"pacman": "pacman -S vim",
		"apk":    "apk add vim",
		"apt":    "apt install vim",
		"dnf":    "dnf install vim",
		"zypper": "zypper install vim",
		"tdnf":   "tdnf install vim",
	}
	for pm, want := range cases {
		if got := pmInstallCmd(pm, "vim"); got != want {
			t.Errorf("pmInstallCmd(%q, vim) = %q, want %q", pm, got, want)
		}
	}
}
