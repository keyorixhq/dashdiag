package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var gentooFixHintCases = []struct {
	name string
	in   string
	want string
}{
	// VMware open-vm-tools — apt form with a trailing (RHEL/SUSE: …) parenthetical
	{
		"open-vm-tools with parenthetical",
		"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
		"to fix (Gentoo): emerge open-vm-tools",
	},
	// rsyslog — three-way apt/dnf/zypper OR string
	{
		"rsyslog three-way",
		"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
		"to fix (Gentoo): emerge rsyslog",
	},
	// rsyslog — "dnf/apt/zypper install" compound (manager keyword mid-string)
	{
		"rsyslog compound dnf/apt/zypper",
		"or install a syslog daemon: dnf/apt/zypper install rsyslog",
		"to fix (Gentoo): emerge rsyslog",
	},
	// nvme-cli — install word then parenthetical with the real commands
	{
		"nvme-cli parenthetical",
		"to fix: install nvme-cli  (apt install nvme-cli  /  dnf install nvme-cli  /  zypper install nvme-cli)",
		"to fix (Gentoo): emerge nvme-cli",
	},
	// smartmontools — apt/dnf/zypper compound inside parens
	{
		"smartmontools compound",
		"to fix: install smartmontools (apt/dnf/zypper install smartmontools)",
		"to fix (Gentoo): emerge smartmontools",
	},
	// qemu-guest-agent — trailing && service-enable must be preserved
	{
		"qemu-guest-agent preserves && tail",
		"to fix (Debian/Ubuntu): apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent",
		"to fix (Gentoo): emerge qemu-guest-agent && systemctl enable --now qemu-guest-agent",
	},
	// apt-get must win over apt (longer keyword first)
	{
		"apt-get nvidia-driver",
		"to fix (Debian/Ubuntu): apt-get install nvidia-driver",
		"to fix (Gentoo): emerge nvidia-driver",
	},
	// cron — single manager, trailing distro tag in parens
	{
		"cronie dnf",
		"to install: dnf install cronie  (RHEL/Fedora)",
		"to fix (Gentoo): emerge cronie",
	},
	// iproute — first match wins among multiple managers
	{
		"iproute2 first match",
		"to install: apt install iproute2  /  dnf install iproute",
		"to fix (Gentoo): emerge iproute2",
	},
	// Passthrough — non-install hints are untouched
	{
		"inspect line untouched",
		"to inspect: iptables -L -n",
		"to inspect: iptables -L -n",
	},
	{
		"sshd edit untouched",
		"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
		"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
	},
	{
		"note untouched",
		"note: hmac-sha1 uses SHA-1 which is cryptographically broken",
		"note: hmac-sha1 uses SHA-1 which is cryptographically broken",
	},
	{
		"adapt not mistaken for apt",
		"note: adapt the firewall ruleset before install windows close",
		"note: adapt the firewall ruleset before install windows close",
	},
}

func TestGentooFixHint(t *testing.T) {
	for _, tt := range gentooFixHintCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := gentooFixHint(tt.in); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// TestGentooifyHints verifies the whole-insight pass: rewrites install hints,
// preserves notes/order, and leaves insights without install hints alone.
func TestGentooifyHints(t *testing.T) {
	in := []models.Insight{
		{
			Level: "WARN", Check: "VMware", Message: "open-vm-tools not installed",
			Hints: []string{
				"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
			},
		},
		{
			Level: "INFO", Check: "Logs", Message: "no text log fallback",
			Hints: []string{
				"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
				"note:   standard Unix tools cannot read binary journal files",
			},
		},
	}
	out := gentooifyHints(in)

	if len(out[0].Hints) != 1 || out[0].Hints[0] != "to fix (Gentoo): emerge open-vm-tools" {
		t.Errorf("vmware hints = %#v", out[0].Hints)
	}
	if len(out[1].Hints) != 2 ||
		out[1].Hints[0] != "to fix (Gentoo): emerge rsyslog" ||
		out[1].Hints[1] != "note:   standard Unix tools cannot read binary journal files" {
		t.Errorf("logs hints = %#v", out[1].Hints)
	}
}

// distroifyInstallHints must rewrite apt-first package-install hints to lead with the
// host's package manager (dnf/zypper/tdnf), preserving any trailing && action — so the
// suggested command is copy-pasteable on RHEL/SUSE (found live: the open-vm-tools hint
// led with apt on an AlmaLinux/VMware guest).
func TestDistroifyInstallHints(t *testing.T) {
	in := []models.Insight{{Hints: []string{
		"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
		"to fix: apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent",
		"to inspect: cat /proc/mounts", // no install suggestion — must pass through
	}}}
	got := distroifyInstallHints(in, "dnf")[0].Hints
	if got[0] != "to fix: dnf install open-vm-tools" {
		t.Errorf("hint[0] = %q, want dnf-led", got[0])
	}
	if got[1] != "to fix: dnf install qemu-guest-agent && systemctl enable --now qemu-guest-agent" {
		t.Errorf("hint[1] = %q, want dnf-led with && action preserved", got[1])
	}
	if got[2] != "to inspect: cat /proc/mounts" {
		t.Errorf("non-install hint must pass through, got %q", got[2])
	}
	// zypper host.
	z := distroifyInstallHints([]models.Insight{{Hints: []string{"to fix: apt install rsyslog  OR  dnf install rsyslog"}}}, "zypper")[0].Hints[0]
	if z != "to fix: zypper install rsyslog" {
		t.Errorf("zypper rewrite = %q", z)
	}
}
