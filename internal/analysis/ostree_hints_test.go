package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

var ostreeFixHintCases = []struct {
	name string
	in   string
	want string
}{
	{
		// The Fedora CoreOS regression: open-vm-tools hint said `dnf install`,
		// which can't persist on the read-only /usr of an ostree host.
		"open-vm-tools with parenthetical",
		"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
		"to fix (ostree): rpm-ostree install open-vm-tools (then reboot)",
	},
	{
		"rsyslog three-way",
		"to fix: apt install rsyslog  OR  dnf install rsyslog  OR  zypper install rsyslog",
		"to fix (ostree): rpm-ostree install rsyslog (then reboot)",
	},
	{
		"dnf compound mid-string",
		"or install a syslog daemon: dnf/apt/zypper install rsyslog",
		"to fix (ostree): rpm-ostree install rsyslog (then reboot)",
	},
	{
		// the && service-enable tail is dropped — the layered package only takes
		// effect after the reboot rpm-ostree requires.
		"&& tail dropped",
		"to fix (Debian/Ubuntu): apt install qemu-guest-agent && systemctl enable --now qemu-guest-agent",
		"to fix (ostree): rpm-ostree install qemu-guest-agent (then reboot)",
	},
	{
		"inspect line untouched",
		"to inspect: nft list ruleset",
		"to inspect: nft list ruleset",
	},
	{
		"sshd edit untouched",
		"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
		"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
	},
}

func TestOstreeFixHint(t *testing.T) {
	for _, tt := range ostreeFixHintCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := ostreeFixHint(tt.in); got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

// Whole-insight pass: rewrites install hints, leaves notes/order intact.
func TestOstreeifyHints(t *testing.T) {
	in := []models.Insight{{
		Level: "WARN", Check: "VMware", Message: "open-vm-tools not installed",
		Hints: []string{
			"to fix: apt install open-vm-tools   (RHEL/SUSE: dnf/zypper install open-vm-tools)",
			"note:   keep this line",
		},
	}}
	out := ostreeifyHints(in)
	if len(out[0].Hints) != 2 ||
		out[0].Hints[0] != "to fix (ostree): rpm-ostree install open-vm-tools (then reboot)" ||
		out[0].Hints[1] != "note:   keep this line" {
		t.Errorf("hints = %#v", out[0].Hints)
	}
}
