//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

func TestExtractAVCProcesses(t *testing.T) {
	samples := []string{
		`type=AVC msg=audit(1:1): avc: denied { read } comm="httpd" scontext=x`,
		`type=AVC msg=audit(2:2): avc: denied { read } comm="httpd" scontext=x`, // duplicate — deduped
		`type=AVC msg=audit(3:3): avc: denied { write } comm="sshd" scontext=x`,
		`no comm field here`,
		`type=AVC comm="unclosed`, // comm= found but no closing quote → end <= 0 → skip
	}
	procs := ExtractAVCProcesses(samples)
	if len(procs) != 2 || procs[0] != "httpd" || procs[1] != "sshd" {
		t.Errorf("expected [httpd sshd] deduped in first-seen order, got %v", procs)
	}
}

func TestIsSafePolicyToken(t *testing.T) {
	if !isSafePolicyToken("httpd_t-1") {
		t.Error("alnum/underscore/hyphen token should be safe")
	}
	if isSafePolicyToken("") {
		t.Error("empty string must not be considered safe")
	}
	if isSafePolicyToken("rm -rf /") {
		t.Error("a token with shell metacharacters/spaces must not be considered safe")
	}
}

func TestParseNeedsDaemonReload(t *testing.T) {
	out := "Id=nginx.service\n" +
		"NeedDaemonReload=yes\n" +
		"\n" +
		"Id=sshd.service\n" +
		"NeedDaemonReload=no\n"
	units := parseNeedsDaemonReload(out)
	if len(units) != 1 || units[0] != "nginx.service" {
		t.Errorf("only the unit with NeedDaemonReload=yes should be reported, got %v", units)
	}
}

func TestParseMaskedUnits(t *testing.T) {
	out := "systemd-networkd-wait-online.service masked\n" +
		"bad-line-no-dot\n" + // no "." in the name field — filtered
		"snapd.seeded.service masked\n"
	units := parseMaskedUnits(out)
	if len(units) != 2 {
		t.Errorf("expected 2 masked units (the dotless line filtered), got %v", units)
	}
}

func TestParseVirshVersion(t *testing.T) {
	out := "Compiled against library: libvirt 10.0.0\n" +
		"Using library: libvirt 10.0.0\n" +
		"Using API: QEMU 10.0.0\n" +
		"Running hypervisor: QEMU 8.2.2\n"
	info := &models.KVMInfo{}
	parseVirshVersion(out, info)
	if info.LibvirtVer != "10.0.0" {
		t.Errorf("LibvirtVer should be parsed from the 'Using library' line, got %q", info.LibvirtVer)
	}
	if info.QEMUVer != "8.2.2" {
		t.Errorf("QEMUVer should be parsed from the 'Running hypervisor' line, got %q", info.QEMUVer)
	}
}

func TestIsKernelThreadAndIsShell(t *testing.T) {
	if !isKernelThread("kworker/0:1") {
		t.Error("kworker/ prefix should be recognized as a kernel thread")
	}
	if isKernelThread("nginx") {
		t.Error("a real userspace process must not be flagged as a kernel thread")
	}
	if !isShell("bash") || !isShell("zsh") {
		t.Error("bash/zsh should be recognized as shells")
	}
	if isShell("nginx") {
		t.Error("nginx must not be recognized as a shell")
	}
}

// TestSecurityCollectorIsOffensiveDistro guards the profile-aware dispatch:
// when the platform Profile carries a distro, it's used directly (no /etc/
// os-release read needed); the zero-profile fallback (isOffensiveDistro())
// already has its own direct test.
func TestSecurityCollectorIsOffensiveDistro(t *testing.T) {
	kali := NewSecurityCollectorWithProfile(platform.Profile{Distro: "kali"})
	if !kali.isOffensiveDistro() {
		t.Error("a profile with Distro=kali should be recognized as offensive")
	}

	ubuntu := NewSecurityCollectorWithProfile(platform.Profile{Distro: "ubuntu"})
	if ubuntu.isOffensiveDistro() {
		t.Error("a profile with Distro=ubuntu must not be flagged offensive")
	}
}
