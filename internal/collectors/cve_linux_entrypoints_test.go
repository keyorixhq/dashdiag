//go:build linux

package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeLookPathSource wraps a Bundle-backed Replay (so PutFile/PutCmd/PutGlob
// still work) but overrides Cached so lookPath("<tool>") resolves per the
// `found` map — the Bundle API has no public seam for Cached results.
type fakeLookPathSource struct {
	*source.Replay
	found map[string]bool
}

func (f fakeLookPathSource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	name := strings.TrimPrefix(key, "lookpath/")
	if f.found[name] {
		return []byte("/usr/bin/" + name), nil
	}
	return nil, errNotFoundCVE
}

var errNotFoundCVE = errors.New("executable file not found in $PATH")

func withLookPathFixture(t *testing.T, found map[string]bool, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	seed(b)
	prev := SetSource(fakeLookPathSource{Replay: source.NewReplay(b), found: found})
	t.Cleanup(func() { SetSource(prev) })
}

func TestIsUbuntu(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "ID=ubuntu\n", 0)
	})
	if !isUbuntu() {
		t.Error("expected isUbuntu() to report true when grep matches")
	}
}

func TestIsUbuntu_NotUbuntu(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "", 1) // grep: no match, exit 1
	})
	if isUbuntu() {
		t.Error("expected isUbuntu() to report false when grep finds no match")
	}
}

func TestIsKali(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=kali\nID_LIKE=debian\n"))
	})
	if !isKali() {
		t.Error("expected isKali() to report true for ID=kali")
	}
}

func TestIsKali_NotKali(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})
	if isKali() {
		t.Error("expected isKali() to report false for a non-Kali distro")
	}
}

func TestIsKali_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if isKali() {
		t.Error("expected isKali() to report false when /etc/os-release is unreadable")
	}
}

func TestCheckCVEDNF_Vulnerable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"advisory", "info", "--cve", "CVE-2026-1234", "--quiet"},
			"Advisory ID: RHSA-2026:1234\nSeverity: Important\n  openssl-1.2.3-1.el9.x86_64\n  openssl-libs-1.2.3-1.el9.x86_64\n", 0)
	})

	result := checkCVEDNF(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVEVulnerable {
		t.Fatalf("expected CVEVulnerable, got %v (reason: %s)", result.Status, result.StatusReason)
	}
	if len(result.AffectedPackages) != 2 {
		t.Errorf("expected 2 affected packages, got %d: %+v", len(result.AffectedPackages), result.AffectedPackages)
	}
	if result.FixAdvisory != "RHSA-2026:1234" {
		t.Errorf("expected FixAdvisory=RHSA-2026:1234, got %q", result.FixAdvisory)
	}
}

func TestCheckCVEDNF_DNF4Fallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"advisory", "info", "--cve", "CVE-2026-1234", "--quiet"})
		b.PutCmd("dnf", []string{"updateinfo", "info", "--cve", "CVE-2026-1234", "--quiet"},
			"Update ID: RHSA-2026:1234\nType: security\n  openssl-1.2.3-1.el9.x86_64\n", 0)
	})

	result := checkCVEDNF(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVEVulnerable {
		t.Fatalf("expected the DNF4 fallback to be parsed as CVEVulnerable, got %v", result.Status)
	}
}

func TestCheckCVEDNF_NoAdvisory(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dnf", []string{"advisory", "info", "--cve", "CVE-2026-1234", "--quiet"}, "No advisory found for this CVE\n", 0)
	})

	result := checkCVEDNF(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVENotAffected {
		t.Errorf("expected CVENotAffected for 'no advisory' output, got %v", result.Status)
	}
}

func TestCheckCVEDNF_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"advisory", "info", "--cve", "CVE-2026-1234", "--quiet"})
		b.PutCmdNotFound("dnf", []string{"updateinfo", "info", "--cve", "CVE-2026-1234", "--quiet"})
	})

	result := checkCVEDNF(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVEUnknown {
		t.Errorf("expected CVEUnknown when both dnf queries fail, got %v", result.Status)
	}
	if !strings.Contains(result.FallbackURL, "CVE-2026-1234") {
		t.Errorf("expected a fallback URL referencing the CVE, got %q", result.FallbackURL)
	}
}

func TestCheckCVEApt_DebsecanAvailable(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"debsecan": true}, func(b *source.Bundle) {
		b.PutCmd("debsecan", []string{"--cve", "CVE-2026-1234", "--format", "detail"},
			"CVE-2026-1234 openssl fix-available some description\n", 0)
	})

	result := checkCVEApt(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVEVulnerable {
		t.Errorf("expected checkCVEApt to delegate to debsecan and report Vulnerable, got %v", result.Status)
	}
}

func TestCheckCVEApt_NoDebsecan_Ubuntu(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "ID=ubuntu\n", 0)
	})

	result := checkCVEApt(context.Background(), "CVE-2026-1234")
	if result.Status != models.CVEUnknown {
		t.Errorf("expected CVEUnknown without debsecan, got %v", result.Status)
	}
	if !strings.Contains(result.FallbackURL, "ubuntu.com/security") {
		t.Errorf("expected an Ubuntu tracker URL, got %q", result.FallbackURL)
	}
}

func TestCheckCVEApt_NoDebsecan_Kali(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "", 1) // not ubuntu
		b.PutFile("/etc/os-release", []byte("ID=kali\n"))
	})

	result := checkCVEApt(context.Background(), "CVE-2026-1234")
	if !strings.Contains(result.FallbackURL, "security-tracker.debian.org") {
		t.Errorf("expected a Debian tracker URL for Kali, got %q", result.FallbackURL)
	}
	if !strings.Contains(result.StatusReason, "Kali") {
		t.Errorf("expected the Kali-specific status reason, got %q", result.StatusReason)
	}
}

func TestCheckCVEApt_NoDebsecan_PlainDebian(t *testing.T) {
	withLookPathFixture(t, map[string]bool{}, func(b *source.Bundle) {
		b.PutCmd("sh", []string{"-c", "grep -i ubuntu /etc/os-release"}, "", 1)
		b.PutFile("/etc/os-release", []byte("ID=debian\n"))
	})

	result := checkCVEApt(context.Background(), "CVE-2026-1234")
	if !strings.Contains(result.FallbackURL, "security-tracker.debian.org") {
		t.Errorf("expected the default Debian tracker URL, got %q", result.FallbackURL)
	}
	if strings.Contains(result.StatusReason, "Kali") {
		t.Errorf("plain Debian must not get the Kali-specific reason, got %q", result.StatusReason)
	}
}
