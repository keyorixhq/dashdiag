package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeRunSource serves scripted command results. The non-Run methods are unused
// by the package-integrity paths under test, so the embedded interface is left
// nil (calling them would panic, which would itself flag an unexpected access).
type fakeRunSource struct {
	source.Source
	run func(name string, args []string) source.Result
}

func (f fakeRunSource) Run(_ context.Context, name string, args ...string) (source.Result, error) {
	return f.run(name, args), nil
}

// TestPkgIntegrityAPTNonZeroExit guards the false-OK fix: `apt-get check` exits
// 100 and writes unmet deps to stderr; the old runCmd discarded that → a host
// with broken deps read clean. The collector must now capture it.
func TestPkgIntegrityAPTNonZeroExit(t *testing.T) {
	fake := fakeRunSource{run: func(name string, _ []string) source.Result {
		if name == "apt-get" {
			return source.Result{
				Stderr: []byte("The following packages have unmet dependencies:\n" +
					" foo : Depends: bar but it is not installed"),
				ExitCode: 100,
			}
		}
		return source.Result{} // dpkg --audit: clean
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityAPT(context.Background(), &pi)
	if len(pi.UnmetDeps) == 0 {
		t.Fatalf("apt-get check exit 100 with stderr unmet-deps must populate UnmetDeps (was a false-OK), got none")
	}
}

// TestPkgIntegrityZypperNonZeroExit: `zypper verify` exits 1 when it finds
// broken/missing deps and writes them to stdout — runCmd dropped them.
// TestPkgIntegrityAPT_DpkgBrokenPackages covers packages_linux.go:1054 — the
// "non-empty dpkg --audit line → BrokenPackages" branch. The existing
// TestPkgIntegrityAPTNonZeroExit leaves dpkg clean (empty stdout); this test
// seeds a broken-package report from dpkg.
func TestPkgIntegrityAPT_DpkgBrokenPackages(t *testing.T) {
	fake := fakeRunSource{run: func(name string, _ []string) source.Result {
		if name == "dpkg" {
			return source.Result{
				Stdout:   []byte("dpkg: foo: dependency problems prevent configuration of foo:\n"),
				ExitCode: 0,
			}
		}
		return source.Result{} // apt-get check: clean
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityAPT(context.Background(), &pi)
	if len(pi.BrokenPackages) == 0 {
		t.Fatal("non-empty dpkg --audit output must populate BrokenPackages")
	}
}

// TestPkgIntegrityDNF_TenOrMoreBrokenPackages covers packages_linux.go:1016 —
// the `if len(pi.BrokenPackages) >= 10 { break }` cap in pkgIntegrityDNF.
func TestPkgIntegrityDNF_TenOrMoreBrokenPackages(t *testing.T) {
	var dnfCheckOut strings.Builder
	for i := range 11 {
		fmt.Fprintf(&dnfCheckOut, "broken-pkg-%s: requires missing-dep\n", strings.Repeat("x", i))
	}
	fake := fakeRunSource{run: func(name string, args []string) source.Result {
		if name == "dnf" && len(args) > 0 && args[0] == "check" {
			return source.Result{Stdout: []byte(dnfCheckOut.String()), ExitCode: 1}
		}
		// rpm --verify: clean
		return source.Result{ExitCode: 0}
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityDNF(context.Background(), &pi)
	if len(pi.BrokenPackages) != 10 {
		t.Errorf("BrokenPackages must be capped at 10, got %d", len(pi.BrokenPackages))
	}
}

// TestPkgIntegrityDNF_RPMVerifyConfigSkipped covers packages_linux.go:1036 —
// the `if len(line) >= 10 && line[9] == 'c' { continue }` guard that skips
// config-file modifications from rpm --verify (expected changes, not tampering).
func TestPkgIntegrityDNF_RPMVerifyConfigSkipped(t *testing.T) {
	fake := fakeRunSource{run: func(name string, args []string) source.Result {
		if name == "dnf" && len(args) > 0 && args[0] == "check" {
			return source.Result{ExitCode: 0} // no broken packages
		}
		if name == "rpm" {
			// 9 attribute chars, then 'c' at position 9 = config file modification.
			// The guard must skip this line; RPMVerifyFailed must stay empty.
			return source.Result{
				Stdout:   []byte(".........c /etc/bash.bashrc\n"),
				ExitCode: 1,
			}
		}
		return source.Result{}
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityDNF(context.Background(), &pi)
	if len(pi.RPMVerifyFailed) != 0 {
		t.Errorf("config file line (line[9]=='c') must be skipped, got RPMVerifyFailed=%v", pi.RPMVerifyFailed)
	}
}

func TestPkgIntegrityZypperNonZeroExit(t *testing.T) {
	fake := fakeRunSource{run: func(_ string, _ []string) source.Result {
		return source.Result{
			Stdout:   []byte("Problem: package foo-1.2 requires bar, but it is broken / missing"),
			ExitCode: 1,
		}
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityZypper(context.Background(), &pi)
	if len(pi.BrokenPackages) == 0 {
		t.Fatalf("zypper verify exit 1 with broken/missing output must populate BrokenPackages (was a false-OK), got none")
	}
}
