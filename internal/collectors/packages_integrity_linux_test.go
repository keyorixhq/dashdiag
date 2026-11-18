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

// TestPkgIntegrityAPT_NonRootLockError is the red/green proof for the apt
// false-OK (defect B, AC1). As non-root the read-only apt dependency check exits
// 100 writing `E: Could not open lock file ... Permission denied` to stderr. That
// output is non-empty (so the "err && out==empty" guard does not fire) and
// matches neither "unmet dep" nor "broken package", so the OLD code left
// CheckFailed=false and UnmetDeps empty — broken deps on any non-root run read as
// clean (same class as the DNF false-OK). The fix: an "E:" line / non-zero exit
// with no recognised unmet-dependency text must set CheckFailed, never read clean.
//
// RED against the pre-fix code (CheckFailed stays false); GREEN after.
func TestPkgIntegrityAPT_NonRootLockError(t *testing.T) {
	fake := fakeRunSource{run: func(name string, _ []string) source.Result {
		if name == pkgCmdAptGet {
			return source.Result{
				Stderr: []byte("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n" +
					"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?"),
				ExitCode: 100,
			}
		}
		return source.Result{} // dpkg --audit: clean
	}}
	defer SetSource(SetSource(fake))

	var pi models.PackageIntegrity
	pkgIntegrityAPT(context.Background(), &pi)
	if len(pi.UnmetDeps) != 0 {
		t.Fatalf("lock-file error is not an unmet-dependency finding; UnmetDeps must stay empty, got %v", pi.UnmetDeps)
	}
	if !pi.CheckFailed {
		t.Fatal("non-root lock-file error (E: ..., exit 100) must set CheckFailed — otherwise broken deps read as a clean system (false-OK)")
	}
}

// TestPkgIntegrityAPT_CheckTable covers the four outcome classes of the read-only
// apt dependency check: real unmet deps (a finding, not a tool failure), a clean
// run, the non-root lock error (tool failure → CheckFailed), and a generic apt
// "E:" error with no unmet-dependency text (tool failure → CheckFailed).
func TestPkgIntegrityAPT_CheckTable(t *testing.T) {
	cases := []struct {
		name           string
		stdout, stderr string
		exit           int
		wantUnmet      bool
		wantFailed     bool
	}{
		{
			name: "unmet dependencies found",
			stdout: "Reading package lists...\nBuilding dependency tree...\n" +
				"Reading state information...\n",
			stderr: "The following packages have unmet dependencies:\n" +
				" foo : Depends: libbar (>= 2.0) but it is not installed\n" +
				"E: Unmet dependencies. Try 'apt --fix-broken install' with no packages (or specify a solution).",
			exit:       100,
			wantUnmet:  true,
			wantFailed: false,
		},
		{
			name:       "clean",
			stdout:     "Reading package lists...\nBuilding dependency tree...\nReading state information...\n",
			stderr:     "",
			exit:       0,
			wantUnmet:  false,
			wantFailed: false,
		},
		{
			name: "non-root lock error",
			stderr: "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n" +
				"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?",
			exit:       100,
			wantUnmet:  false,
			wantFailed: true,
		},
		{
			name:       "generic apt error, no unmet-dep text",
			stderr:     "E: The package cache file is corrupted",
			exit:       100,
			wantUnmet:  false,
			wantFailed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakeRunSource{run: func(name string, _ []string) source.Result {
				if name == pkgCmdAptGet {
					return source.Result{Stdout: []byte(tc.stdout), Stderr: []byte(tc.stderr), ExitCode: tc.exit}
				}
				return source.Result{} // dpkg --audit: clean
			}}
			defer SetSource(SetSource(fake))

			var pi models.PackageIntegrity
			pkgIntegrityAPT(context.Background(), &pi)
			if gotUnmet := len(pi.UnmetDeps) > 0; gotUnmet != tc.wantUnmet {
				t.Errorf("UnmetDeps present = %v, want %v (got %v)", gotUnmet, tc.wantUnmet, pi.UnmetDeps)
			}
			if pi.CheckFailed != tc.wantFailed {
				t.Errorf("CheckFailed = %v, want %v", pi.CheckFailed, tc.wantFailed)
			}
		})
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

// TestPkgIntegrityDNF_CheckFailed is the mechanical-sweep finding (gap C,
// idiom 3): `dnf check` failing to spawn at all (not a findings-bearing
// non-zero exit) left BrokenPackages empty with no disclosure —
// indistinguishable from a genuinely clean system. CheckFailed must be set.
func TestPkgIntegrityDNF_CheckFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dnf", []string{"--cacheonly", "check", flagQuiet})
		b.PutCmdNotFound("rpm", append([]string{"--verify"}, []string{"bash", "coreutils", "systemd", "glibc", "openssl-libs"}...))
	})
	var pi models.PackageIntegrity
	pkgIntegrityDNF(context.Background(), &pi)
	if len(pi.BrokenPackages) != 0 || len(pi.RPMVerifyFailed) != 0 {
		t.Errorf("expected no findings on total command failure, got BrokenPackages=%v RPMVerifyFailed=%v", pi.BrokenPackages, pi.RPMVerifyFailed)
	}
	if !pi.CheckFailed {
		t.Error("expected CheckFailed=true — otherwise indistinguishable from a verified-clean system")
	}
}

// TestPkgIntegrityAPT_CheckFailed is the sibling of TestPkgIntegrityDNF_CheckFailed:
// `dpkg --audit`/`apt-get check` failing to spawn at all left BrokenPackages/
// UnmetDeps empty with no disclosure.
func TestPkgIntegrityAPT_CheckFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("dpkg", []string{"--audit"})
		b.PutCmdNotFound(pkgCmdAptGet, []string{"-s", "-o", "Debug::NoLocking=true", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "check"})
	})
	var pi models.PackageIntegrity
	pkgIntegrityAPT(context.Background(), &pi)
	if len(pi.BrokenPackages) != 0 || len(pi.UnmetDeps) != 0 {
		t.Errorf("expected no findings on total command failure, got BrokenPackages=%v UnmetDeps=%v", pi.BrokenPackages, pi.UnmetDeps)
	}
	if !pi.CheckFailed {
		t.Error("expected CheckFailed=true — otherwise indistinguishable from a verified-clean system")
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
		if name == "dnf" && len(args) > 1 && args[1] == "check" {
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
		if name == "dnf" && len(args) > 1 && args[1] == "check" {
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
