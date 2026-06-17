package collectors

import (
	"context"
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
