package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOSPrettyNameFromPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("has pretty name", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "with-pretty")
		content := "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := osPrettyNameFromPath(path); got != "Ubuntu 24.04 LTS" {
			t.Errorf("osPrettyNameFromPath = %q, want Ubuntu 24.04 LTS", got)
		}
	})

	t.Run("missing pretty name falls back to GOOS", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "no-pretty")
		if err := os.WriteFile(path, []byte("NAME=\"Foo\"\nID=foo\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := osPrettyNameFromPath(path); got != runtime.GOOS {
			t.Errorf("osPrettyNameFromPath(no PRETTY_NAME) = %q, want %q", got, runtime.GOOS)
		}
	})

	t.Run("file absent falls back to GOOS", func(t *testing.T) {
		t.Parallel()
		if got := osPrettyNameFromPath(filepath.Join(dir, "does-not-exist")); got != runtime.GOOS {
			t.Errorf("osPrettyNameFromPath(absent) = %q, want %q", got, runtime.GOOS)
		}
	})
}

// TestOSPrettyName_Override and TestSystemLabel both mutate the package-level
// identity override (SetIdentity) that TestSetIdentity in identity_test.go also
// mutates. That shared mutable state (guarded by a mutex for data-race safety,
// but not for logical isolation) makes these tests order-sensitive against each
// other, so — matching the existing convention in identity_test.go — they do NOT
// call t.Parallel(): Go runs non-parallel tests to completion one at a time,
// which is what keeps the override read-after-write assertions deterministic.
func TestOSPrettyName_Override(t *testing.T) {
	restore := SetIdentity("", "Overridden OS")
	defer restore()
	if got := OSPrettyName(); got != "Overridden OS" {
		t.Errorf("OSPrettyName() under override = %q, want Overridden OS", got)
	}
}

// TestOSPrettyName_RealPath is a smoke test for the production wrapper's
// non-override branch: it reads the real /etc/os-release on whatever host
// runs the suite. Matching TestOSPrettyName_Override/TestSystemLabel (which
// mutate the same package-level identity override), it does NOT call
// t.Parallel() so it can't race with them over hostOverride/osOverride.
func TestOSPrettyName_RealPath(t *testing.T) {
	restore := SetIdentity("", "") // ensure no override leaks in from another test
	defer restore()
	got := OSPrettyName()
	if got == "" {
		t.Error("OSPrettyName() (no override) returned empty string, want a value")
	}
}

func TestSystemLabelWithHostname_Error(t *testing.T) {
	t.Parallel()
	restore := SetIdentity("", "TestOS")
	defer restore()
	failHostname := func() (string, error) { return "", errors.New("hostname unavailable") }
	got := systemLabelWithHostname(failHostname)
	if !strings.HasPrefix(got, "unknown · ") {
		t.Errorf("systemLabelWithHostname(error) = %q, want prefix \"unknown · \"", got)
	}
}

func TestSystemLabel(t *testing.T) {
	liveHost, _ := os.Hostname()

	// SystemLabel reads os.Hostname() live (not the identity override), but
	// OSPrettyName() honors SetIdentity — pin that half for a deterministic assert.
	restore := SetIdentity("", "Test OS 9000")
	defer restore()

	got := SystemLabel()
	want := liveHost + " · Test OS 9000"
	if got != want {
		t.Errorf("SystemLabel() = %q, want %q", got, want)
	}
	if !strings.Contains(got, " · ") {
		t.Errorf("SystemLabel() = %q, want it to contain ' · ' separator", got)
	}
}
