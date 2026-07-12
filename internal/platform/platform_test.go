package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsLinuxIsMacOS(t *testing.T) {
	t.Parallel()
	if got := IsLinux(); got != (runtime.GOOS == "linux") {
		t.Errorf("IsLinux() = %v, want %v", got, runtime.GOOS == "linux")
	}
	if got := IsMacOS(); got != (runtime.GOOS == "darwin") {
		t.Errorf("IsMacOS() = %v, want %v", got, runtime.GOOS == "darwin")
	}
	// The two are mutually exclusive on any single build.
	if IsLinux() && IsMacOS() {
		t.Error("IsLinux() and IsMacOS() both true, impossible for a single GOOS")
	}
}

func TestSystemdAvailableAt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "present")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if !systemdAvailableAt(path) {
			t.Error("expected true when the systemd private socket path exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		if systemdAvailableAt(filepath.Join(dir, "absent")) {
			t.Error("expected false when the systemd private socket path is missing")
		}
	})
}

func TestSystemdAvailable_Wired(t *testing.T) {
	t.Parallel()
	// SystemdAvailable() must delegate to systemdAvailableAt with the real
	// systemd private-socket path; just confirm it doesn't panic and returns
	// a bool consistent with a direct stat of the same well-known path.
	want := systemdAvailableAt("/run/systemd/private")
	if got := SystemdAvailable(); got != want {
		t.Errorf("SystemdAvailable() = %v, want %v (wiring mismatch)", got, want)
	}
}
