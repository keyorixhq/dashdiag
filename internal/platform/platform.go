package platform

import (
	"os"
	"runtime"
)

func IsLinux() bool { return runtime.GOOS == "linux" }
func IsMacOS() bool { return runtime.GOOS == "darwin" }

// SystemdAvailable reports whether systemd is the init system on this host.
func SystemdAvailable() bool {
	return systemdAvailableAt("/run/systemd/private")
}

// systemdAvailableAt is the testable core of SystemdAvailable.
func systemdAvailableAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
