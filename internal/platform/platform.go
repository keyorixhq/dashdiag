package platform

import (
	"os"
	"runtime"
)

func IsLinux() bool { return runtime.GOOS == "linux" }
func IsMacOS() bool { return runtime.GOOS == "darwin" }

// SystemdAvailable reports whether systemd is the init system on this host.
func SystemdAvailable() bool {
	_, err := os.Stat("/run/systemd/private")
	return err == nil
}
