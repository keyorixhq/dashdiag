package platform

import (
	"os"
	"runtime"
	"strings"
)

// OSPrettyName returns the PRETTY_NAME field from /etc/os-release,
// falling back to runtime.GOOS if the file is absent (macOS, etc).
func OSPrettyName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			val := strings.TrimPrefix(line, "PRETTY_NAME=")
			val = strings.Trim(val, `"`)
			return val
		}
	}
	return runtime.GOOS
}

// SystemLabel returns "hostname · OS" for use in command headers.
// Example: "fedora44-test · Fedora Linux 44 (Server Edition)"
func SystemLabel() string {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return host + " · " + OSPrettyName()
}
