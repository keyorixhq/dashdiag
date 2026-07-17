package platform

import (
	"os"
	"runtime"
	"strings"
)

// OSPrettyName returns the PRETTY_NAME field from /etc/os-release,
// falling back to runtime.GOOS if the file is absent (macOS, etc).
func OSPrettyName() string {
	if o := osIdentityOverride(); o != "" {
		return o // replay: report the captured host's OS, not the replaying box's
	}
	return osPrettyNameFromPath("/etc/os-release")
}

// osPrettyNameFromPath is the testable core of OSPrettyName.
func osPrettyNameFromPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtime.GOOS
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if after, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			val := after
			val = strings.Trim(val, `"`)
			return val
		}
	}
	return runtime.GOOS
}

// SystemLabel returns "hostname · OS" for use in command headers.
// Example: "fedora44-test · Fedora Linux 44 (Server Edition)"
func SystemLabel() string {
	return systemLabelWithHostname(os.Hostname)
}

// systemLabelWithHostname is the testable core of SystemLabel — accepts a
// hostname resolver so tests can inject errors without touching the OS.
func systemLabelWithHostname(hostnameFunc func() (string, error)) string {
	host, err := hostnameFunc()
	if err != nil {
		host = "unknown"
	}
	return host + " · " + OSPrettyName()
}
