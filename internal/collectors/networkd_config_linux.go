//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// NetworkdConfigCollector audits systemd-networkd config-file permissions. It is
// a sharp, deterministic check for a documented Photon OS footgun: networkd runs
// as an unprivileged dynamic user and silently ignores any config file lacking
// the world-read bit, so a root-created 0600 .network file leaves its interface
// unconfigured with no error on the console.
type NetworkdConfigCollector struct{}

func NewNetworkdConfigCollector() *NetworkdConfigCollector { return &NetworkdConfigCollector{} }

func (c *NetworkdConfigCollector) Name() string           { return "Networkd" }
func (c *NetworkdConfigCollector) Timeout() time.Duration { return 3 * time.Second }

// networkdConfigDir is where systemd-networkd reads its config files.
const networkdConfigDir = "/etc/systemd/network"

// networkdConfigGlobs covers all three systemd-networkd config file types.
var networkdConfigGlobs = []string{"*.network", "*.link", "*.netdev"}

// NetworkdAvailable reports whether there is any systemd-networkd config file to
// audit. Cheap, file-only gate (the collector confirms networkd is the *active*
// manager before judging — a wrong-perm file is harmless if networkd isn't the
// one reading it).
func NetworkdAvailable() bool {
	for _, g := range networkdConfigGlobs {
		if m, _ := glob(networkdConfigDir + "/" + g); len(m) > 0 {
			return true
		}
	}
	return false
}

func (c *NetworkdConfigCollector) Collect(ctx context.Context) (interface{}, error) {
	// Only meaningful when systemd-networkd is the active network manager.
	if _, err := runCmd(ctx, "systemctl", "is-active", "systemd-networkd"); err != nil {
		return &models.NetworkdConfigInfo{Detected: false}, nil
	}

	info := &models.NetworkdConfigInfo{Detected: true}
	for _, g := range networkdConfigGlobs {
		matches, _ := glob(networkdConfigDir + "/" + g)
		for _, path := range matches {
			info.TotalFiles++
			meta, err := statFile(path)
			if err != nil {
				continue
			}
			if !networkdCanRead(meta.Mode) {
				info.UnreadableFiles = append(info.UnreadableFiles, models.NetworkdConfigFile{
					Path: path,
					Mode: fmt.Sprintf("%04o", meta.Mode.Perm()),
				})
			}
		}
	}
	return info, nil
}

// networkdCanRead reports whether systemd-networkd (an unprivileged dynamic user)
// can read a config file of the given mode. networkd requires the world-read bit
// (the documented requirement is mode 0644); a root-owned 0600/0640 file is
// silently ignored. The other-read bit (0004) is the deterministic failure marker.
func networkdCanRead(mode os.FileMode) bool {
	return mode.Perm()&0o004 != 0
}
