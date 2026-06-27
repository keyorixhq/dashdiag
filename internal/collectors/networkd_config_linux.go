//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	info.FailedLinks = collectNetworkdFailedLinks(ctx)
	return info, nil
}

// collectNetworkdFailedLinks returns networkd-managed links whose SETUP state is
// "failed". Prefers the structured `networkctl --json=short list` (systemd 249+);
// falls back to the column output of `networkctl list`. Returns nil on any read
// error (networkctl absent / older) — the perms audit still stands on its own.
func collectNetworkdFailedLinks(ctx context.Context) []models.NetworkdLink {
	if out, err := runCmd(ctx, "networkctl", "--json=short", "list"); err == nil {
		if links := parseNetworkctlJSON(out); links != nil {
			return links
		}
	}
	out, err := runCmd(ctx, "networkctl", "list", "--no-legend")
	if err != nil {
		return nil
	}
	return parseNetworkctlColumns(out)
}

// networkctlJSON mirrors the fields of `networkctl --json=short list` we read.
type networkctlJSON struct {
	Interfaces []struct {
		Name                string `json:"Name"`
		OperationalState    string `json:"OperationalState"`
		AdministrativeState string `json:"AdministrativeState"`
	} `json:"Interfaces"`
}

// parseNetworkctlJSON returns the failed-SETUP links from --json output. Returns
// nil (not empty) on a parse error so the caller falls back to column parsing.
func parseNetworkctlJSON(out string) []models.NetworkdLink {
	var doc networkctlJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	failed := []models.NetworkdLink{}
	for _, i := range doc.Interfaces {
		if networkdSetupFailed(i.AdministrativeState) {
			failed = append(failed, models.NetworkdLink{
				Name: i.Name, Setup: i.AdministrativeState, Operational: i.OperationalState,
			})
		}
	}
	return failed
}

// parseNetworkctlColumns parses `networkctl list --no-legend` rows:
//
//	2 eth0 ether routable configured
//
// SETUP is the last field, OPERATIONAL the one before it.
func parseNetworkctlColumns(out string) []models.NetworkdLink {
	var failed []models.NetworkdLink
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		setup := f[len(f)-1]
		if networkdSetupFailed(setup) {
			failed = append(failed, models.NetworkdLink{
				Name: f[1], Setup: setup, Operational: f[len(f)-2],
			})
		}
	}
	return failed
}

// networkdSetupFailed reports whether a SETUP/AdministrativeState value means
// networkd tried and FAILED to configure the link — the unambiguous signal.
// Transient (configuring/pending) and unmanaged states are deliberately excluded
// to avoid false alarms.
func networkdSetupFailed(setup string) bool {
	return strings.EqualFold(strings.TrimSpace(setup), "failed")
}

// networkdCanRead reports whether systemd-networkd (an unprivileged dynamic user)
// can read a config file of the given mode. networkd requires the world-read bit
// (the documented requirement is mode 0644); a root-owned 0600/0640 file is
// silently ignored. The other-read bit (0004) is the deterministic failure marker.
func networkdCanRead(mode os.FileMode) bool {
	return mode.Perm()&0o004 != 0
}
