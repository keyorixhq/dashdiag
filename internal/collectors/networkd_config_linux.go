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

// NetworkdAvailable reports whether the networkd collector has anything to do:
// either a config file in /etc to perm-audit, OR networkd is the active network
// manager (its config may live in /run or /usr/lib, where the link-state checks —
// failed/stuck links — still apply). Without the is-active fallback a networkd host
// that keeps no config under /etc got no link-state check at all, so a failed/stuck
// link went unreported. The collector re-confirms is-active before judging, so the
// fallback can only add coverage, never a false alarm.
func NetworkdAvailable() bool {
	for _, g := range networkdConfigGlobs {
		if m, _ := glob(networkdConfigDir + "/" + g); len(m) > 0 {
			return true
		}
	}
	return networkdIsActive()
}

// networkdIsActive reports whether systemd-networkd is the active network manager.
// Errors (no systemctl / inactive) → false, so non-systemd and NetworkManager hosts
// stay silent.
func networkdIsActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := runCmd(ctx, "systemctl", "is-active", "systemd-networkd")
	return err == nil
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

	info.FailedLinks, info.StuckLinks = classifyNetworkdLinks(collectNetworkdLinks(ctx), systemUptimeSeconds())
	return info, nil
}

// collectNetworkdLinks returns ALL networkd-tracked links. Prefers the structured
// `networkctl --json=short list` (systemd 249+); falls back to the column output of
// `networkctl list`. Returns nil on any read error (networkctl absent / older) — the
// perms audit still stands on its own.
func collectNetworkdLinks(ctx context.Context) []models.NetworkdLink {
	if out, err := runCmd(ctx, "networkctl", "--json=short", "list"); err == nil {
		if links := parseNetworkctlLinksJSON(out); links != nil {
			return links
		}
	}
	out, err := runCmd(ctx, "networkctl", "list", "--no-legend")
	if err != nil {
		return nil
	}
	return parseNetworkctlLinksColumns(out)
}

// classifyNetworkdLinks splits links into FAILED (networkd gave up applying config)
// and STUCK (still SETUP=configuring/pending long after boot — it never finished).
// The uptime gate is what makes "configuring" a real fault rather than a boot
// transient: links normally reach configured/routable within networkd-wait-online's
// ~120s window, so one still configuring well past boot is genuinely stuck.
func classifyNetworkdLinks(links []models.NetworkdLink, uptimeSec float64) (failed, stuck []models.NetworkdLink) {
	const bootSettleSec = 300 // 5 min — comfortably past wait-online's ~120s timeout
	for _, l := range links {
		switch {
		case networkdSetupFailed(l.Setup):
			failed = append(failed, l)
		case networkdSetupConfiguring(l.Setup) && uptimeSec > bootSettleSec:
			stuck = append(stuck, l)
		}
	}
	return failed, stuck
}

// networkctlJSON mirrors the fields of `networkctl --json=short list` we read.
type networkctlJSON struct {
	Interfaces []struct {
		Name                string `json:"Name"`
		OperationalState    string `json:"OperationalState"`
		AdministrativeState string `json:"AdministrativeState"`
	} `json:"Interfaces"`
}

// parseNetworkctlLinksJSON returns ALL links from --json output. Returns nil (not
// empty) on a parse error so the caller falls back to column parsing.
func parseNetworkctlLinksJSON(out string) []models.NetworkdLink {
	var doc networkctlJSON
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil
	}
	links := make([]models.NetworkdLink, 0, len(doc.Interfaces))
	for _, i := range doc.Interfaces {
		links = append(links, models.NetworkdLink{
			Name: i.Name, Setup: i.AdministrativeState, Operational: i.OperationalState,
		})
	}
	return links
}

// parseNetworkctlLinksColumns parses ALL `networkctl list --no-legend` rows:
//
//	2 eth0 ether routable configured
//
// SETUP is the last field, OPERATIONAL the one before it.
func parseNetworkctlLinksColumns(out string) []models.NetworkdLink {
	var links []models.NetworkdLink
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		links = append(links, models.NetworkdLink{
			Name: f[1], Setup: f[len(f)-1], Operational: f[len(f)-2],
		})
	}
	return links
}

// networkdSetupConfiguring reports whether a SETUP state means networkd is still
// trying to bring the link up (it hasn't reached configured/routable).
func networkdSetupConfiguring(setup string) bool {
	s := strings.ToLower(strings.TrimSpace(setup))
	return s == "configuring" || s == "pending"
}

// systemUptimeSeconds returns the host uptime from /proc/uptime (source-routed), or
// 0 if unreadable (which makes the uptime-gated stuck check conservatively skip).
func systemUptimeSeconds() float64 {
	data, err := readFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	return parseFloat(fields[0])
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
