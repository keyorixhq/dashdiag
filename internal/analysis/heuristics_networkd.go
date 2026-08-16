package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	nwdCatNetworkd = "Networkd"
	nwdPfxAffected = "affected: "
)

// checkNetworkdConfig flags systemd-networkd config files that networkd cannot
// read. networkd runs as an unprivileged dynamic user and silently ignores any
// .network/.link/.netdev file lacking the world-read bit (the documented
// requirement is mode 0644), leaving the interface it configures unconfigured —
// a no-network state with no error on the console. Emitted as WARN: the file is
// definitively ignored, but we can't prove from perms alone that it was the file
// the host needed. VMware Photon OS (networkd by default, root-created 0600 files)
// is the prime victim — a documented Photon footgun.
func checkNetworkdConfig(info models.NetworkdConfigInfo) []models.Insight {
	if !info.Detected {
		return nil
	}
	var out []models.Insight

	// cmd-04-05 and its untagged siblings in this file (found sweeping for
	// the same pattern): file paths and link names below are spliced
	// unescaped into copy-pasteable shell hints; validate each before use,
	// same looksLikeSafeToken guard diskGrowthHints applies for filesystem
	// device/mount names.
	if len(info.UnreadableFiles) > 0 {
		paths := make([]string, 0, len(info.UnreadableFiles))
		for _, f := range info.UnreadableFiles {
			paths = append(paths, fmt.Sprintf("%s (mode %s)", f.Path, f.Mode))
		}
		chmodHint := "to fix: file path withheld — contains unexpected characters"
		if looksLikeSafeToken(info.UnreadableFiles[0].Path) {
			chmodHint = "to fix: chmod 644 " + info.UnreadableFiles[0].Path
		}
		out = append(out, insight("WARN", nwdCatNetworkd,
			fmt.Sprintf("%d systemd-networkd config file(s) not readable by networkd (need mode 0644) — silently ignored, so the network they configure may not be applied", len(info.UnreadableFiles)),
			[]string{
				nwdPfxAffected + strings.Join(paths, ", "),
				"networkd runs as an unprivileged user and skips files without the world-read bit — no error is printed to the console",
				chmodHint,
				"to verify: networkctl status",
			},
		))
	}

	if len(info.FailedLinks) > 0 {
		names := make([]string, 0, len(info.FailedLinks))
		for _, l := range info.FailedLinks {
			names = append(names, fmt.Sprintf("%s (operational: %s)", l.Name, l.Operational))
		}
		safeLinkName := "<link>"
		if looksLikeSafeToken(info.FailedLinks[0].Name) {
			safeLinkName = info.FailedLinks[0].Name
		}
		out = append(out, insight("WARN", nwdCatNetworkd,
			fmt.Sprintf("%d systemd-networkd link(s) failed to configure (SETUP=failed) — the network config did not apply", len(info.FailedLinks)),
			[]string{
				nwdPfxAffected + strings.Join(names, ", "),
				"networkd accepted the link's config but could not apply it (bad directive, conflicting address/route, or an ignored config file)",
				"to inspect: networkctl status " + safeLinkName,
				"to reload after a fix: networkctl reload && networkctl reconfigure " + safeLinkName,
			},
		))
	}

	if len(info.StuckLinks) > 0 {
		names := make([]string, 0, len(info.StuckLinks))
		for _, l := range info.StuckLinks {
			names = append(names, fmt.Sprintf("%s (operational: %s)", l.Name, l.Operational))
		}
		safeStuckLinkName := "<link>"
		if looksLikeSafeToken(info.StuckLinks[0].Name) {
			safeStuckLinkName = info.StuckLinks[0].Name
		}
		out = append(out, insight("WARN", nwdCatNetworkd,
			fmt.Sprintf("%d systemd-networkd link(s) stuck in SETUP=configuring long after boot — never reached configured/routable", len(info.StuckLinks)),
			[]string{
				nwdPfxAffected + strings.Join(names, ", "),
				"networkd is still trying to bring the link up (common causes: no DHCP offer, or an address/route it can't apply)",
				"to inspect: networkctl status " + safeStuckLinkName,
				"to inspect: journalctl -u systemd-networkd -b --no-pager | tail -50",
			},
		))
	}

	return out
}
