package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
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
	if !info.Detected || len(info.UnreadableFiles) == 0 {
		return nil
	}
	paths := make([]string, 0, len(info.UnreadableFiles))
	for _, f := range info.UnreadableFiles {
		paths = append(paths, fmt.Sprintf("%s (mode %s)", f.Path, f.Mode))
	}
	n := len(info.UnreadableFiles)
	return []models.Insight{insight("WARN", "Networkd",
		fmt.Sprintf("%d systemd-networkd config file(s) not readable by networkd (need mode 0644) — silently ignored, so the network they configure may not be applied", n),
		[]string{
			"affected: " + strings.Join(paths, ", "),
			"networkd runs as an unprivileged user and skips files without the world-read bit — no error is printed to the console",
			"to fix: chmod 644 " + info.UnreadableFiles[0].Path,
			"to verify: networkctl status",
		},
	)}
}
