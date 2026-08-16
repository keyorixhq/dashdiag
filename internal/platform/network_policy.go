package platform

import "os"

// NetworkAllowed is the single policy decision behind every outbound network
// call dsd ever makes (cloud-metadata probe, connectivity/DNS checks, the
// GitHub update nudge, Red Hat CVE enrichment, NFS/SteamOS reachability
// probes, macOS sntp — see PRIVACY.md and docs/THREAT_MODEL.md for the full
// list). Network calls are OFF BY DEFAULT: PRIVACY.md promises "no network
// calls, ever," and until this policy existed that promise was false the
// moment any of those 8+ call sites ran with no opt-out but an undocumented
// env var — see VERIFICATION-2026-08.md gap B.
//
// Opt in with either the --network flag (root.go's PersistentPreRun sets
// DSD_ALLOW_NETWORK when it's passed, so this stays a pure env-var check —
// no leaf package needs a cobra/pflag dependency) or the DSD_ALLOW_NETWORK
// env var directly, for scripted/CI use where a flag is inconvenient to
// thread through.
//
// DSD_OFFLINE is a hard override in the opposite direction: if set, network
// is refused NO MATTER what --network/DSD_ALLOW_NETWORK say. This is a
// deliberate, security-relevant precedent — an explicit request to go
// offline must always win over a request to allow network, so a script that
// already sets DSD_OFFLINE=1 cannot be made to phone out by an environment
// that also happens to export DSD_ALLOW_NETWORK=1 (e.g. a shared CI image).
// Kept working (not removed) so nobody's existing DSD_OFFLINE=1 usage from
// before this policy existed silently starts behaving differently — the
// worst case is staying offline when network was actually fine, never the
// reverse. Document this precedence anywhere it's user-visible (--help,
// README, PRIVACY.md) — precedence that only exists in code is precedence
// nobody can rely on.
func NetworkAllowed() bool {
	if os.Getenv("DSD_OFFLINE") != "" {
		return false
	}
	return os.Getenv("DSD_ALLOW_NETWORK") != ""
}
