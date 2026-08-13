package collectors

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// subscriptionManagerPath returns the subscription-manager binary path, checking
// every location it ships in. RHEL 10 moved it to /usr/sbin (+ a /sbin compat
// link); older RHEL/Oracle/Rocky/Alma shipped /usr/bin. Empty string when absent.
// The old code only checked /usr/bin, so on RHEL 10 the whole Subscription
// collector was silently skipped — an EXPIRED subscription (security patches
// actually cut off) went unwarned. (Found live on EC2 RHEL 10.)
func subscriptionManagerPath() string {
	for _, p := range []string{
		"/usr/sbin/subscription-manager", // RHEL 10
		"/usr/bin/subscription-manager",  // RHEL 8/9, Oracle, Rocky, Alma
		"/sbin/subscription-manager",     // compat link
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// rhuiManaged reports whether the host gets updates via Red Hat Update
// Infrastructure (RHUI) — the PAYG model on AWS/Azure/GCP, where dnf works
// WITHOUT subscription-manager registration. On such a host "not registered" is
// NORMAL and updates are fully available, so the unregistered verdict must not
// fire (it would false-alarm on virtually every PAYG cloud RHEL image). Detected
// by the RHUI client PKI dir / repo file that all cloud RHUI images ship.
func rhuiManaged() bool {
	return fileExists("/etc/pki/rhui") ||
		fileExists("/etc/yum.repos.d/redhat-rhui.repo")
}

// HasSubscriptionManager returns true when this host uses any enterprise
// Linux subscription system: SUSE (SUSEConnect), RHEL/Oracle/Rocky
// (subscription-manager), or Ubuntu Pro (ubuntu-advantage-tools).
func HasSubscriptionManager() bool {
	if subscriptionManagerPath() != "" {
		return true
	}
	return slices.ContainsFunc([]string{
		"/usr/bin/SUSEConnect",
		"/usr/bin/pro",
	}, fileExists)
}

// IsSUSEHost returns true when this is a SUSE/openSUSE system.
// Used for SUSE-specific collectors (Snapper, SUSEConnect).
func IsSUSEHost() bool {
	if fileExists("/usr/bin/SUSEConnect") {
		return true
	}
	if fileExists("/usr/bin/zypper") {
		return true
	}
	return false
}

// SUSEConnectCollector checks enterprise Linux subscription status.
// Covers SUSE (SUSEConnect), RHEL/Oracle/Rocky (subscription-manager),
// and Ubuntu Pro (pro status). Silent no-op on unmanaged systems.
type SUSEConnectCollector struct{}

func NewSUSEConnectCollector() *SUSEConnectCollector { return &SUSEConnectCollector{} }

func (c *SUSEConnectCollector) Name() string           { return "Subscription" }
func (c *SUSEConnectCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *SUSEConnectCollector) Collect(ctx context.Context) (any, error) {
	info := &models.SUSEConnectInfo{ExpiresDays: -1}

	// RHEL / Oracle Linux / Rocky / AlmaLinux
	if subscriptionManagerPath() != "" {
		return collectRHELSubscription(ctx, info), nil
	}

	// Ubuntu Pro
	if fileExists("/usr/bin/pro") {
		return collectUbuntuPro(ctx, info), nil
	}

	// SUSE / SLES — existing logic via CollectSUSEConnect
	sec := &models.SecurityInfo{}
	CollectSUSEConnect(ctx, sec)
	info.Platform = "suse"
	info.Registered = sec.SUSEConnectRegistered
	info.ExpiresDays = sec.SUSEConnectExpiresDays
	info.Status = sec.SUSEConnectStatus
	return info, nil
}

// collectRHELSubscription checks Red Hat subscription-manager status.
func collectRHELSubscription(ctx context.Context, info *models.SUSEConnectInfo) *models.SUSEConnectInfo {
	info.Platform = "rhel"

	// subscription-manager status exits 0=subscribed, 1=unsubscribed/expired
	out, err := runCmd(ctx, "subscription-manager", "status")
	if err != nil {
		// Not registered at all
		info.Registered = false
		info.Status = unregisteredStatus()
		return info
	}

	out = strings.ToLower(out)
	switch {
	case strings.Contains(out, "current"):
		info.Registered = true
		info.Status = "current"
	case strings.Contains(out, "invalid") || strings.Contains(out, "expired"):
		info.Registered = true // registered but expired
		info.Status = "expired"
		info.ExpiresDays = 0
	case strings.Contains(out, "not registered"):
		info.Registered = false
		info.Status = unregisteredStatus()
	default:
		// Output didn't match any known pattern — don't let it read as "current"
		// (checkRHELSubscription's default case) just because nothing matched.
		info.Registered = false
		info.Status = strings.TrimSpace(out)
		info.StatusUnverified = true
	}
	return info
}

// unregisteredStatus distinguishes a host that simply isn't subscription-manager
// registered (security repos genuinely unavailable → warn) from a RHUI/PAYG cloud
// host, where "not registered" is normal and updates come from the cloud RHUI
// repos (→ no warning, or it false-alarms on every AWS/Azure/GCP RHEL image).
func unregisteredStatus() string {
	if rhuiManaged() {
		return "unregistered-rhui"
	}
	return "unregistered"
}

// collectUbuntuPro checks Ubuntu Pro (ubuntu-advantage) status.
func collectUbuntuPro(ctx context.Context, info *models.SUSEConnectInfo) *models.SUSEConnectInfo {
	info.Platform = "ubuntu-pro"

	out, err := runCmd(ctx, "pro", "status", "--format", "json")
	if err != nil {
		// pro installed but not attached
		info.Registered = false
		info.Status = "detached"
		return info
	}

	// Decode the actual JSON field rather than lowercasing the whole body and
	// substring-searching for `"attached": true` — that match was order- and
	// whitespace-fragile (a differently-formatted but semantically identical
	// document, e.g. reindented output, would silently miss) and does not
	// resolve duplicate keys the way a real JSON parser does (last value
	// wins), so it can pick up a stale/decoy occurrence instead of the
	// actual final value.
	var status struct {
		Attached bool `json:"attached"`
	}
	if jsonErr := json.Unmarshal([]byte(out), &status); jsonErr != nil {
		// `pro`'s JSON shape is not a stability-guaranteed contract. Don't
		// guess from unparseable output — disclose it as unverified rather
		// than defaulting to "detached", which would read as a confident
		// (and possibly wrong) entitlement verdict.
		info.Registered = false
		info.Status = strings.TrimSpace(out)
		info.StatusUnverified = true
		return info
	}

	info.Registered = status.Attached
	if status.Attached {
		info.Status = "attached"
	} else {
		info.Status = "detached"
	}
	return info
}
