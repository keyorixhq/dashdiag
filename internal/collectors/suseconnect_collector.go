package collectors

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HasSubscriptionManager returns true when this host uses any enterprise
// Linux subscription system: SUSE (SUSEConnect), RHEL/Oracle/Rocky
// (subscription-manager), or Ubuntu Pro (ubuntu-advantage-tools).
func HasSubscriptionManager() bool {
	for _, bin := range []string{
		"/usr/bin/SUSEConnect",          // SUSE / SLES
		"/usr/bin/subscription-manager", // RHEL, Oracle, Rocky, Alma
		"/usr/bin/pro",                  // Ubuntu Pro (ubuntu-advantage-tools)
	} {
		if _, err := os.Stat(bin); err == nil {
			return true
		}
	}
	return false
}

// IsSUSEHost returns true when this is a SUSE/openSUSE system.
// Used for SUSE-specific collectors (Snapper, SUSEConnect).
func IsSUSEHost() bool {
	if _, err := os.Stat("/usr/bin/SUSEConnect"); err == nil {
		return true
	}
	if _, err := os.Stat("/usr/bin/zypper"); err == nil {
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

func (c *SUSEConnectCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.SUSEConnectInfo{ExpiresDays: -1}

	// RHEL / Oracle Linux / Rocky / AlmaLinux
	if _, err := os.Stat("/usr/bin/subscription-manager"); err == nil {
		return collectRHELSubscription(ctx, info), nil
	}

	// Ubuntu Pro
	if _, err := os.Stat("/usr/bin/pro"); err == nil {
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
		info.Status = "unregistered"
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
		info.Status = "unregistered"
	default:
		info.Registered = false
		info.Status = strings.TrimSpace(out)
	}
	return info
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

	out = strings.ToLower(out)
	if strings.Contains(out, `"attached": true`) || strings.Contains(out, `"attached":true`) {
		info.Registered = true
		info.Status = "attached"
	} else {
		info.Registered = false
		info.Status = "detached"
	}
	return info
}
