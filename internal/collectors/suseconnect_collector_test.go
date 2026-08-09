//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestSubscriptionManagerPath_RHEL10(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/subscription-manager", source.FileMeta{})
	})
	if got := subscriptionManagerPath(); got != "/usr/sbin/subscription-manager" {
		t.Errorf("subscriptionManagerPath() = %q, want /usr/sbin/subscription-manager", got)
	}
}

func TestSubscriptionManagerPath_RHEL89(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/subscription-manager", source.FileMeta{})
	})
	if got := subscriptionManagerPath(); got != "/usr/bin/subscription-manager" {
		t.Errorf("subscriptionManagerPath() = %q, want /usr/bin/subscription-manager", got)
	}
}

func TestSubscriptionManagerPath_CompatLink(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sbin/subscription-manager", source.FileMeta{})
	})
	if got := subscriptionManagerPath(); got != "/sbin/subscription-manager" {
		t.Errorf("subscriptionManagerPath() = %q, want /sbin/subscription-manager", got)
	}
}

func TestSubscriptionManagerPath_Absent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := subscriptionManagerPath(); got != "" {
		t.Errorf("subscriptionManagerPath() = %q, want empty", got)
	}
}

func TestRhuiManaged_PKIDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/pki/rhui", source.FileMeta{})
	})
	if !rhuiManaged() {
		t.Error("rhuiManaged() = false, want true")
	}
}

func TestRhuiManaged_RepoFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/yum.repos.d/redhat-rhui.repo", source.FileMeta{})
	})
	if !rhuiManaged() {
		t.Error("rhuiManaged() = false, want true")
	}
}

func TestRhuiManaged_Neither(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if rhuiManaged() {
		t.Error("rhuiManaged() = true, want false")
	}
}

func TestHasSubscriptionManager_RHEL(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/subscription-manager", source.FileMeta{})
	})
	if !HasSubscriptionManager() {
		t.Error("HasSubscriptionManager() = false, want true")
	}
}

func TestHasSubscriptionManager_SUSE(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/SUSEConnect", source.FileMeta{})
	})
	if !HasSubscriptionManager() {
		t.Error("HasSubscriptionManager() = false, want true")
	}
}

func TestHasSubscriptionManager_UbuntuPro(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pro", source.FileMeta{})
	})
	if !HasSubscriptionManager() {
		t.Error("HasSubscriptionManager() = false, want true")
	}
}

func TestHasSubscriptionManager_None(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if HasSubscriptionManager() {
		t.Error("HasSubscriptionManager() = true, want false")
	}
}

func TestIsSUSEHost_SUSEConnect(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/SUSEConnect", source.FileMeta{})
	})
	if !IsSUSEHost() {
		t.Error("IsSUSEHost() = false, want true")
	}
}

func TestIsSUSEHost_Zypper(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/zypper", source.FileMeta{})
	})
	if !IsSUSEHost() {
		t.Error("IsSUSEHost() = false, want true")
	}
}

func TestIsSUSEHost_Neither(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if IsSUSEHost() {
		t.Error("IsSUSEHost() = true, want false")
	}
}

func TestSUSEConnectCollectorIdentity(t *testing.T) {
	c := NewSUSEConnectCollector()
	if c == nil {
		t.Fatal("NewSUSEConnectCollector returned nil")
	}
	if c.Name() != "Subscription" {
		t.Errorf("Name() = %q, want Subscription", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

func TestUnregisteredStatus_RHUI(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/pki/rhui", source.FileMeta{})
	})
	if got := unregisteredStatus(); got != "unregistered-rhui" {
		t.Errorf("unregisteredStatus() = %q, want unregistered-rhui", got)
	}
}

func TestUnregisteredStatus_Plain(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := unregisteredStatus(); got != "unregistered" {
		t.Errorf("unregisteredStatus() = %q, want unregistered", got)
	}
}

func TestCollectRHELSubscription_Current(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("subscription-manager", []string{"status"}, "Overall Status: Current\n", 0)
	})
	info := &models.SUSEConnectInfo{}
	collectRHELSubscription(context.Background(), info)
	if info.Platform != "rhel" || !info.Registered || info.Status != "current" {
		t.Errorf("info = %+v, want rhel/registered=true/current", info)
	}
}

func TestCollectRHELSubscription_Expired(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("subscription-manager", []string{"status"}, "Overall Status: Invalid\n", 0)
	})
	info := &models.SUSEConnectInfo{ExpiresDays: -1}
	collectRHELSubscription(context.Background(), info)
	if !info.Registered || info.Status != "expired" || info.ExpiresDays != 0 {
		t.Errorf("info = %+v, want registered=true/expired/0", info)
	}
}

func TestCollectRHELSubscription_NotRegisteredExplicit(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("subscription-manager", []string{"status"}, "Overall Status: Not Registered\n", 0)
	})
	info := &models.SUSEConnectInfo{}
	collectRHELSubscription(context.Background(), info)
	if info.Registered || info.Status != "unregistered" {
		t.Errorf("info = %+v, want registered=false/unregistered", info)
	}
}

func TestCollectRHELSubscription_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("subscription-manager", []string{"status"})
	})
	info := &models.SUSEConnectInfo{}
	collectRHELSubscription(context.Background(), info)
	if info.Registered || info.Status != "unregistered" {
		t.Errorf("info = %+v, want registered=false/unregistered", info)
	}
}

func TestCollectRHELSubscription_UnknownOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("subscription-manager", []string{"status"}, "Some Weird Future Status\n", 0)
	})
	info := &models.SUSEConnectInfo{}
	collectRHELSubscription(context.Background(), info)
	if info.Registered || info.Status != "some weird future status" {
		t.Errorf("info = %+v, want registered=false/'some weird future status'", info)
	}
	// The raw text landed in Status unparsed — StatusUnverified must be set so
	// analysis doesn't read this as a silent "current" via its default case.
	if !info.StatusUnverified {
		t.Errorf("info = %+v, want StatusUnverified=true for unrecognized output", info)
	}
}

// TestCollectRHELSubscription_Current_NotUnverified guards the inverse: a
// cleanly-matched "current" status must NOT set StatusUnverified.
func TestCollectRHELSubscription_Current_NotUnverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("subscription-manager", []string{"status"}, "Overall Status: Current\n", 0)
	})
	info := &models.SUSEConnectInfo{}
	collectRHELSubscription(context.Background(), info)
	if info.StatusUnverified {
		t.Errorf("info = %+v, want StatusUnverified=false for a cleanly-parsed 'current' status", info)
	}
}

func TestCollectUbuntuPro_Attached(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pro", []string{"status", "--format", "json"}, `{"attached": true}`, 0)
	})
	info := &models.SUSEConnectInfo{}
	collectUbuntuPro(context.Background(), info)
	if info.Platform != "ubuntu-pro" || !info.Registered || info.Status != "attached" {
		t.Errorf("info = %+v, want ubuntu-pro/registered=true/attached", info)
	}
}

func TestCollectUbuntuPro_AttachedNoSpace(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pro", []string{"status", "--format", "json"}, `{"attached":true}`, 0)
	})
	info := &models.SUSEConnectInfo{}
	collectUbuntuPro(context.Background(), info)
	if !info.Registered || info.Status != "attached" {
		t.Errorf("info = %+v, want registered=true/attached", info)
	}
}

func TestCollectUbuntuPro_Detached(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pro", []string{"status", "--format", "json"}, `{"attached": false}`, 0)
	})
	info := &models.SUSEConnectInfo{}
	collectUbuntuPro(context.Background(), info)
	if info.Registered || info.Status != "detached" {
		t.Errorf("info = %+v, want registered=false/detached", info)
	}
}

func TestCollectUbuntuPro_NotAttached(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pro", []string{"status", "--format", "json"})
	})
	info := &models.SUSEConnectInfo{}
	collectUbuntuPro(context.Background(), info)
	if info.Registered || info.Status != "detached" {
		t.Errorf("info = %+v, want registered=false/detached", info)
	}
}

func TestSUSEConnectCollector_Collect_RHEL(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/subscription-manager", source.FileMeta{})
		b.PutCmd("subscription-manager", []string{"status"}, "Overall Status: Current\n", 0)
	})
	c := NewSUSEConnectCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SUSEConnectInfo)
	if info.Platform != "rhel" || !info.Registered || info.Status != "current" {
		t.Errorf("info = %+v, want rhel/registered=true/current", info)
	}
}

func TestSUSEConnectCollector_Collect_UbuntuPro(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pro", source.FileMeta{})
		b.PutCmd("pro", []string{"status", "--format", "json"}, `{"attached": true}`, 0)
	})
	c := NewSUSEConnectCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SUSEConnectInfo)
	if info.Platform != "ubuntu-pro" || !info.Registered {
		t.Errorf("info = %+v, want ubuntu-pro/registered=true", info)
	}
}

func TestSUSEConnectCollector_Collect_SUSEFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// Neither subscription-manager nor pro present -> falls to CollectSUSEConnect,
		// which itself gates on lookPath("SUSEConnect") (unseeded here -> not found).
	})
	c := NewSUSEConnectCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SUSEConnectInfo)
	if info.Platform != "suse" {
		t.Errorf("Platform = %q, want suse", info.Platform)
	}
}
