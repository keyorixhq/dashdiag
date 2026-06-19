//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FALSE_OK_SWEEP #14 + the substring bug found live on openSUSE Leap: an
// unregistered host returns status:"Not Registered", which the old contains-
// "registered" check read as REGISTERED (silent false-OK). Parse exactly.
func TestApplySUSEConnectStatus(t *testing.T) {
	t.Run("unregistered is not registered", func(t *testing.T) {
		// Verbatim openSUSE Leap 15.6 unregistered output.
		out := `[{"identifier":"Leap","version":"15.6","arch":"aarch64","status":"Not Registered"}]`
		var info models.SecurityInfo
		applySUSEConnectStatus(out, &info)
		if info.SUSEConnectRegistered {
			t.Errorf(`"Not Registered" must NOT read as registered`)
		}
	})

	t.Run("registered with active subscription", func(t *testing.T) {
		out := `[{"identifier":"SLES","version":"15.6","arch":"x86_64","status":"Registered","subscription_status":"ACTIVE","expires_at":"2099-01-01 00:00:00 UTC"}]`
		var info models.SecurityInfo
		applySUSEConnectStatus(out, &info)
		if !info.SUSEConnectRegistered {
			t.Error("registered product must read as registered")
		}
		if info.SUSEConnectStatus != "ACTIVE" {
			t.Errorf("status = %q, want ACTIVE", info.SUSEConnectStatus)
		}
		if info.SUSEConnectExpiresDays <= 0 {
			t.Errorf("future expiry should be > 0 days, got %d", info.SUSEConnectExpiresDays)
		}
	})

	t.Run("garbled output is query-failed", func(t *testing.T) {
		var info models.SecurityInfo
		applySUSEConnectStatus("not json at all", &info)
		if info.SUSEConnectStatus != "query-failed" {
			t.Errorf("unparseable output must be query-failed, got %q", info.SUSEConnectStatus)
		}
		if info.SUSEConnectRegistered {
			t.Error("garbled output must not read as registered")
		}
	})
}
