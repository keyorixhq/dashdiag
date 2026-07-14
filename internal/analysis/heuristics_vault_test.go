package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckVault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    models.VaultInfo
		want string
	}{
		{"not available is silent", models.VaultInfo{Available: false}, ""},
		{"not reachable is WARN", models.VaultInfo{Available: true, Reachable: false}, "WARN"},
		{"reachable but API unreadable is INFO", models.VaultInfo{Available: true, Reachable: true, StatusRead: false}, "INFO"},
		{"healthy vault is clean", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: false, TLSEnabled: true,
		}, ""},
		{"dev mode is CRIT", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
		}, "CRIT"},
		{"sealed is CRIT", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: true, DevMode: false, TLSEnabled: true,
		}, "CRIT"},
		{"uninitialised is WARN", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: false, Sealed: false, DevMode: false, TLSEnabled: true,
		}, "WARN"},
		{"no TLS in prod mode is WARN", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: false, TLSEnabled: false,
		}, "WARN"},
		// Dev mode suppresses the TLS warning — dev implies inmem, not a misconfiguration.
		{"dev mode suppresses TLS warn", models.VaultInfo{
			Available: true, Reachable: true, StatusRead: true,
			Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
		}, "CRIT"}, // CRIT from dev mode only, no duplicate TLS WARN
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertLevel(t, checkVault(tt.v), tt.want)
		})
	}
}

func TestCheckVaultDevModeNoTLSWarn(t *testing.T) {
	t.Parallel()
	// When DevMode is true, there must be no TLS insight — dev mode is already CRIT.
	insights := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: true,
		Initialized: true, Sealed: false, DevMode: true, TLSEnabled: false,
	})
	for _, ins := range insights {
		if ins.Level == "WARN" {
			t.Errorf("unexpected WARN in dev mode (TLS warning should be suppressed): %+v", ins)
		}
	}
}
