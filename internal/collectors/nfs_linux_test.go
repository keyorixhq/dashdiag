//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the NFS collector's pure parsers. nfsParseSource
// and nfsAuditOptions take strings/structs and return values — no network or
// syscall access. (nfsAuditOptions calls nfsCheckFstab, which reads /etc/fstab;
// the synthetic mount path below never matches a real fstab line, so only the
// option-derived warnings appear.)

func TestNFSParseSource(t *testing.T) {
	tests := []struct {
		source     string
		wantServer string
		wantExport string
	}{
		{"nfs.example.com:/data", "nfs.example.com", "/data"},
		{"10.0.0.5:/srv/share", "10.0.0.5", "/srv/share"},
		{"server:export", "server", "export"},     // no leading slash on export
		{"server", "server", "/"},                 // bare server -> root export
		{"[::1]:/export", "[::1]", "/export"},     // bracketed IPv6
		{"fe80::1:/export", "fe80::1", "/export"}, // bare IPv6 (first ":/" wins)
	}
	for _, tt := range tests {
		server, export := nfsParseSource(tt.source)
		if server != tt.wantServer || export != tt.wantExport {
			t.Errorf("nfsParseSource(%q) = (%q, %q), want (%q, %q)",
				tt.source, server, export, tt.wantServer, tt.wantExport)
		}
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestNFSAuditOptions(t *testing.T) {
	const mount = "/mnt/nfs-unit-test" // never present in a real /etc/fstab

	tests := []struct {
		name        string
		options     string
		wantWarn    string // substring that must be present ("" = none required)
		wantNotWarn string // substring that must be absent ("" = no check)
	}{
		{"soft without timeo warns", "soft,rsize=8192", "soft mount without timeo", ""},
		{"soft with timeo is fine", "soft,timeo=600,rsize=8192", "", "soft mount without timeo"},
		{"nolock warns", "rw,nolock", "nolock", ""},
		{"vers=3 warns", "vers=3,rw", "NFSv3", ""},
		{"vers=4.2 is fine", "vers=4.2,rw", "", "consider upgrading"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &models.NFSMount{Mount: mount, Server: "10.255.255.1", Options: tt.options}
			nfsAuditOptions(m)
			if tt.wantWarn != "" && !hasWarning(m.OptionsWarnings, tt.wantWarn) {
				t.Errorf("expected a warning containing %q, got %v", tt.wantWarn, m.OptionsWarnings)
			}
			if tt.wantNotWarn != "" && hasWarning(m.OptionsWarnings, tt.wantNotWarn) {
				t.Errorf("did not expect a warning containing %q, got %v", tt.wantNotWarn, m.OptionsWarnings)
			}
		})
	}
}
