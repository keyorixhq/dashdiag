package analysis

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeOSReleaseSource serves a fixed /etc/os-release body and returns
// os.ErrNotExist for every other path. Embedded source.Live forwards all other
// interface methods so the test binary does not need to implement the full surface.
type fakeOSReleaseSource struct {
	source.Live
	body string // content to serve at /etc/os-release
}

func (f fakeOSReleaseSource) ReadFile(path string) ([]byte, error) {
	if path == "/etc/os-release" {
		return []byte(f.body), nil
	}
	return nil, os.ErrNotExist
}

// errOSReleaseSource always returns an error for /etc/os-release.
type errOSReleaseSource struct {
	source.Live
}

func (errOSReleaseSource) ReadFile(_ string) ([]byte, error) {
	return nil, os.ErrPermission
}

// TestIsSteamOSHost covers the three isSteamOSHost() branches:
// (1) ReadFileViaSource fails → false,
// (2) ID=steamos           → true,
// (3) VARIANT_ID=steamdeck → true.
func TestIsSteamOSHost(t *testing.T) {
	// Not parallel: subtests swap global source state.
	tests := []struct {
		name string
		src  source.Source
		want bool
	}{
		{
			"error reading os-release returns false",
			errOSReleaseSource{},
			false,
		},
		{
			"ID=steamos returns true",
			fakeOSReleaseSource{body: "ID=steamos\nNAME=\"SteamOS\"\n"},
			true,
		},
		{
			"VARIANT_ID=steamdeck returns true",
			fakeOSReleaseSource{body: "ID=arch\nVARIANT_ID=steamdeck\n"},
			true,
		},
		{
			"neither ID nor VARIANT_ID match returns false",
			fakeOSReleaseSource{body: "ID=ubuntu\nVARIANT_ID=desktop\n"},
			false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel: swaps global source state.
			prev := collectors.SetSource(tt.src)
			defer collectors.SetSource(prev)

			if got := isSteamOSHost(); got != tt.want {
				t.Errorf("isSteamOSHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHostIsOstree covers the three hostIsOstree() branches:
// (1) ReadFileViaSource fails → false,
// (2) VARIANT_ID match (coreos/silverblue/kinoite/iot/sericea/onyx) → true,
// (3) ID match (fedora-coreos / rhcos) → true.
func TestHostIsOstree(t *testing.T) {
	// Not parallel: subtests swap global source state.
	tests := []struct {
		name string
		src  source.Source
		want bool
	}{
		{
			"error reading os-release returns false",
			errOSReleaseSource{},
			false,
		},
		{
			"VARIANT_ID=silverblue returns true",
			fakeOSReleaseSource{body: "ID=fedora\nVARIANT_ID=silverblue\n"},
			true,
		},
		{
			"VARIANT_ID=kinoite returns true",
			fakeOSReleaseSource{body: "ID=fedora\nVARIANT_ID=kinoite\n"},
			true,
		},
		{
			"VARIANT_ID=coreos returns true",
			fakeOSReleaseSource{body: "VARIANT_ID=coreos\n"},
			true,
		},
		{
			"VARIANT_ID=sericea returns true",
			fakeOSReleaseSource{body: "VARIANT_ID=sericea\n"},
			true,
		},
		{
			"VARIANT_ID=onyx returns true",
			fakeOSReleaseSource{body: "VARIANT_ID=onyx\n"},
			true,
		},
		{
			"VARIANT_ID=iot returns true",
			fakeOSReleaseSource{body: "VARIANT_ID=iot\n"},
			true,
		},
		{
			"ID=fedora-coreos returns true",
			fakeOSReleaseSource{body: "ID=fedora-coreos\n"},
			true,
		},
		{
			"ID=rhcos returns true",
			fakeOSReleaseSource{body: "ID=rhcos\n"},
			true,
		},
		{
			"plain Fedora workstation returns false",
			fakeOSReleaseSource{body: "ID=fedora\nVARIANT_ID=workstation\n"},
			false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel: swaps global source state.
			prev := collectors.SetSource(tt.src)
			defer collectors.SetSource(prev)

			if got := hostIsOstree(); got != tt.want {
				t.Errorf("hostIsOstree() = %v, want %v", got, tt.want)
			}
		})
	}
}
