package baseline

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestSaveSecurityBaseline_MarshalFails exercises security_baseline.go:73-75 —
// the json.MarshalIndent error path. In production this branch is unreachable
// because SecurityBaseline is a plain struct, so a marshalSecBaselineFn seam is
// used to inject the failure directly.
//
// NOT t.Parallel(): swaps the package-level marshalSecBaselineFn var.
func TestSaveSecurityBaseline_MarshalFails(t *testing.T) {
	orig := marshalSecBaselineFn
	defer func() { marshalSecBaselineFn = orig }()

	home := t.TempDir()
	t.Setenv("HOME", home)

	marshalSecBaselineFn = func(_ *SecurityBaseline) ([]byte, error) {
		return nil, fmt.Errorf("injected marshal failure")
	}

	if err := SaveSecurityBaseline(&SecurityBaseline{Hostname: "h"}); err == nil {
		t.Error("SaveSecurityBaseline should surface an injected marshal failure")
	}
}

// TestSaveSecurityBaseline_CreateTempFails_Seam exercises security_baseline.go:78-80 —
// the os.CreateTemp error path via seam injection so it is covered even when
// the test runs as root (where chmod-based approaches in mkdirfail_test.go
// cannot trigger EPERM).
//
// NOT t.Parallel(): swaps the package-level createSecBaseTempFn var.
func TestSaveSecurityBaseline_CreateTempFails_Seam(t *testing.T) {
	origCreate := createSecBaseTempFn
	defer func() { createSecBaseTempFn = origCreate }()

	home := t.TempDir()
	t.Setenv("HOME", home)

	createSecBaseTempFn = func(_ string, _ string) (*os.File, error) {
		return nil, fmt.Errorf("injected CreateTemp failure")
	}

	if err := SaveSecurityBaseline(&SecurityBaseline{Hostname: "h"}); err == nil {
		t.Error("SaveSecurityBaseline should surface an injected CreateTemp failure")
	}
}

// TestHashSSHConfigFiles_WithInjectedPath exercises security_baseline.go lines
// 139–140 (the map initialisation and path list inside hashSSHConfigFiles)
// without depending on /etc/ssh/sshd_config existing on the test host.
// It writes a real temp file and appends its path via the sshConfigExtraPaths
// seam so that the success branch (lines 151–152) is also covered.
//
// NOT t.Parallel(): swaps the package-level sshConfigExtraPaths var.
func TestHashSSHConfigFiles_WithInjectedPath(t *testing.T) {
	origExtra := sshConfigExtraPaths
	defer func() { sshConfigExtraPaths = origExtra }()

	// Write a synthetic sshd_config-like file into a temp dir.
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte("Port 22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sshConfigExtraPaths = []string{p}

	hashes := hashSSHConfigFiles()
	if hashes == nil {
		t.Fatal("hashSSHConfigFiles must return a non-nil map")
	}
	h, ok := hashes[p]
	if !ok {
		t.Fatalf("injected path %q absent from hashes: %v", p, hashes)
	}
	if len(h) != 64 {
		t.Errorf("hash for %s has length %d, want 64 (sha256 hex)", p, len(h))
	}
}
