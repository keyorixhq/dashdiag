//go:build linux

package collectors

import "testing"

func TestKernelNVRAToUname(t *testing.T) {
	cases := map[string]string{
		"kernel-uek-6.12.0-203.76.7.5.el10uek.x86_64": "6.12.0-203.76.7.5.el10uek.x86_64",
		"kernel-core-5.14.0-687.17.1.el9_8.x86_64":    "5.14.0-687.17.1.el9_8.x86_64",
		"kernel-5.14.0-687.17.1.el9_8.x86_64":         "5.14.0-687.17.1.el9_8.x86_64",
		"kernel-uek-core-6.12.0-1.el10uek.x86_64":     "6.12.0-1.el10uek.x86_64",
	}
	for in, want := range cases {
		if got := kernelNVRAToUname(in); got != want {
			t.Errorf("kernelNVRAToUname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapsHasDeletedLib(t *testing.T) {
	stale := `7f0a00000000-7f0a00021000 r-xp 00000000 fd:00 1234  /usr/lib64/libc.so.6 (deleted)
7f0a00021000-7f0a00022000 r--p 00021000 fd:00 1234  /usr/lib64/libc.so.6 (deleted)`
	if !mapsHasDeletedLib(stale) {
		t.Error("a deleted system .so must be detected")
	}
	// A deleted temp file (not a .so / not a lib dir) must NOT count.
	tmp := `7f0a00000000-7f0a00021000 rw-p 00000000 fd:00 99  /tmp/scratch.dat (deleted)`
	if mapsHasDeletedLib(tmp) {
		t.Error("a deleted non-lib temp file must NOT count as a stale library")
	}
	// A live mapping (no deleted marker) must not count.
	live := `7f0a00000000-7f0a00021000 r-xp 00000000 fd:00 1234  /usr/lib64/libssl.so.3`
	if mapsHasDeletedLib(live) {
		t.Error("a current (non-deleted) mapping must not count")
	}
}

func TestCountKsplicePending(t *testing.T) {
	if got := countKsplicePending("Nothing to be done.\n"); got != 0 {
		t.Errorf("'nothing to be done' = %d, want 0", got)
	}
	if got := countKsplicePending("Your kernel is already up to date.\n"); got != 0 {
		t.Errorf("'up to date' = %d, want 0", got)
	}
	out := "Installing [abc123] CVE-2026-1.\nInstalling [def456] CVE-2026-2.\nDone.\n"
	if got := countKsplicePending(out); got != 2 {
		t.Errorf("two pending = %d, want 2", got)
	}
}
