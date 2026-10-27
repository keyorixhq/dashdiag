package source

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// globFake gives direct control over the two calls GlobChecked composes.
type globFake struct {
	Source
	matches    []string
	globErr    error
	readDirErr error
	readDirs   []string
}

func (f *globFake) Glob(string) ([]string, error) { return f.matches, f.globErr }
func (f *globFake) ReadDir(dir string) ([]string, error) {
	f.readDirs = append(f.readDirs, dir)
	return nil, f.readDirErr
}

func TestGlobParentDir(t *testing.T) {
	cases := map[string]string{
		"/etc/ssh/sshd_config.d/*.conf":       "/etc/ssh/sshd_config.d",
		"/etc/letsencrypt/live/*/cert.pem":    "/etc/letsencrypt/live",
		"/sys/class/hwmon/hwmon*/temp*_input": "/sys/class/hwmon",
		"/proc/[0-9]*/maps":                   "/proc",
		"/boot/vmlinuz-*":                     "/boot",
		"/etc/nftables.conf":                  "/etc",
		"*.crt":                               ".",
	}
	for pat, want := range cases {
		if got := GlobParentDir(pat); got != want {
			t.Errorf("GlobParentDir(%q) = %q, want %q", pat, got, want)
		}
	}
}

func TestGlobChecked_UnreadableDirIsNotEmpty(t *testing.T) {
	f := &globFake{readDirErr: fmt.Errorf("readdir: %w", os.ErrPermission)}
	m, unreadable, err := GlobChecked(f, "/etc/letsencrypt/live/*/cert.pem")
	if err != nil || len(m) != 0 || !unreadable {
		t.Fatalf("got (%v, %v, %v), want (empty, true, nil)", m, unreadable, err)
	}
	if len(f.readDirs) != 1 || f.readDirs[0] != "/etc/letsencrypt/live" {
		t.Errorf("ReadDir consulted on %v, want the literal parent /etc/letsencrypt/live", f.readDirs)
	}
}

func TestGlobChecked_EmptyReadableAndMissingAreNotUnreadable(t *testing.T) {
	for name, rerr := range map[string]error{"readable": nil, "missing": os.ErrNotExist} {
		f := &globFake{readDirErr: rerr}
		_, unreadable, err := GlobChecked(f, "/boot/vmlinuz-*")
		if err != nil || unreadable {
			t.Errorf("%s: got unreadable=%v err=%v, want false/nil", name, unreadable, err)
		}
	}
}

func TestGlobChecked_MatchesSkipReadDirAndErrorsPropagate(t *testing.T) {
	f := &globFake{matches: []string{"/boot/vmlinuz-6.1"}, readDirErr: os.ErrPermission}
	m, unreadable, err := GlobChecked(f, "/boot/vmlinuz-*")
	if err != nil || unreadable || len(m) != 1 || len(f.readDirs) != 0 {
		t.Errorf("non-empty result must not consult ReadDir: got (%v,%v,%v) readDirs=%v", m, unreadable, err, f.readDirs)
	}

	bad := errors.New("bad pattern")
	_, unreadable, err = GlobChecked(&globFake{globErr: bad}, "[")
	if !errors.Is(err, bad) || unreadable {
		t.Errorf("glob error must pass through: err=%v unreadable=%v", err, unreadable)
	}
}
