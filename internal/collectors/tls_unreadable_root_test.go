package collectors

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// readDirErrSource fails ReadDir for the listed directories with err.
type readDirErrSource struct {
	source.Source
	errs map[string]error
}

func (s readDirErrSource) ReadDir(dir string) ([]string, error) {
	if err, ok := s.errs[dir]; ok {
		return nil, err
	}
	return s.Source.ReadDir(dir)
}

func withReadDirErrs(t *testing.T, errs map[string]error) {
	t.Helper()
	prev := SetSource(readDirErrSource{Source: source.NewReplay(source.NewBundle()), errs: errs})
	t.Cleanup(func() { SetSource(prev) })
}

// DD-COLLECTOR-GAPS-1 High #3: a scan root whose directory read fails (the
// Debian/Ubuntu default /etc/ssl/private is 0710) must come back as an
// Uncheckable entry, never as a silently dropped root.
func TestScanCertPath_UnreadableRootIsUncheckable(t *testing.T) {
	withReadDirErrs(t, map[string]error{
		"/etc/ssl/private": fmt.Errorf("open /etc/ssl/private: %w", os.ErrPermission),
	})
	certs, unc := scanCertPath(context.Background(), "/etc/ssl/private", time.Now())
	if len(certs) != 0 {
		t.Fatalf("certs = %+v, want none", certs)
	}
	if len(unc) != 1 || unc[0].Path != "/etc/ssl/private" || !strings.Contains(unc[0].Error, "could not read directory") {
		t.Fatalf("uncheckable = %+v, want the unreadable root", unc)
	}
	if os.Geteuid() != 0 && !unc[0].NeedsRoot {
		t.Errorf("NeedsRoot = false for a permission-denied dir seen by non-root")
	}
}

// A scan root that simply does not exist is the normal case on most hosts and
// must stay silent.
func TestScanCertPath_MissingRootIsNotAnError(t *testing.T) {
	withReadDirErrs(t, map[string]error{
		"/etc/haproxy": fmt.Errorf("open /etc/haproxy: %w", os.ErrNotExist),
	})
	certs, unc := scanCertPath(context.Background(), "/etc/haproxy", time.Now())
	if len(certs) != 0 || len(unc) != 0 {
		t.Fatalf("certs=%+v unc=%+v, want both empty for an absent root", certs, unc)
	}
}

// DD-COLLECTOR-GAPS-1 follow-up: a permission-denied subdirectory of a readable
// scan root must be reported, not mistaken for a non-cert file. probeIsDir used
// to answer false for any ReadDir error, so the walker skipped the entry.
func TestScanCertPath_UnreadableNestedSubdirIsUncheckable(t *testing.T) {
	b := source.NewBundle()
	b.PutDir("/etc/pki", []string{"tls-private"})
	prev := SetSource(readDirErrSource{
		Source: source.NewReplay(b),
		errs: map[string]error{
			"/etc/pki/tls-private": fmt.Errorf("open /etc/pki/tls-private: %w", os.ErrPermission),
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	certs, unc := scanCertPath(context.Background(), "/etc/pki", time.Now())
	if len(certs) != 0 {
		t.Fatalf("certs = %+v, want none", certs)
	}
	if len(unc) != 1 || unc[0].Path != "/etc/pki/tls-private" {
		t.Fatalf("uncheckable = %+v, want the unreadable nested directory", unc)
	}
}
