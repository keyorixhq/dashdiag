//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// A scrub running right now must read as "scrubbed today" (age 0), not the
// "never scrubbed" default — otherwise dsd WARNs during a scheduled scrub.
func TestMergeZpoolStatusScrubInProgress(t *testing.T) {
	t.Parallel()
	pools := map[string]models.ZFSPool{"tank": {Name: "tank", ScrubAgeDays: -1}}
	const status = `  pool: tank
 state: ONLINE
  scan: scrub in progress since Sun Jun  8 02:00:01 2026
	1.20T scanned at 2.50G/s, 800G issued at 1.60G/s, 4.00T total

config:
	NAME        STATE     READ WRITE CKSUM
	tank        ONLINE       0     0     0

errors: No known data errors`
	mergeZpoolStatus(status, pools)
	if got := pools["tank"].ScrubAgeDays; got != 0 {
		t.Errorf("scrub-in-progress ScrubAgeDays = %d, want 0 (healthy, scrubbing now)", got)
	}
}

func TestParseZFSVdevErrors(t *testing.T) {
	t.Parallel()

	// Real-ish `zpool status` config section with a faulted disk carrying a
	// trailing note and an abbreviated checksum count — the cases the old
	// last-3-fields read silently dropped.
	const status = `  pool: tank
 state: DEGRADED
config:

	NAME        STATE     READ WRITE CKSUM
	tank        DEGRADED     0     0     0
	  mirror-0  DEGRADED     0     0     0
	    sda     ONLINE       0     0     0
	    sdb     FAULTED      0     2  1.5K  too many errors
	    sdc     ONLINE       0     0     0  (resilvering)

errors: No known data errors`

	r, w, c := parseZFSVdevErrors(status)
	// write: 0+0+0+2+0 = 2 ; cksum: 0+0+0+1500+0 = 1500 (summed across the pool,
	// mirror and leaf lines as before — only the parsing was fixed).
	if w != 2 {
		t.Errorf("write errors: got %d, want 2", w)
	}
	if c != 1500 {
		t.Errorf("cksum errors: got %d, want 1500", c)
	}
	if r != 0 {
		t.Errorf("read errors: got %d, want 0", r)
	}
}

func TestParseZFSVdevErrorsHealthy(t *testing.T) {
	t.Parallel()
	const status = `	NAME        STATE     READ WRITE CKSUM
	tank        ONLINE       0     0     0
	  sda       ONLINE       0     0     0`
	r, w, c := parseZFSVdevErrors(status)
	if r != 0 || w != 0 || c != 0 {
		t.Errorf("healthy pool: got %d/%d/%d, want 0/0/0", r, w, c)
	}
}

func TestParseZFSScrubAgeParsesYear(t *testing.T) {
	t.Parallel()
	// Modern OpenZFS scrub line: the date after "on" is five tokens incl. the
	// year. The old i+1:i+5 slice dropped the year and always returned -1.
	const status = `  scan: scrub repaired 0B in 00:04:30 with 0 errors on Sun Jun  1 03:28:31 2020`
	got := parseZFSScrubAge(status)
	if got < 0 {
		t.Fatalf("scrub age: got %d (parse failed), want a positive day count", got)
	}
	// 2020 is years in the past relative to any plausible test clock.
	if got < 1000 {
		t.Errorf("scrub age: got %d days, want a large positive (date is in 2020)", got)
	}
}

func TestParseZFSScrubAgeNever(t *testing.T) {
	t.Parallel()
	const status = `  scan: none requested`
	if got := parseZFSScrubAge(status); got != -1 {
		t.Errorf("never-scrubbed: got %d, want -1", got)
	}
}
