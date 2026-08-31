//go:build linux

package collectors

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestParseDmesgLine_ChronologicalInterleavingUnderNonUTCTZ is C3's
// demonstration+regression test.
//
// dmesg -T prints the kernel ring buffer's timestamps in the process's
// LOCAL time with no offset in the text; Go's time.Parse defaults an
// offset-less layout to UTC, so on any non-UTC host the parsed instant is
// off by the host's UTC offset from the true event time — invisible on a
// UTC-only test suite/CI box, where local time IS UTC and the bug produces
// a coincidentally correct result. Forcing time.Local to a non-UTC zone
// here is what actually exercises this class of bug rather than its
// symptom (a UTC-only run would pass either way).
//
// The known-correct interleaving: a kernel NVMe timeout (dmesg) happens
// first; 5 seconds later the dependent service's failure is logged to the
// journal. journald's __REALTIME_TIMESTAMP is always real epoch
// microseconds — TZ-immune already — so it's the fixed reference the dmesg
// event's computed timestamp must land before.
//
// This test is red against the pre-fix code (dmesg -T's ambiguous,
// offset-less format) and green against the fix (dmesg --time-format=iso,
// which carries an explicit offset dmesg itself always computes correctly
// regardless of what TZ the invoking process happens to be in).
func TestParseDmesgLine_ChronologicalInterleavingUnderNonUTCTZ(t *testing.T) {
	loc, err := time.LoadLocation("Etc/GMT+8") // fixed UTC-8, no DST — deterministic on any date
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	origLocal := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = origLocal })

	dmesgInstant := time.Date(2026, 8, 31, 9, 15, 0, 0, time.UTC)
	journalInstant := dmesgInstant.Add(5 * time.Second)

	// What a real `dmesg -x --time-format=iso` prints on a UTC-8 host: local
	// wall clock WITH the correct explicit offset (01:15:00-0800 ==
	// 09:15:00Z) — dmesg computes this offset itself, correctly, regardless
	// of what this test process's own time.Local is set to.
	dmesgLine := "kern  :err   : " + dmesgInstant.In(loc).Format("2006-01-02T15:04:05.000000-0700") +
		" nvme nvme0: I/O 0 QID 1 timeout, aborting"

	journalEntry := struct {
		RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
		Priority          string `json:"PRIORITY"`
		SyslogID          string `json:"SYSLOG_IDENTIFIER"`
		Message           string `json:"MESSAGE"`
	}{
		RealtimeTimestamp: fmt.Sprintf("%d", journalInstant.UnixMicro()),
		Priority:          "4",
		SyslogID:          "systemd",
		Message:           "dependent.service: Main process exited, code=exited",
	}
	journalJSON, err := json.Marshal(journalEntry)
	if err != nil {
		t.Fatal(err)
	}

	since := time.Unix(0, 0)    // this test is about ordering, not window filtering
	bootTime := time.Unix(0, 0) // unused by the ISO path this test exercises
	dmesgEvent := parseDmesgLine(dmesgLine, since, bootTime)
	if dmesgEvent == nil {
		t.Fatal("parseDmesgLine returned nil for a well-formed --time-format=iso line")
	}
	journalEvent := parseJournalLine(string(journalJSON))
	if journalEvent == nil {
		t.Fatal("parseJournalLine returned nil")
	}

	if dmesgEvent.TimestampUnix != dmesgInstant.Unix() {
		t.Errorf("dmesg event TimestampUnix = %d, want %d (%s) — off by %ds, the exact shape of the local-parsed-as-UTC bug (28800s = 8h under UTC-8)",
			dmesgEvent.TimestampUnix, dmesgInstant.Unix(), dmesgInstant,
			dmesgEvent.TimestampUnix-dmesgInstant.Unix())
	}
	if journalEvent.TimestampUnix != journalInstant.Unix() {
		t.Errorf("journal event TimestampUnix = %d, want %d", journalEvent.TimestampUnix, journalInstant.Unix())
	}

	// Deliberately reversed input order — the sort must correct it.
	events := []models.TimelineEvent{*journalEvent, *dmesgEvent}
	sort.Slice(events, func(i, j int) bool { return events[i].TimestampUnix < events[j].TimestampUnix })

	if events[0].Source != "dmesg" || events[1].Source != "journal" {
		t.Errorf("chronological order wrong: got %s then %s, want dmesg then journal — dmesg happened first in the real incident, and merging with journal's TZ-immune epoch timestamp must preserve that",
			events[0].Source, events[1].Source)
	}
}
