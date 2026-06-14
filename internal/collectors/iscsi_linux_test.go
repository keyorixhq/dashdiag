//go:build linux

package collectors

import (
	"strings"
	"testing"
)

// Verbatim `iscsiadm -m session -P 1` output (from the live 2-portal LIO rig), with
// the second portal edited to FAILED to exercise failure detection. The old parser
// read the stateless `-m session` form and hardcoded LOGGED_IN, so FailedCount could
// never increment.
const iscsiSessionP1 = `Target: iqn.2026-06.test.dsd:tgt0 (non-flash)
	Current Portal: 192.168.10.69:3260,1
		iSCSI Connection State: LOGGED IN
		iSCSI Session State: LOGGED_IN
		Internal iscsid Session State: NO CHANGE
	Current Portal: 127.0.0.1:3260,1
		iSCSI Connection State: TRANSPORT WAIT
		iSCSI Session State: FAILED
		Internal iscsid Session State: RECONNECT
`

func TestParseISCSISessionsP1(t *testing.T) {
	s := parseISCSISessions(iscsiSessionP1)
	if len(s) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(s), s)
	}
	if s[0].Portal != "192.168.10.69:3260" || strings.ToUpper(s[0].State) != "LOGGED_IN" {
		t.Errorf("session 0 = %+v, want portal 192.168.10.69:3260 LOGGED_IN", s[0])
	}
	if s[1].Portal != "127.0.0.1:3260" || strings.ToUpper(s[1].State) != "FAILED" {
		t.Errorf("session 1 = %+v, want portal 127.0.0.1:3260 FAILED", s[1])
	}
	for _, x := range s {
		if x.Target != "iqn.2026-06.test.dsd:tgt0" {
			t.Errorf("target = %q", x.Target)
		}
	}
	// Failure counting (mirrors Collect): exactly one non-LOGGED_IN session.
	failed := 0
	for _, x := range s {
		if strings.ToUpper(x.State) != "LOGGED_IN" {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed count = %d, want 1", failed)
	}
}
