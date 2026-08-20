//go:build linux

package collectors

// wontfix_spec_test.go — specification tests for adversarial-review findings
// closed WONT_FIX (VERIFICATION-2026-08.md §8). These pin a DECIDED
// behaviour, not a bug hunt. If one fails, either the behaviour drifted or
// the decision changed — revisit the decision (see the finding ID) before
// changing code to make it pass.
//
// internal-collectors-21-09's other half — that a protocol mismatch degrades
// to a single INFO line, never a WARN/CRIT — is already asserted by
// TestCheckMongoDB's "no metrics should be INFO" case in
// internal/analysis/heuristics_mongo_test.go, and by this package's own
// TestMongoDBCollector_Collect_EvalFails. Not duplicated here.

import "testing"

// TestSpec_InternalCollectors2109_AvailableGatesAreTCPOnly:
// internal-collectors-21-09 (MongoDB) was closed WONT_FIX because a real fix
// needs a shared per-protocol handshake helper across the ~13 service
// collectors that share this exact shape — a dedicated follow-up pass, not a
// one-file patch (see RELEASE-DECISIONS-v1.md's Option C). The census's own
// note that RabbitMQ/Kafka share the identical pattern is confirmed here,
// not just suspected: RabbitMQAvailable and KafkaAvailable are structurally
// identical to MongoDBAvailable (CLI-present check + a bare TCP dial, no
// wire-protocol handshake). Literally anything answering the connect on that
// port — a misconfigured service, a deliberately planted listener — makes
// *Available() report true. This test asserts that decided (accepted) gap:
// a dial-reachable port is sufficient, full stop, no matter what's actually
// listening.
func TestSpec_InternalCollectors2109_AvailableGatesAreTCPOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		cliKey    string
		cliPath   string
		dialKey   string
		available func() bool
	}{
		{"MongoDB", "lookpath/mongosh", "/usr/bin/mongosh", "dial/tcp/127.0.0.1:27017", MongoDBAvailable},
		{"RabbitMQ", "lookpath/rabbitmq-diagnostics", "/usr/sbin/rabbitmq-diagnostics", "dial/tcp/127.0.0.1:5672", RabbitMQAvailable},
		{"Kafka", "lookpath/kafka-topics.sh", "/opt/kafka/bin/kafka-topics.sh", "dial/tcp/127.0.0.1:9092", KafkaAvailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// withCombinedFixture calls t.Cleanup internally; not t.Parallel()
			// (shared global source, same precedent as this package's other
			// fixture-based *Available tests).
			withCombinedFixture(t, map[string][]byte{
				c.cliKey:  []byte(c.cliPath),
				c.dialKey: {'1'}, // fixture only encodes "TCP connect succeeded" — nothing about
				// what actually answered. That's the point: this collector's Available()
				// gate has no way to distinguish a real service from anything else
				// bound to the port, by design, today.
			}, nil, nil)
			if !c.available() {
				t.Errorf("%sAvailable() = false, want true — a bare successful TCP dial plus an "+
					"installed CLI is documented as sufficient (internal-collectors-21-09: no "+
					"protocol handshake at the gate)", c.name)
			}
		})
	}
}

// TestSpec_InternalCollectors1005_SecretPatternListIsNotExhaustive:
// internal-collectors-10-05 was closed WONT_FIX because secret-name-substring
// detection is fundamentally open-ended — it will always under-report some
// naming convention, and closing that fully needs entropy/content-based
// detection, materially larger scope with its own false-positive risk (this
// round only narrowed false POSITIVES, e.g. skipping trivial values). This
// test documents the accepted false-NEGATIVE side: an env var name that
// carries a real secret but doesn't contain any of secretPatterns' hardcoded
// substrings is not flagged. If this starts passing because the var got
// caught, secretPatterns grew a new substring — fine, just make sure the
// widening was deliberate, then update this test's example to a name that's
// still a genuine gap (the point isn't these two specific names, it's that
// *some* gap always exists for a substring-based list).
func TestSpec_InternalCollectors1005_SecretPatternListIsNotExhaustive(t *testing.T) {
	t.Parallel()
	knownGaps := []string{
		"GH_PAT",  // GitHub personal access token — no PASSWORD/TOKEN/SECRET/KEY/CREDENTIALS substring
		"DB_PASS", // common abbreviation — only PASSWORD/PASSWD/PWD are matched, not PASS
	}
	for _, name := range knownGaps {
		got := detectPlaintextSecrets([]string{name + "=sensitive-value-here"})
		if len(got) != 0 {
			t.Errorf("detectPlaintextSecrets flagged %q — if secretPatterns was widened to catch this "+
				"deliberately, update this test's example to a name that's still an accepted gap "+
				"(internal-collectors-10-05: the list is accepted as permanently incomplete, not a "+
				"regression target)", name)
		}
	}
	// Sanity: the function isn't simply broken — patterns it does list still fire.
	if got := detectPlaintextSecrets([]string{"DB_PASSWORD=sensitive-value-here"}); len(got) != 1 {
		t.Errorf("detectPlaintextSecrets(DB_PASSWORD=...) = %v, want exactly one match — sanity check "+
			"that the function itself still works, not just that the known gaps are gaps", got)
	}
}
