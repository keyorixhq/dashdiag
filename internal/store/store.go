// Package store provides a time-series snapshot store for dsd health runs.
//
// The default is NullStore (no-op). JSONLStore writes append-only JSONL to
// ~/.dsd/store.jsonl (non-root) or /var/lib/dashdiag/store.jsonl (root).
// This is the local persistence layer from ADR-0001; the push-to-backend
// (--push / dashdiag.sh) is a later layer on top.
package store

import (
	"context"
	"time"
)

// Entry is one dsd health run recorded in the store.
// Fields are designed to be fleet-dashboard-ready from day one (ADR-0001):
// hostname + version carry the host identity; checks and metrics are the
// time-series values that enable drift correlation and trend reporting.
type Entry struct {
	Timestamp time.Time          `json:"ts"`
	Hostname  string             `json:"host"`
	Version   string             `json:"version"`
	Verdict   string             `json:"verdict"`              // OK | WARN | CRIT
	Checks    map[string]string  `json:"checks"`               // check name → status
	Metrics   map[string]float64 `json:"metrics,omitempty"`    // numeric trend values
}

// Store is the persistence interface for health run snapshots.
// NullStore is always safe to use as the default; callers need not nil-check.
type Store interface {
	// Append records one health run. The implementation must be safe for
	// concurrent calls from within a single process.
	Append(ctx context.Context, e Entry) error
	// History returns the last n entries for the given hostname, ordered
	// oldest-first. Returns an empty slice (not an error) when n entries
	// do not exist yet.
	History(ctx context.Context, hostname string, n int) ([]Entry, error)
	// Close flushes and releases any held resources. Callers must not use the
	// store after Close returns.
	Close() error
}

// NullStore discards every entry. It is the default so dsd stays read-only
// unless the caller explicitly opens a JSONLStore.
type NullStore struct{}

func (NullStore) Append(_ context.Context, _ Entry) error            { return nil }
func (NullStore) History(_ context.Context, _ string, _ int) ([]Entry, error) { return nil, nil }
func (NullStore) Close() error                                        { return nil }

// VerdictFromInsights derives the overall verdict string from insight levels.
// Matches the exit-code contract: CRIT > WARN > OK.
func VerdictFromInsights(levels []string) string {
	v := "OK"
	for _, l := range levels {
		switch l {
		case "CRIT":
			return "CRIT"
		case "WARN":
			if v != "CRIT" {
				v = "WARN"
			}
		}
	}
	return v
}
