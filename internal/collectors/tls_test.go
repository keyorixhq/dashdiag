package collectors

import (
	"testing"
	"time"
)

// expiryDays must report any already-expired cert as a negative number of days,
// including one that expired less than 24h ago. int() truncation toward zero
// would otherwise round -0.x to 0, mis-classifying a down cert as "expires in 0
// days" (Expiring) instead of expired (Expired/CRIT-now).
func TestExpiryDays(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		notAfter time.Time
		want     int
	}{
		{"valid 90 days", now.Add(90 * 24 * time.Hour), 90},
		{"valid 29.5 days floors to 29", now.Add(29*24*time.Hour + 12*time.Hour), 29},
		{"expires in 6h -> 0 (still valid)", now.Add(6 * time.Hour), 0},
		{"expired 1h ago -> negative (the bug)", now.Add(-1 * time.Hour), -1},
		{"expired 23h ago -> negative (the bug)", now.Add(-23 * time.Hour), -1},
		{"expired 2 days ago", now.Add(-2 * 24 * time.Hour), -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiryDays(tc.notAfter, now); got != tc.want {
				t.Errorf("expiryDays = %d, want %d", got, tc.want)
			}
		})
	}
}

// The classification an expired-<24h cert must land in: ExpiresIn < 0 (Expired),
// never the >=0 Expiring bucket. Guards the integration with the collector's
// Expired/Expiring tally and the CRIT "expired N days ago" insight.
func TestExpiryDays_FreshlyExpiredIsNegative(t *testing.T) {
	now := time.Now()
	if d := expiryDays(now.Add(-time.Minute), now); d >= 0 {
		t.Errorf("a cert expired a minute ago must be negative, got %d", d)
	}
}
