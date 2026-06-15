//go:build linux

package collectors

import "testing"

func TestParseAMConfigReload(t *testing.T) {
	tests := []struct {
		name      string
		metrics   string
		wantOK    bool
		wantFound bool
	}{
		{
			name:      "success no timestamp",
			metrics:   "alertmanager_config_last_reload_successful 1",
			wantOK:    true,
			wantFound: true,
		},
		{
			name:      "failed no timestamp",
			metrics:   "alertmanager_config_last_reload_successful 0",
			wantOK:    false,
			wantFound: true,
		},
		{
			// The regression: an optional Prometheus exposition timestamp after the
			// value must NOT be read as the value. A failed reload with a timestamp
			// previously parsed as success (HasPrefix of the timestamp "17…").
			name:      "failed WITH timestamp must stay failed",
			metrics:   "alertmanager_config_last_reload_successful 0 1700000000000",
			wantOK:    false,
			wantFound: true,
		},
		{
			name:      "success WITH timestamp",
			metrics:   "alertmanager_config_last_reload_successful 1 1700000000000",
			wantOK:    true,
			wantFound: true,
		},
		{
			name: "real exposition block with HELP/TYPE comments",
			metrics: "# HELP alertmanager_config_last_reload_successful Whether the last configuration reload attempt was successful.\n" +
				"# TYPE alertmanager_config_last_reload_successful gauge\n" +
				"alertmanager_config_last_reload_successful 0\n",
			wantOK:    false,
			wantFound: true,
		},
		{
			name:      "metric absent",
			metrics:   "alertmanager_notifications_total 5\n",
			wantOK:    false,
			wantFound: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, found := parseAMConfigReload(tc.metrics)
			if ok != tc.wantOK || found != tc.wantFound {
				t.Errorf("parseAMConfigReload(%q) = (ok=%v, found=%v), want (ok=%v, found=%v)",
					tc.metrics, ok, found, tc.wantOK, tc.wantFound)
			}
		})
	}
}
