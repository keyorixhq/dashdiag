package render

import (
	"reflect"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// TestStyleForStatus covers all four named levels plus the default fallback
// (an unrecognized/OK level renders with StyleOK). lipgloss.Style has no
// exported equality helper, so compare via reflect.DeepEqual on the struct.
func TestStyleForStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		level string
		want  lipgloss.Style
	}{
		{"CRIT", StyleCrit},
		{"WARN", StyleWarn},
		{"INFO", StyleInfo},
		{"OK", StyleOK},
		{"", StyleOK},
		{"unknown", StyleOK},
	}
	for _, tc := range cases {
		if got := styleForStatus(tc.level); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("styleForStatus(%q) did not match expected style", tc.level)
		}
	}
}
