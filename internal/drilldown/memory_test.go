package drilldown

import "testing"

func TestShortenProcessName(t *testing.T) {
	cases := []struct{ in, want string }{
		// Chrome helper nested inside two .app bundles
		{
			in:   "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/148.0/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
			want: "Google Chrome Helper (Renderer) (Google…",
		},
		// Simple .app, leaf different from app name
		{
			in:   "/Applications/iTerm.app/Contents/MacOS/iTerm2",
			want: "iTerm2 (iTerm.app)",
		},
		// App name == leaf — just show name
		{
			in:   "/Applications/Slack.app/Contents/MacOS/Slack",
			want: "Slack",
		},
		// System framework binary — no .app, use basename
		{
			in:   "/System/Library/Frameworks/CoreServices.framework/Versions/A/Support/mds_stores",
			want: "mds_stores",
		},
		{in: "dsd", want: "dsd"},
		{in: "", want: ""},
	}
	for _, c := range cases {
		got := shortenProcessName(c.in)
		if got != c.want {
			t.Errorf("shortenProcessName(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}
