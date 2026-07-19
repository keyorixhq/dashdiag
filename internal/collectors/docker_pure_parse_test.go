package collectors

import (
	"testing"
)

// TestNormalizeArch guards the kernel-arch → OCI-arch mapping used when
// reporting image/daemon architecture.  No build tag: the function is defined
// in docker.go (linux||darwin) and the test file has no constraint, so the
// test compiles wherever docker.go compiles — including macOS CI.
func TestNormalizeArch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"x86_64", "amd64"},
		{"aarch64", "arm64"},
		{"armv7l", "arm"},
		{"armv6l", "arm"},
		{"s390x", "s390x"},
		{"ppc64le", "ppc64le"},
		{"riscv64", "riscv64"}, // unknown arch — returned as-is, lowercased
		{"X86_64", "x86_64"},   // no map hit → strings.ToLower applied
	}
	for _, c := range cases {
		if got := normalizeArch(c.in); got != c.want {
			t.Errorf("normalizeArch(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDockerExitLabel guards the human-readable exit-code labels used in
// container crash analysis.
func TestDockerExitLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code int
		want string
	}{
		{0, "clean exit"},
		{137, "OOM kill (SIGKILL)"},
		{143, "graceful shutdown (SIGTERM)"},
		{42, ""},  // unknown code → empty string
		{-1, ""}, // unknown code → empty string
	}
	for _, c := range cases {
		if got := dockerExitLabel(c.code); got != c.want {
			t.Errorf("dockerExitLabel(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// TestDetectPlaintextSecrets guards the env-var secret scanner.  The function
// inspects variable NAMES only — values are never returned.
func TestDetectPlaintextSecrets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		env  []string
		want []string
	}{
		{[]string{"DB_PASSWORD=mysecret"}, []string{"DB_PASSWORD"}},
		{[]string{"MY_TOKEN=abc"}, []string{"MY_TOKEN"}},
		{[]string{"API_KEY=key123"}, []string{"API_KEY"}},
		{[]string{"PATH=/usr/bin"}, []string{}},          // value starts with "/", skipped
		{[]string{"ENABLE_FEATURE=true"}, []string{}},    // trivial value
		{[]string{"EMPTY_SECRET="}, []string{}},           // empty value skipped
		{[]string{"MALFORMED_NO_EQUALS"}, []string{}},     // no "=" separator
		{[]string{"NORMAL_VAR=value"}, []string{}},        // no secret pattern in name
		{[]string{"DB_PASSWORD=true"}, []string{}},        // trivial value even though name matches
		{
			[]string{"A_PASSWORD=secret", "B_TOKEN=abc", "NORMAL=val"},
			[]string{"A_PASSWORD", "B_TOKEN"},
		},
	}
	for _, c := range cases {
		got := detectPlaintextSecrets(c.env)
		// Normalise nil → empty slice for comparison.
		if got == nil {
			got = []string{}
		}
		if len(got) != len(c.want) {
			t.Errorf("detectPlaintextSecrets(%v) = %v, want %v", c.env, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("detectPlaintextSecrets(%v)[%d] = %q, want %q", c.env, i, got[i], c.want[i])
			}
		}
	}
}

// TestExtractJournalMessage guards the journalctl-line parser that strips the
// timestamp/hostname prefix and truncates to 120 runes.
func TestExtractJournalMessage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want string
	}{
		{"May 19 14:05:46 host docker[123]: container exited", "container exited"},
		{"no colon separator", ""},
		{"", ""},
		{"prefix: ", ""},             // TrimSpace of empty after colon
		{"prefix:  padded message ", "padded message"}, // TrimSpace strips both ends
	}
	for _, c := range cases {
		if got := extractJournalMessage(c.line); got != c.want {
			t.Errorf("extractJournalMessage(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}
