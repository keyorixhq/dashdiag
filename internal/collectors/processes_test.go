package collectors

import (
	"os"
	"testing"
)

func TestParseProcStat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		input     string
		wantName  string
		wantState string
		wantPPID  int
		wantErr   bool
	}{
		{
			name:      "running nginx",
			input:     "1234 (nginx) S 1 1234 1234 0 -1 4194560 0 0",
			wantName:  "nginx",
			wantState: "S",
			wantPPID:  1,
		},
		{
			name:      "zombie defunct",
			input:     "5678 (defunct) Z 1234 5678 5678 0 -1 0",
			wantName:  "defunct",
			wantState: "Z",
			wantPPID:  1234,
		},
		{
			name:      "D-state uninterruptible",
			input:     "999 (kworker) D 2 999 999 0 -1 0",
			wantName:  "kworker",
			wantState: "D",
			wantPPID:  2,
		},
		{
			name:      "name with spaces",
			input:     "123 (my process) R 0 123 123 0 -1 0",
			wantName:  "my process",
			wantState: "R",
			wantPPID:  0,
		},
		{
			name:    "no parens",
			input:   "1234 nginx S 1",
			wantErr: true,
		},
		{
			name:    "too few fields after name",
			input:   "1234 (nginx) S",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "garbage",
			input:   "garbage line here",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			name, state, ppid, err := parseProcStat([]byte(tc.input))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if name != tc.wantName {
				t.Errorf("name: got %q, want %q", name, tc.wantName)
			}
			if state != tc.wantState {
				t.Errorf("state: got %q, want %q", state, tc.wantState)
			}
			if ppid != tc.wantPPID {
				t.Errorf("ppid: got %d, want %d", ppid, tc.wantPPID)
			}
		})
	}
}

func TestParseProcStat_Fixtures(t *testing.T) {
	t.Parallel()
	t.Run("running", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile("../../testdata/fixtures/processes/stat_running.txt")
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}
		name, state, ppid, err := parseProcStat(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "nginx" || state != "S" || ppid != 1 {
			t.Errorf("got name=%q state=%q ppid=%d, want nginx S 1", name, state, ppid)
		}
	})

	t.Run("zombie", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile("../../testdata/fixtures/processes/stat_zombie.txt")
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}
		name, state, ppid, err := parseProcStat(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if name != "defunct" || state != "Z" || ppid != 1234 {
			t.Errorf("got name=%q state=%q ppid=%d, want defunct Z 1234", name, state, ppid)
		}
	})
}

func FuzzParseProcStat(f *testing.F) {
	f.Add([]byte("1234 (nginx) S 1 1234 1234 0 -1 0"))
	f.Add([]byte("5678 (defunct) Z 1234 5678 5678 0 -1 0"))
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Add([]byte("123 (my process with spaces) D 0 123 123 0 -1 0"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseProcStat(data) //nolint:errcheck
	})
}
