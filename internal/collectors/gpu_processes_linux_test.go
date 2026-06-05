//go:build linux

package collectors

import "testing"

// TestParseGPUProcessesEmptyMem guards against the index-out-of-range panic when
// nvidia-smi reports an empty/[N/A] used_memory (MIG / vGPU / no accounting).
func TestParseGPUProcessesEmptyMem(t *testing.T) {
	t.Parallel()
	// noheader,nounits CSV; second row has a blank memory column.
	out := "1234, 6823, python\n" +
		"5678, , gunicorn\n" +
		"9012, [N/A], ollama\n"

	got := parseGPUProcesses(out) // must not panic
	if len(got) != 3 {
		t.Fatalf("process count: got %d, want 3", len(got))
	}
	if got[0].MemUseMB != 6823 {
		t.Errorf("proc[0] mem: got %d, want 6823", got[0].MemUseMB)
	}
	if got[1].MemUseMB != 0 || got[1].Name != "gunicorn" {
		t.Errorf("proc[1]: got mem=%d name=%q, want 0/gunicorn", got[1].MemUseMB, got[1].Name)
	}
	if got[2].MemUseMB != 0 || got[2].Name != "ollama" {
		t.Errorf("proc[2]: got mem=%d name=%q, want 0/ollama", got[2].MemUseMB, got[2].Name)
	}
}
