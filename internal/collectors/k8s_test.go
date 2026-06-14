package collectors

import (
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the K8s collector's pure helpers. k8s.go is
// platform-neutral (no build tag), so these run on every OS.

func TestK8sTruncate(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exact", 5, "exact"},
		{"toolong", 4, "tool…"},
	}
	for _, tt := range tests {
		if got := k8sTruncate(tt.s, tt.n); got != tt.want {
			t.Errorf("k8sTruncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

func TestUpdatePodCounts(t *testing.T) {
	tests := []struct {
		name        string
		pod         models.K8sPodInfo
		maxRestarts int
		wantField   func(*models.K8sInfo) int
		wantValue   int
		wantCrash   bool // expect an entry in crashNames
	}{
		{
			name:        "crashloop increments CrashLooping",
			pod:         models.K8sPodInfo{Namespace: "ns", Name: "p", Status: "CrashLoopBackOff", Ready: "0/1"},
			maxRestarts: 5,
			wantField:   func(i *models.K8sInfo) int { return i.CrashLooping },
			wantValue:   1,
			wantCrash:   true, // maxRestarts >= 3
		},
		{
			name:        "crashloop under 3 restarts does not record crash name",
			pod:         models.K8sPodInfo{Namespace: "ns", Name: "p", Status: "Error", Ready: "0/1"},
			maxRestarts: 2,
			wantField:   func(i *models.K8sInfo) int { return i.CrashLooping },
			wantValue:   1,
			wantCrash:   false,
		},
		{
			name:        "pending increments Pending",
			pod:         models.K8sPodInfo{Status: "Pending"},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.Pending },
			wantValue:   1,
		},
		{
			name:        "running but 0/N increments PodsNotReady",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "0/2"},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.PodsNotReady },
			wantValue:   1,
		},
		{
			name:        "high restarts increments HighRestarts",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "1/1"},
			maxRestarts: 10,
			wantField:   func(i *models.K8sInfo) int { return i.HighRestarts },
			wantValue:   1,
		},
		{
			name:        "terminating increments Terminating",
			pod:         models.K8sPodInfo{Status: "Running", Ready: "1/1", Terminating: true},
			maxRestarts: 0,
			wantField:   func(i *models.K8sInfo) int { return i.Terminating },
			wantValue:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &models.K8sInfo{}
			crashNames := map[string]bool{}
			pod := tt.pod
			updatePodCounts(info, &pod, tt.maxRestarts, crashNames)
			if got := tt.wantField(info); got != tt.wantValue {
				t.Errorf("counter = %d, want %d", got, tt.wantValue)
			}
			if gotCrash := len(crashNames) > 0; gotCrash != tt.wantCrash {
				t.Errorf("crashNames recorded = %v, want %v (%v)", gotCrash, tt.wantCrash, crashNames)
			}
		})
	}
}

// TestCNIBinsPresentIn pins the multi-path CNI check (kubeadm /opt/cni/bin vs the
// k3s bundle) — found via live k3s validation: checking only /opt/cni/bin false-CRIT'd
// every k3s node, whose CNI plugins live under /var/lib/rancher/k3s/data/.../bin.
func TestCNIBinsPresentIn(t *testing.T) {
	dir := t.TempDir()
	kubeadm := dir + "/opt-cni-bin" // absent
	k3s := dir + "/k3s-bin"         // populated
	if err := os.MkdirAll(k3s, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k3s+"/flannel", []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// kubeadm path absent, k3s path populated → checked & ok (the k3s regression).
	if checked, ok := cniBinsPresentIn(kubeadm, k3s); !checked || !ok {
		t.Errorf("k3s bundle present: checked=%v ok=%v, want both true", checked, ok)
	}
	// Both absent → checked (we could look) but not ok (genuinely no CNI).
	if checked, ok := cniBinsPresentIn(kubeadm, dir+"/also-absent"); !checked || ok {
		t.Errorf("both absent: checked=%v ok=%v, want checked=true ok=false", checked, ok)
	}
	// A readable-but-empty dir → checked, not ok.
	empty := dir + "/empty"
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if checked, ok := cniBinsPresentIn(empty); !checked || ok {
		t.Errorf("empty dir: checked=%v ok=%v, want checked=true ok=false", checked, ok)
	}
}
