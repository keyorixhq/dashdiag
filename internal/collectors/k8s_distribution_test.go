//go:build linux

package collectors

import (
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// pathSetSource reports a fixed set of paths as present (via Stat) and everything
// else absent; lookPath always misses. Lets the on-disk distribution/kubectl
// detection be exercised without a real cluster.
type pathSetSource struct {
	source.Source
	exists map[string]bool
}

func (s pathSetSource) Stat(p string) (source.FileMeta, error) {
	if s.exists[p] {
		return source.FileMeta{}, nil
	}
	return source.FileMeta{}, errors.New("no such file or directory")
}
func (pathSetSource) Cached(string, func() ([]byte, error)) ([]byte, error) {
	return nil, errors.New("not on PATH")
}

func TestK8sDistribution(t *testing.T) {
	cases := []struct {
		name   string
		exists []string
		want   string
	}{
		{"rke2", []string{"/var/lib/rancher/rke2"}, "rke2"},
		// RKE2 also lays down /var/lib/rancher, so its marker must win over k3s.
		{"rke2 beats k3s", []string{"/var/lib/rancher/rke2", "/var/lib/rancher/k3s"}, "rke2"},
		{"k3s", []string{"/etc/rancher/k3s/k3s.yaml"}, "k3s"},
		{"kubeadm", []string{"/etc/kubernetes/manifests"}, "kubeadm"},
		{"unknown", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]bool{}
			for _, p := range tc.exists {
				m[p] = true
			}
			defer SetSource(SetSource(pathSetSource{exists: m}))
			if got := k8sDistribution(); got != tc.want {
				t.Errorf("k8sDistribution() = %q, want %q", got, tc.want)
			}
		})
	}
}

// RKE2's kubectl is off-PATH and its kubeconfig is root-only — detection must return
// the path WITH the --kubeconfig flag, or every cluster query fails (the node would
// read as "k8s not detected", as it did before this support). Validated live on real
// SLES 16 + RKE2 v1.35.6.
func TestK8sDetectBinRKE2(t *testing.T) {
	defer SetSource(SetSource(pathSetSource{exists: map[string]bool{
		"/var/lib/rancher/rke2/bin/kubectl": true,
	}}))
	want := "/var/lib/rancher/rke2/bin/kubectl --kubeconfig=/etc/rancher/rke2/rke2.yaml"
	if got := k8sDetectBin(); got != want {
		t.Errorf("k8sDetectBin() = %q, want %q", got, want)
	}
}
