//go:build linux

package collectors

import "testing"

// Most k8s distros run containerd embedded (no host containerd.service), so detection
// must recognize each distro's bundled socket or a healthy node reads "containerd not
// active" — found live on RKE2/k0s/MicroK8s (2026-07-01). Real socket paths from the
// live nodes: k0s /run/k0s/containerd.sock, MicroK8s /var/snap/microk8s/common/run/
// containerd.sock, k3s/RKE2 /run/k3s/containerd/containerd.sock.
func TestK8sBundledContainerdSockPresent(t *testing.T) {
	cases := []struct {
		name string
		sock string
	}{
		{"k3s/rke2", "/run/k3s/containerd/containerd.sock"},
		{"k0s", "/run/k0s/containerd.sock"},
		{"microk8s", "/var/snap/microk8s/common/run/containerd.sock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer SetSource(SetSource(pathSetSource{exists: map[string]bool{tc.sock: true}}))
			if !k8sBundledContainerdSockPresent() {
				t.Errorf("%s socket %s present must count as containerd active", tc.name, tc.sock)
			}
		})
	}

	// No bundled socket → not present (a plain kubeadm node uses the host containerd.service).
	defer SetSource(SetSource(pathSetSource{exists: map[string]bool{}}))
	if k8sBundledContainerdSockPresent() {
		t.Errorf("with no bundled socket present, must return false")
	}
}
