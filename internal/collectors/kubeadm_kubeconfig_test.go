package collectors

import "testing"

// kubeadm copies its admin kubeconfig to /etc/kubernetes/admin.conf (root-only) but not
// to /root/.kube/config, so `sudo dsd k8s` ran bare kubectl → localhost:8080 → "API
// unreachable" on a healthy cluster (found live on a kubeadm node, 2026-07-01). The
// non-root operator path (~/.kube/config) worked and must stay untouched.
func TestKubeadmKubeconfigFlagFor(t *testing.T) {
	const flag = " --kubeconfig=/etc/kubernetes/admin.conf"
	cases := []struct {
		name           string
		euid           int
		kubeconfigEnv  string
		rootKubeExists bool
		adminConfExist bool
		want           string
	}{
		{"root, no kubeconfig, admin.conf present → use it", 0, "", false, true, flag},
		{"non-root operator → leave default (~/.kube/config)", 1000, "", false, true, ""},
		{"root but KUBECONFIG set → respect it", 0, "/x/kc", false, true, ""},
		{"root but /root/.kube/config exists → respect it", 0, "", true, true, ""},
		{"root, admin.conf missing (not kubeadm) → nothing", 0, "", false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kubeadmKubeconfigFlagFor(tc.euid, tc.kubeconfigEnv, tc.rootKubeExists, tc.adminConfExist); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
