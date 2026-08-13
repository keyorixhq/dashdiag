package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// K8sOSLayer "couldn't measure" disclosure (found during the pve01 root-vs-non-root
// validation of #742): KubeForwardChecked/KubeServicesChecked/CNIChecked are
// genuinely privilege-gated (iptables/nft/ipvsadm need CAP_NET_ADMIN; /etc/cni/net.d
// and /opt/cni/bin are commonly root-only) but degraded silently — identical output
// to a healthy, fully-checked node. checkK8sOSLayerCoverageGaps discloses that once,
// rather than per-field. FlannelCNIUnreadable is the narrower case where
// /etc/cni/net.d exists but couldn't be listed (0700 root:root, confirmed live on a
// pve01 Ubuntu 24.04 guest), silently reading FlannelInUse=false ("not flannel")
// instead of "unknown".

// TestUnverifiedOSLayerFieldsAreInfo covers checkK8sOSLayerCoverageGaps' actual
// signal (KubeForwardChecked/CNIChecked), not the uid==0 proxy (OSLayerNeedsRoot)
// it used to key on. Regression for the completeness-guard finding
// (TestAllChecksRegistered, checkExemptions "checkK8sOSLayerCoverageGaps"): the old
// disclosure fired only on OSLayerNeedsRoot, so a ROOT run on a tool-missing node
// (k3s's bundled iptables is off the host PATH — detectKubeForward's own doc
// comment) got ZERO disclosure, identical output to a fully-checked clean node.
func TestUnverifiedOSLayerFieldsAreInfo(t *testing.T) {
	t.Run("root run, tools missing (the bug this guards) still discloses", func(t *testing.T) {
		got := CheckK8sOSLayer(models.K8sOSLayer{OSLayerNeedsRoot: false, KubeForwardChecked: false, CNIChecked: false})
		if !hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
			t.Errorf("root run with unverified fields must INFO, got %+v", got)
		}
	})
	t.Run("non-root run where the tools succeeded anyway does not disclose", func(t *testing.T) {
		// OSLayerNeedsRoot alone (the old, now-unused signal) must not trigger
		// the disclosure — nft and /opt/cni/bin are sometimes readable without
		// root, and a non-root run that actually verified both must not read
		// as "limited".
		got := CheckK8sOSLayer(models.K8sOSLayer{OSLayerNeedsRoot: true, KubeForwardChecked: true, CNIChecked: true})
		if hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
			t.Errorf("fully-verified fields must not emit the INFO even under non-root, got %+v", got)
		}
	})
	t.Run("fully checked and root discloses nothing", func(t *testing.T) {
		got := CheckK8sOSLayer(models.K8sOSLayer{KubeForwardChecked: true, CNIChecked: true})
		if hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
			t.Errorf("fully-verified clean node must not emit the INFO, got %+v", got)
		}
	})
}

func TestFlannelCNIUnreadableIsInfo(t *testing.T) {
	if got := CheckK8sOSLayer(models.K8sOSLayer{FlannelCNIUnreadable: true}); !hasInsightMsg(got, "INFO", "CNI config directory not readable") {
		t.Errorf("unreadable CNI config dir must INFO, got %+v", got)
	}
	if got := CheckK8sOSLayer(models.K8sOSLayer{}); hasInsightMsg(got, "INFO", "CNI config directory not readable") {
		t.Errorf("readable CNI config dir must not emit the INFO, got %+v", got)
	}
}

// TestCertDirUnreadableIsInfo is the regression test for the false-OK fix:
// checkCertExpiry's candidate cert directories (kubeadm PKI, k3s tls) exist
// but couldn't be listed — commonly 0700 root-owned under a non-root deep
// run — must not read the same as "neither candidate applies to this
// distro", which also leaves CertExpiredNames/CertExpirySoon at their zero
// value and was previously indistinguishable.
func TestCertDirUnreadableIsInfo(t *testing.T) {
	got := CheckK8sOSLayer(models.K8sOSLayer{CertChecked: false, CertDirUnreadable: true})
	if !hasInsightMsg(got, "INFO", "certificate expiry could not be verified") {
		t.Errorf("unreadable cert dir must INFO, got %+v", got)
	}
	// The legitimate "neither cert dir applies to this distro" case: both
	// false, must stay silent.
	if got := CheckK8sOSLayer(models.K8sOSLayer{CertChecked: false, CertDirUnreadable: false}); hasInsightMsg(got, "INFO", "certificate expiry could not be verified") {
		t.Errorf("neither candidate applying must not emit the INFO, got %+v", got)
	}
	// A successfully-checked dir with nothing expiring must stay silent too.
	if got := CheckK8sOSLayer(models.K8sOSLayer{CertChecked: true}); hasInsightMsg(got, "INFO", "certificate expiry could not be verified") {
		t.Errorf("a successfully-checked clean cert dir must not emit the INFO, got %+v", got)
	}
}
