package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// K8sOSLayer "couldn't measure" disclosure (found during the pve01 root-vs-non-root
// validation of #742): KubeForwardChecked/KubeServicesChecked/CNIChecked are
// genuinely privilege-gated (iptables/nft/ipvsadm need CAP_NET_ADMIN; /etc/cni/net.d
// and /opt/cni/bin are commonly root-only) but degraded silently — identical output
// to a healthy, fully-checked node. OSLayerNeedsRoot discloses that once, rather than
// per-field. FlannelCNIUnreadable is the narrower case where /etc/cni/net.d exists
// but couldn't be listed (0700 root:root, confirmed live on a pve01 Ubuntu 24.04
// guest), silently reading FlannelInUse=false ("not flannel") instead of "unknown".

func TestOSLayerNeedsRootIsInfo(t *testing.T) {
	if got := CheckK8sOSLayer(models.K8sOSLayer{OSLayerNeedsRoot: true}); !hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
		t.Errorf("non-root deep collection must INFO, got %+v", got)
	}
	if got := CheckK8sOSLayer(models.K8sOSLayer{}); hasInsightMsg(got, "INFO", "some OS-layer checks limited") {
		t.Errorf("root run must not emit the INFO, got %+v", got)
	}
}

func TestFlannelCNIUnreadableIsInfo(t *testing.T) {
	if got := CheckK8sOSLayer(models.K8sOSLayer{FlannelCNIUnreadable: true}); !hasInsightMsg(got, "INFO", "CNI config directory not readable") {
		t.Errorf("unreadable CNI config dir must INFO, got %+v", got)
	}
	if got := CheckK8sOSLayer(models.K8sOSLayer{}); hasInsightMsg(got, "INFO", "CNI config directory not readable") {
		t.Errorf("readable CNI config dir must not emit the INFO, got %+v", got)
	}
}
