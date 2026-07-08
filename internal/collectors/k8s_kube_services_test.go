package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// Characterization tests for detectKubeServices (Spec 23e). k8s.go carries no
// build tag, so these run on every OS, same as the rest of k8s_test.go.

// mockExec returns a source.Live whose Exec dispatches on (name, args) via the
// given handler, mirroring the pattern used by bind_linux_test.go.
func mockExec(handler func(name string, args []string) (source.Result, error)) source.Live {
	return source.Live{Exec: func(_ context.Context, name string, args ...string) (source.Result, error) {
		return handler(name, args)
	}}
}

func TestDetectKubeServices(t *testing.T) {
	const kubeProxyPodOut = "kube-system   kube-proxy-abc12   1/1   Running   0   3d\n"
	const svcOutPopulated = "-A KUBE-SERVICES -m comment --comment \"kube-dns\" -j KUBE-SVC-XYZ\n" +
		":KUBE-SVC-XYZ - [0:0]\n"
	const svcOutEmpty = "-A OTHER-CHAIN -j ACCEPT\n"
	const ipvsProxierLog = "I0101 00:00:00 proxier.go:123] Using ipvs Proxier\n"
	const iptablesProxierLog = "I0101 00:00:00 proxier.go:123] Using iptables Proxier\n"
	const ipvsOutPopulated = "IP Virtual Server version 1.2.1\nProt LocalAddress:Port Scheduler Flags\n" +
		"TCP  10.0.0.1:443 rr\n  -> 10.244.0.5:6443 Masq 1 0 0\n"
	const ipvsOutEmpty = "IP Virtual Server version 1.2.1\nProt LocalAddress:Port Scheduler Flags\n"

	tests := []struct {
		name           string
		handler        func(name string, args []string) (source.Result, error)
		wantChecked    bool
		wantMode       string
		wantSvcCount   int
		wantChainCount int
	}{
		{
			name: "nftables backend — mode nft, no verdict-eligible count",
			handler: func(name string, _ []string) (source.Result, error) {
				if name == "nft" {
					return source.Result{Stdout: []byte("table ip kube-proxy\n")}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked: true,
			wantMode:    "nft",
		},
		{
			name: "kube-proxy pod not found — not applicable",
			handler: func(name string, args []string) (source.Result, error) {
				if name == "nft" {
					return source.Result{}, &cmdError{name: name, code: 1}
				}
				if name == "kubectl" && len(args) > 0 && args[0] == "get" {
					return source.Result{Stdout: []byte("")}, nil // no kube-proxy pods
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked: false,
		},
		{
			name: "iptables mode populated — OK",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutPopulated)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked:    true,
			wantMode:       "iptables",
			wantSvcCount:   1,
			wantChainCount: 1,
		},
		{
			name: "iptables-save unavailable — unknown",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1} // iptables-save fails too
			},
			wantChecked: false,
		},
		{
			name: "iptables empty, ipvs mode populated — OK",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutEmpty)}, nil
				case name == "kubectl" && len(args) > 0 && args[0] == "logs":
					return source.Result{Stdout: []byte(ipvsProxierLog)}, nil
				case name == "ipvsadm":
					return source.Result{Stdout: []byte(ipvsOutPopulated)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked:  true,
			wantMode:     "ipvs",
			wantSvcCount: 1,
		},
		{
			name: "iptables empty, ipvs mode populated but 0 virtual servers — real fault, WARN-eligible",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutEmpty)}, nil
				case name == "kubectl" && len(args) > 0 && args[0] == "logs":
					return source.Result{Stdout: []byte(ipvsProxierLog)}, nil
				case name == "ipvsadm":
					return source.Result{Stdout: []byte(ipvsOutEmpty)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked:  true,
			wantMode:     "ipvs",
			wantSvcCount: 0,
		},
		{
			name: "iptables empty, ipvs mode but ipvsadm unavailable — unknown",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutEmpty)}, nil
				case name == "kubectl" && len(args) > 0 && args[0] == "logs":
					return source.Result{Stdout: []byte(ipvsProxierLog)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1} // ipvsadm fails
			},
			wantChecked: false,
			wantMode:    "ipvs",
		},
		{
			name: "iptables empty, iptables proxier — real fault, WARN-eligible",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutEmpty)}, nil
				case name == "kubectl" && len(args) > 0 && args[0] == "logs":
					return source.Result{Stdout: []byte(iptablesProxierLog)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1}
			},
			wantChecked:  true,
			wantMode:     "iptables",
			wantSvcCount: 0,
		},
		{
			name: "iptables empty, kube-proxy logs inconclusive — treated as real iptables fault",
			handler: func(name string, args []string) (source.Result, error) {
				switch {
				case name == "nft":
					return source.Result{}, &cmdError{name: name, code: 1}
				case name == "kubectl" && len(args) > 0 && args[0] == "get":
					return source.Result{Stdout: []byte(kubeProxyPodOut)}, nil
				case name == "iptables-save":
					return source.Result{Stdout: []byte(svcOutEmpty)}, nil
				}
				return source.Result{}, &cmdError{name: name, code: 1} // logs fails
			},
			wantChecked:  true,
			wantMode:     "iptables",
			wantSvcCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := SetSource(mockExec(tt.handler))
			defer SetSource(prev)

			checked, mode, svcCount, chainCount := detectKubeServices(context.Background(), "kubectl")
			if checked != tt.wantChecked {
				t.Errorf("checked = %v, want %v", checked, tt.wantChecked)
			}
			if mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", mode, tt.wantMode)
			}
			if svcCount != tt.wantSvcCount {
				t.Errorf("svcCount = %d, want %d", svcCount, tt.wantSvcCount)
			}
			if chainCount != tt.wantChainCount {
				t.Errorf("chainCount = %d, want %d", chainCount, tt.wantChainCount)
			}
		})
	}
}
