//go:build linux

package collectors

import (
	"testing"
)

// nft list ruleset: NixOS-style input hook with default drop and an explicit
// SSH accept (services.openssh / allowedTCPPorts = [ 22 ]).
const nftDropWithSSH = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		tcp dport 22 accept
		tcp dport 80 accept
	}
}`

// nft: default-drop input, SSH not opened — locked out.
const nftDropNoSSH = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		tcp dport 80 accept
	}
}`

// nft: input hook accepts by default — everything reachable.
const nftAcceptPolicy = `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept
	}
}`

// nft: default drop, port given as service name.
const nftDropSSHName = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport ssh accept
	}
}`

// nft: default drop, SSH on a non-standard port 2222 only.
const nftDropPort2222 = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 2222 accept
	}
}`

// nft: explicit reject of SSH despite accept policy.
const nftRejectSSH = `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 22 reject
	}
}`

func TestSSHAllowedNFT(t *testing.T) {
	tests := []struct {
		name string
		out  string
		port int
		want bool
	}{
		{"drop policy with ssh accept", nftDropWithSSH, 22, true},
		{"drop policy no ssh", nftDropNoSSH, 22, false},
		{"accept policy", nftAcceptPolicy, 22, true},
		{"drop policy ssh by name", nftDropSSHName, 22, true},
		{"custom port open, asked custom", nftDropPort2222, 2222, true},
		{"custom port open, asked 22", nftDropPort2222, 22, false},
		{"explicit reject", nftRejectSSH, 22, false},
		{"empty ruleset", "", 22, true},
		// dport 22 must not match a 2222 rule when asking for 22.
		{"no false match on 2222", nftDropPort2222, 22, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sshAllowedNFT(tt.out, tt.port); got != tt.want {
				t.Errorf("sshAllowedNFT(port=%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

// iptables -L -n --line-numbers, INPUT policy DROP, SSH accepted.
const iptDropWithSSH = `Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
3    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
Chain FORWARD (policy DROP)
num  target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination`

// iptables: INPUT policy DROP, SSH not opened.
const iptDropNoSSH = `Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
Chain OUTPUT (policy ACCEPT)`

// iptables: INPUT policy ACCEPT — open.
const iptAcceptPolicy = `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)`

// iptables: NixOS scripted-firewall style — SSH accept lives in a sub-chain,
// INPUT policy is ACCEPT with a jump and trailing refuse chain.
const iptSubChain = `Chain INPUT (policy ACCEPT)
num  target            prot opt source               destination
1    nixos-fw          all  --  0.0.0.0/0            0.0.0.0/0
Chain nixos-fw (1 references)
num  target            prot opt source               destination
1    ACCEPT            tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22
2    nixos-fw-refuse   all  --  0.0.0.0/0            0.0.0.0/0`

// iptables: multiport with SSH included, under a drop policy.
const iptMultiport = `Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            multiport dports 22,80,443`

// iptables: explicit DROP of SSH.
const iptDropSSH = `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22`

func TestSSHAllowedIPT(t *testing.T) {
	tests := []struct {
		name string
		out  string
		port int
		want bool
	}{
		{"drop policy with ssh accept", iptDropWithSSH, 22, true},
		{"drop policy no ssh", iptDropNoSSH, 22, false},
		{"accept policy", iptAcceptPolicy, 22, true},
		{"ssh accept in sub-chain", iptSubChain, 22, true},
		{"multiport includes ssh", iptMultiport, 22, true},
		{"explicit drop", iptDropSSH, 22, false},
		{"empty output", "", 22, true},
		{"no false match on dpt:2222", iptDropWithSSH, 2222, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sshAllowedIPT(tt.out, tt.port); got != tt.want {
				t.Errorf("sshAllowedIPT(port=%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}
