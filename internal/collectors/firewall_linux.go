//go:build linux

package collectors

import (
	"bufio"
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// sbinToolPath reports whether a tool that commonly lives in an sbin directory
// (nft, iptables, …) is installed, returning its resolved path or "". It is a
// DETECTION gate, not an exec path: callers invoke the tool by bare name so the
// capture/replay command key stays stable. It tries $PATH first (lookPath), then
// the standard sbin locations — which matters for unprivileged runs, where
// /usr/sbin and /sbin are typically absent from $PATH, so a plain lookPath miss
// would make the caller wrongly conclude the tool is "not installed" instead of
// "installed but needs root to read". Both component reads are source-routed
// (lookPath + fileExists), so capture/replay stays hermetic.
func sbinToolPath(name string) string {
	if p, err := lookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
		cand := filepath.Join(dir, name)
		if fileExists(cand) {
			return cand
		}
	}
	return ""
}

type FirewallCollector struct{}

func NewFirewallCollector() *FirewallCollector      { return &FirewallCollector{} }
func (c *FirewallCollector) Name() string           { return "Firewall" }
func (c *FirewallCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *FirewallCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.FirewallInfo{}

	// Prefer nftables (modern), fall back to iptables. Both helpers mutate
	// info in place; their (info, nil) return is kept only for the callers
	// in the security collector that reuse the same parsing.
	switch {
	case sbinToolPath("nft") != "":
		_, _ = collectNFTables(ctx, info)
	case sbinToolPath("iptables") != "":
		_, _ = collectIPTables(ctx, info)
	default:
		// No firewall userspace tooling found on $PATH or in the standard sbin
		// dirs (minimal container/image). We cannot read the kernel's netfilter
		// state, so report it unverified rather than let !Available pass as a
		// silent "no firewall problems".
		info.Status = "unverified"
		info.StatusReason = "no firewall tooling (nft/iptables) found — firewall state not verified"
	}

	// On Proxmox VE the host firewall is managed by pve-firewall, which loads
	// its nftables/iptables rules dynamically. An empty base ruleset is not
	// "unprotected" when pve-firewall is the active manager (see BUG-017).
	if IsPVEHost() && pveFirewallActive(ctx) {
		info.PVEFirewallActive = true
	}

	// On a cloud guest (AWS/Azure/GCP) the network firewall is the provider's
	// Security Group / NSG / VPC rules — a layer dsd cannot read from inside the
	// instance. Record that so the heuristic does not assert "host unprotected"
	// on an empty host ruleset (a false alarm that reads as cloud-naive). DMI-only
	// detection: cheap, no root, no IMDS round-trip.
	if p := cloudGuestProvider(); p != "" {
		info.CloudGuest = true
		info.CloudProvider = p
	}
	return info, nil
}

// cloudGuestProvider returns "aws"/"azure"/"gcp" if this host is a detected cloud
// VM, else "". Uses the existing DMI-based guest gates (no IMDS, no privilege).
func cloudGuestProvider() string {
	switch {
	case AWSGuestAvailable():
		return "aws"
	case AzureGuestAvailable():
		return "azure"
	case GCPGuestAvailable():
		return "gcp"
	default:
		return ""
	}
}

// lookPathOK reports whether a binary is found on PATH.
func lookPathOK(bin string) bool {
	_, err := lookPath(bin)
	return err == nil
}

// pveFirewallActive reports whether the Proxmox pve-firewall service is active.
// `systemctl is-active` exits 0 and prints "active" only when the unit is running.
func pveFirewallActive(ctx context.Context) bool {
	out, err := runCmd(ctx, "systemctl", "is-active", "pve-firewall")
	return err == nil && strings.TrimSpace(out) == "active"
}

func collectNFTables(ctx context.Context, info *models.FirewallInfo) (*models.FirewallInfo, error) {
	// Invoke by bare name (NOT the sbinToolPath result): runCmd records the literal
	// command name as the capture/replay key, so an absolute path here would change
	// the key and make every pre-existing bundle replay as a false "could not read
	// ruleset". A bare-name exec is still correct — on a non-root run where sbin is
	// off $PATH it fails to launch, which the err path below turns into the honest
	// "run as root?" not-verified reason. The sbinToolPath gate in Collect() is what
	// tells us the binary exists.
	out, err := runCmd(ctx, "nft", "list", "ruleset")
	if err != nil {
		// nft is installed but the ruleset read failed — dominant case is a non-root
		// run (CAP_NET_ADMIN/EPERM). Record it so the verdict says "not verified"
		// instead of silently leaving Available=false (a clean-looking no-firewall).
		info.Status = "unverified"
		info.StatusReason = "could not read nftables ruleset (run as root?): " + err.Error()
		return info, nil
	}
	parseNFTRuleset(out, info)

	// Same "service up but unreachable" correlation as the iptables path, for the
	// nftables backend. Only when an input base chain has policy drop, and only when
	// the ruleset is fully parseable (see parseNFTInputAccept).
	if info.DefaultDrop {
		correlateBlockedListenersNFT(out, info)
	}
	return info, nil
}

// correlateBlockedListenersNFT populates info.BlockedListeners from an nftables
// ruleset: TCP ports listening on all interfaces with no accept rule under an
// input policy-drop chain. Reuses the parsed `nft list ruleset` output (no second
// command). Bails (leaves BlockedListeners nil) the moment the ruleset has anything
// it can't fully reason about (a jump/goto, a named set, or any accept that isn't
// lo / established / an explicit tcp dport) so a reachable service is never flagged.
func correlateBlockedListenersNFT(ruleset string, info *models.FirewallInfo) {
	accepted, determinable := parseNFTInputAccept(ruleset)
	if !determinable {
		return
	}
	var blocked []int
	for _, port := range listeningExposedTCPPorts() {
		if !accepted[port] {
			blocked = append(blocked, port)
		}
	}
	info.BlockedListeners = blocked
}

// nftDportRe captures the dport argument of a TCP nft rule: a literal port, a
// range (8000-8002), or an inline set ({ 80, 443 }). Anchored on a preceding
// "tcp" so a `udp dport N accept` rule does NOT match — without this, a
// TCP-only listening service genuinely blocked by the firewall (only UDP :N
// was opened) was credited as accepted because some other rule opened the
// same port number for UDP, suppressing the "service up but firewall drops
// it" WARN. A named set (dport @foo) or a vmap matches nothing here → the
// caller treats the accept as unparseable and bails.
var nftDportRe = regexp.MustCompile(`\btcp\s+dport\s+(\{[^}]*\}|[0-9]+-[0-9]+|[0-9]+)`)

// parseNFTInputAccept scans the input base chain(s) of an `nft list ruleset` and
// returns the set of explicitly-accepted TCP dports, plus determinable=false if any
// accept rule could permit inbound in a way it can't enumerate (a jump/goto, a
// source/ipset/named-set accept, a no-dport accept). Conservative by construction:
// only lo, established/related state, and literal `tcp dport …` accepts are
// understood; everything else bails. Mirrors the iptables parseIPTInputAccept.
func parseNFTInputAccept(ruleset string) (accepted map[int]bool, determinable bool) {
	accepted = map[int]bool{}
	determinable = true
	inInput := false
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "table "):
			continue
		case strings.HasPrefix(line, "chain "):
			inInput = false // new chain — not known to be input until its type line
			continue
		case strings.HasPrefix(line, "type "):
			inInput = strings.Contains(line, "hook input") // chain config line
			continue
		case strings.HasPrefix(line, "}"): // NOSONAR — same body as the chain case: both reset inInput; identical action, distinct trigger
			inInput = false
			continue
		}
		if !inInput {
			continue
		}
		// A rule line inside an input base chain.
		if hasField(line, "jump") || hasField(line, "goto") {
			determinable = false // dispatch to a chain we don't follow
			continue
		}
		if !hasField(line, "accept") {
			continue // drop / counter / log / return — does not accept
		}
		if strings.Contains(line, `iif "lo"`) || strings.Contains(line, `iifname "lo"`) {
			continue // loopback-only accept grants no external reachability
		}
		if ports := nftAcceptedDports(line); len(ports) > 0 {
			for _, p := range ports {
				accepted[p] = true
			}
			continue
		}
		// A UDP-only dport accept (nftDportRe no longer matches it) tells us
		// nothing about TCP reachability — skip cleanly rather than falling into
		// the "undeterminable" catch-all below, which would otherwise flag an
		// entire benign ruleset as unparseable over a harmless UDP rule.
		if strings.Contains(line, "udp dport") {
			continue
		}
		// ct state established/related accept (no dport) is reply traffic only.
		if strings.Contains(line, "ct state") && !strings.Contains(line, "new") {
			continue
		}
		// An accept we can't pin to a dport (saddr, named set @x, vmap, bare accept)
		// could permit arbitrary inbound — bail rather than risk a false alarm.
		determinable = false
	}
	return accepted, determinable
}

// nftAcceptedDports extracts the literal TCP dports from one nft accept rule:
//
//	tcp dport 22 accept            → [22]
//	tcp dport { 80, 443 } accept   → [80,443]
//	tcp dport 8000-8002 accept     → [8000,8001,8002]
//
// Returns empty for a named set (dport @set) so the caller bails.
func nftAcceptedDports(line string) []int {
	m := nftDportRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	arg := m[1]
	var ports []int
	if strings.HasPrefix(arg, "{") {
		arg = strings.Trim(arg, "{}")
		for _, part := range strings.Split(arg, ",") {
			ports = append(ports, expandNFTPortElem(strings.TrimSpace(part))...)
		}
		return ports
	}
	return expandNFTPortElem(arg)
}

// expandNFTPortElem parses one dport element — a single port or an N-M range
// (bounded to 1024 to cap expansion of a huge range).
func expandNFTPortElem(s string) []int {
	if lo, hi, ok := parseNFTRange(s); ok {
		var ports []int
		for p := lo; p <= hi && p-lo <= 1024; p++ {
			ports = append(ports, p)
		}
		return ports
	}
	if p, err := strconv.Atoi(s); err == nil {
		return []int{p}
	}
	return nil
}

// parseNFTRange parses "8000-8002" → (8000, 8002, true); a bare number is not a
// range. (nft renders ranges with '-', unlike iptables' ':'.)
func parseNFTRange(s string) (lo, hi int, ok bool) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

// hasField reports whether w appears as a whitespace-separated token in line.
func hasField(line, w string) bool {
	for _, f := range strings.Fields(line) {
		if f == w {
			return true
		}
	}
	return false
}

// parseNFTRuleset parses `nft list ruleset` output into a FirewallInfo. Split
// out from collectNFTables so the security collector can reuse the exact same
// rule-counting logic (keeping `dsd health` and `dsd security` in agreement).
func parseNFTRuleset(out string, info *models.FirewallInfo) {
	info.Available = true
	info.Backend = "nftables"

	scanner := bufio.NewScanner(strings.NewReader(out))
	var currentTable, currentChain string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "table ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				currentTable = parts[2]
			}
		} else if strings.HasPrefix(line, "chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
			ch := models.FirewallChain{Table: currentTable, Name: currentChain}
			// Look for "policy drop" or "policy accept" on same line or next
			if strings.Contains(strings.ToLower(line), "policy drop") {
				ch.Policy = "drop"
				if currentChain == "input" || currentChain == "INPUT" {
					info.DefaultDrop = true
				}
			} else if strings.Contains(strings.ToLower(line), "policy accept") {
				ch.Policy = "accept"
			}
			info.Chains = append(info.Chains, ch)
		} else if line != "" && !strings.HasSuffix(line, "{") && !strings.HasPrefix(line, "}") {
			// In real `nft list ruleset`, an input base chain's policy sits on its
			// `type filter hook input priority …; policy drop;` line — NOT the
			// `chain input {` line the block above inspects — so DefaultDrop was never
			// detected for nftables. Catch it here.
			if strings.Contains(line, "hook input") && strings.Contains(line, "policy drop") {
				info.DefaultDrop = true
				if n := len(info.Chains); n > 0 {
					info.Chains[n-1].Policy = "drop"
				}
			}
			info.TotalRules++
		}
	}
	// Active only when there is actual filtering — an empty `nft list ruleset`
	// (nftables installed, no rules) is NOT a firewall. Matches the iptables path
	// (TotalRules > 0) so the two backends agree; previously nftables set Active
	// unconditionally, a latent false-OK (no rules read as "protected").
	info.Active = info.TotalRules > 0
}

func collectIPTables(ctx context.Context, info *models.FirewallInfo) (*models.FirewallInfo, error) {
	// Bare name keeps the replay key stable (see collectNFTables).
	out, err := runCmd(ctx, "iptables", "-L", "-n", "--line-numbers")
	if err != nil {
		// iptables installed but the list read failed (non-root EPERM, most often) —
		// flag it so the verdict reports "not verified" rather than a silent OK.
		info.Status = "unverified"
		info.StatusReason = "could not read iptables rules (run as root?): " + err.Error()
		return info, nil
	}
	parseIPTList(out, info)

	// When the INPUT policy is DROP, correlate listening services against the ACCEPT
	// rules to find ports that are exposed (bound 0.0.0.0/::) but unreachable — the
	// classic "service up but firewall drops it" footgun (common on Photon, which
	// ships a default-DROP iptables ruleset). Conservative: only flags when the
	// ruleset is fully parseable (see correlateBlockedListeners).
	if info.DefaultDrop {
		correlateBlockedListeners(ctx, info)
	}
	return info, nil
}

// correlateBlockedListeners populates info.BlockedListeners with TCP ports that
// listen on all interfaces but have no INPUT ACCEPT rule under a DROP policy.
// Re-reads the INPUT chain with `-nvL` (the -v is essential: it exposes the `in`
// interface column so an `-i lo -j ACCEPT` rule isn't misread as a blanket accept).
// Bails (leaves BlockedListeners nil) the moment the ruleset contains anything it
// can't fully reason about — a custom-chain jump, an ipset/blanket ACCEPT — so a
// reachable service is never mis-flagged as blocked.
func correlateBlockedListeners(ctx context.Context, info *models.FirewallInfo) {
	out, err := runCmd(ctx, "iptables", "-t", "filter", "-nvL", "INPUT")
	if err != nil {
		return
	}
	accepted, determinable := parseIPTInputAccept(out)
	if !determinable {
		return
	}
	var blocked []int
	for _, port := range listeningExposedTCPPorts() {
		if !accepted[port] {
			blocked = append(blocked, port)
		}
	}
	info.BlockedListeners = blocked
}

// iptNonAcceptTargets are INPUT targets that never accept a packet, so a rule with
// one cannot make a port reachable. Any OTHER non-ACCEPT target is a jump to a
// custom chain we don't follow → the ruleset becomes indeterminable.
var iptNonAcceptTargets = map[string]bool{
	"DROP": true, "REJECT": true, "LOG": true, "RETURN": true, "MARK": true,
	"NFLOG": true, "AUDIT": true, "ULOG": true, "TRACE": true, "CONNMARK": true,
	"TCPMSS": true, "NOTRACK": true, "CT": true, "NFQUEUE": true,
}

// parseIPTInputAccept parses `iptables -nvL INPUT` and returns the set of TCP
// destination ports explicitly ACCEPTed for NEW inbound, plus determinable=false
// if any rule could permit traffic in a way it can't enumerate (a custom-chain
// jump, or a non-lo ACCEPT with no explicit dport — blanket/ipset/source-scoped).
// Columns (-nvL): pkts bytes target prot opt in out source destination [matches].
func parseIPTInputAccept(out string) (accepted map[int]bool, determinable bool) {
	accepted = map[int]bool{}
	determinable = true
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		target, prot, in := f[2], f[3], f[5]
		tail := strings.Join(f[9:], " ")
		if target != "ACCEPT" {
			if !iptNonAcceptTargets[target] {
				determinable = false // jump to a custom chain we don't follow
			}
			continue
		}
		if in == "lo" {
			continue // loopback-only ACCEPT grants no external reachability
		}
		// A UDP-scoped ACCEPT (-p udp) is not evidence a TCP port is reachable —
		// e.g. "udp dpt:53 ACCEPT" was previously credited as opening TCP :53 just
		// because some other rule matched the same port number for UDP, silently
		// suppressing the "TCP service up but firewall drops it" WARN. Skip
		// cleanly (not "determinable=false") so a benign UDP rule doesn't flag
		// the whole ruleset as unparseable. iptables -nvL renders the prot column
		// as either the name ("udp") or the raw protocol number (17) depending on
		// version/flags — the Photon fixture below shows numeric ("6" for tcp),
		// so both forms must be recognized.
		if prot == "udp" || prot == "17" {
			continue
		}
		if ports := iptAcceptedDports(tail); len(ports) > 0 {
			for _, p := range ports {
				accepted[p] = true
			}
			continue
		}
		// A no-dport ACCEPT that only matches established/related reply traffic does
		// not open a listener to NEW connections — ignore it.
		if iptEstablishedOnly(tail) {
			continue
		}
		// A non-lo ACCEPT with no parseable dport (blanket accept, ipset, or
		// source-scoped) could permit arbitrary inbound — we can't prove any port is
		// blocked, so stop here rather than risk a false alarm.
		determinable = false
	}
	return accepted, determinable
}

// iptEstablishedOnly reports whether a rule's match tail is a conntrack
// established/related state rule with no NEW state (reply traffic only).
func iptEstablishedOnly(tail string) bool {
	l := strings.ToLower(tail)
	if !strings.Contains(l, "state") { // covers "ctstate" and "state"
		return false
	}
	return !strings.Contains(l, "new")
}

// iptAcceptedDports extracts TCP destination ports from a rule match tail:
//
//	"tcp dpt:22"                         → [22]
//	"tcp dpts:8000:8002"                 → [8000,8001,8002]
//	"multiport dports 80,443,8080"       → [80,443,8080]
func iptAcceptedDports(tail string) []int {
	var ports []int
	fields := strings.Fields(tail)
	for i, tok := range fields {
		switch {
		case strings.HasPrefix(tok, "dpt:"):
			if p, err := strconv.Atoi(strings.TrimPrefix(tok, "dpt:")); err == nil {
				ports = append(ports, p)
			}
		case strings.HasPrefix(tok, "dpts:"):
			lo, hi, ok := parsePortRange(strings.TrimPrefix(tok, "dpts:"))
			if ok && hi-lo <= 1024 { // bound the expansion; huge ranges are effectively "many"
				for p := lo; p <= hi; p++ {
					ports = append(ports, p)
				}
			}
		case tok == "dports" && i+1 < len(fields):
			for _, part := range strings.Split(fields[i+1], ",") {
				if lo, hi, ok := parsePortRange(part); ok {
					for p := lo; p <= hi && p-lo <= 1024; p++ {
						ports = append(ports, p)
					}
				} else if p, err := strconv.Atoi(part); err == nil {
					ports = append(ports, p)
				}
			}
		}
	}
	return ports
}

// parsePortRange parses "8000:8002" into (8000, 8002, true); a bare number is not
// a range (returns ok=false).
func parsePortRange(s string) (lo, hi int, ok bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(parts[0])
	hi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

// listeningExposedTCPPorts returns TCP ports in LISTEN state bound to all
// interfaces (0.0.0.0 or ::) from /proc/net/tcp{,6}. Loopback-bound listeners
// (127.0.0.1/::1) are excluded — they are not externally exposed regardless of the
// firewall. Source-routed reads so capture/replay stays faithful.
func listeningExposedTCPPorts() []int {
	seen := map[int]bool{}
	var ports []int
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		for _, p := range parseProcNetTCPListeners(string(data)) {
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	sort.Ints(ports)
	return ports
}

// parseProcNetTCPListeners returns the ports in /proc/net/tcp{,6} content that are
// in LISTEN state (0A) and bound to the wildcard address (0.0.0.0 / ::).
func parseProcNetTCPListeners(data string) []int {
	var ports []int
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		parts := strings.SplitN(f[1], ":", 2)
		if len(parts) != 2 || !isAllZeroHexAddr(parts[0]) {
			continue // bound to a specific address (incl. loopback) — not 0.0.0.0/::
		}
		if port, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
			ports = append(ports, int(port))
		}
	}
	return ports
}

// isAllZeroHexAddr reports whether a /proc/net/tcp local-address hex string is the
// wildcard bind (0.0.0.0 → "00000000", :: → 32 zeros).
func isAllZeroHexAddr(h string) bool {
	if h == "" {
		return false
	}
	for _, c := range h {
		if c != '0' {
			return false
		}
	}
	return true
}

// parseIPTList parses `iptables -L -n --line-numbers` output into a
// FirewallInfo. Split out from collectIPTables so the security collector can
// reuse the same rule-counting logic.
func parseIPTList(out string, info *models.FirewallInfo) {
	info.Available = true
	info.Backend = "iptables"

	scanner := bufio.NewScanner(strings.NewReader(out))
	var currentChain models.FirewallChain
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Chain ") {
			if currentChain.Name != "" {
				info.Chains = append(info.Chains, currentChain)
			}
			parts := strings.Fields(line)
			currentChain = models.FirewallChain{Table: "filter", Name: parts[1]}
			// "Chain INPUT (policy DROP)" → extract policy
			if i := strings.Index(line, "policy "); i >= 0 {
				rest := line[i+7:]
				if strings.HasPrefix(rest, "DROP") || strings.HasPrefix(rest, "REJECT") {
					currentChain.Policy = "drop"
					if parts[1] == "INPUT" {
						info.DefaultDrop = true
					}
				} else {
					currentChain.Policy = "accept"
				}
			}
		} else if line != "" && !strings.HasPrefix(line, "target") && !strings.HasPrefix(line, "num") {
			currentChain.Rules++
			info.TotalRules++
		}
	}
	if currentChain.Name != "" {
		info.Chains = append(info.Chains, currentChain)
	}
	if info.TotalRules > 0 {
		info.Active = true
	}
}
