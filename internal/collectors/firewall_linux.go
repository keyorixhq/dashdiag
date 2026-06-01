//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type FirewallCollector struct{}

func NewFirewallCollector() *FirewallCollector      { return &FirewallCollector{} }
func (c *FirewallCollector) Name() string           { return "Firewall" }
func (c *FirewallCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *FirewallCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.FirewallInfo{}

	// Prefer nftables (modern), fall back to iptables
	if _, err := exec.LookPath("nft"); err == nil {
		return collectNFTables(ctx, info)
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return collectIPTables(ctx, info)
	}
	return info, nil
}

func collectNFTables(ctx context.Context, info *models.FirewallInfo) (*models.FirewallInfo, error) {
	out, err := runCmd(ctx, "nft", "list", "ruleset")
	if err != nil {
		return info, nil
	}
	parseNFTRuleset(out, info)
	return info, nil
}

// parseNFTRuleset parses `nft list ruleset` output into a FirewallInfo. Split
// out from collectNFTables so the security collector can reuse the exact same
// rule-counting logic (keeping `dsd health` and `dsd security` in agreement).
func parseNFTRuleset(out string, info *models.FirewallInfo) {
	info.Available = true
	info.Backend = "nftables"
	info.Active = true

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
			info.TotalRules++
		}
	}
}

func collectIPTables(ctx context.Context, info *models.FirewallInfo) (*models.FirewallInfo, error) {
	out, err := runCmd(ctx, "iptables", "-L", "-n", "--line-numbers")
	if err != nil {
		return info, nil
	}
	parseIPTList(out, info)
	return info, nil
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
