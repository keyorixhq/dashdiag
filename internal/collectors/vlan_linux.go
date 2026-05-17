//go:build linux

package collectors

import (
	"bufio"
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type VLANCollector struct{}

func NewVLANCollector() *VLANCollector          { return &VLANCollector{} }
func (c *VLANCollector) Name() string           { return "VLAN" }
func (c *VLANCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *VLANCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.VLANInfo{}

	// /proc/net/vlan/config lists all VLAN interfaces
	data, err := os.ReadFile("/proc/net/vlan/config")
	if err != nil {
		return info, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "eth0.100      | 100 | eth0"
		if strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		vlanIDStr := strings.TrimSpace(parts[1])
		parent := strings.TrimSpace(parts[2])
		vlanID, _ := strconv.Atoi(vlanIDStr)

		iface, err := net.InterfaceByName(name)
		up := err == nil && iface.Flags&net.FlagUp != 0

		info.Interfaces = append(info.Interfaces, models.VLANInterface{
			Name:   name,
			Parent: parent,
			VLANID: vlanID,
			Up:     up,
		})
	}
	return info, nil
}

// IsVLANPresent returns true when VLAN interfaces exist.
func IsVLANPresent() bool {
	_, err := os.Stat("/proc/net/vlan/config")
	return err == nil
}

func parseVLANConfig(content string) []models.VLANInterface {
	var result []models.VLANInterface
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		vlanID, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		parent := strings.TrimSpace(parts[2])
		result = append(result, models.VLANInterface{Name: name, VLANID: vlanID, Parent: parent})
	}
	return result
}
