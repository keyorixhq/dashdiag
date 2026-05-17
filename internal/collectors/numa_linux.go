//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NUMACollector struct{}

func NewNUMACollector() *NUMACollector          { return &NUMACollector{} }
func (c *NUMACollector) Name() string           { return "NUMA" }
func (c *NUMACollector) Timeout() time.Duration { return 3 * time.Second }

func (c *NUMACollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.NUMAInfo{}

	nodes, _ := filepath.Glob("/sys/devices/system/node/node[0-9]*")
	if len(nodes) <= 1 {
		return info, nil // single-node system — not interesting
	}
	info.Available = true
	info.NodeCount = len(nodes)

	var maxMem, minMem float64 = 0, 1 << 62
	for _, nodePath := range nodes {
		node := parseNUMANode(nodePath)
		info.Nodes = append(info.Nodes, node)
		if node.MemGB > maxMem {
			maxMem = node.MemGB
		}
		if node.MemGB < minMem {
			minMem = node.MemGB
		}
	}
	// Flag imbalance when max node has >40% more memory than min
	if minMem > 0 && maxMem/minMem > 1.4 {
		info.Imbalanced = true
	}
	return info, nil
}

// IsNUMAPresent returns true when multiple NUMA nodes exist.
func IsNUMAPresent() bool {
	nodes, _ := filepath.Glob("/sys/devices/system/node/node[0-9]*")
	return len(nodes) > 1
}

func parseNUMANode(path string) models.NUMANode {
	name := filepath.Base(path)
	idStr := strings.TrimPrefix(name, "node")
	id, _ := strconv.Atoi(idStr)
	node := models.NUMANode{ID: id}

	// Memory info from meminfo
	memData, err := os.ReadFile(filepath.Join(path, "meminfo"))
	if err == nil {
		for _, line := range strings.Split(string(memData), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			kb, err := strconv.ParseInt(fields[3], 10, 64)
			if err != nil {
				continue
			}
			switch fields[2] {
			case "MemTotal:":
				node.MemGB = float64(kb) / (1024 * 1024)
			case "MemFree:":
				node.MemFreeGB = float64(kb) / (1024 * 1024)
			}
		}
	}

	// CPU list
	cpuListData, err := os.ReadFile(filepath.Join(path, "cpulist"))
	if err == nil {
		node.CPUs = parseCPUList(strings.TrimSpace(string(cpuListData)))
	}
	return node
}

// parseCPUList parses "0-3,8-11" → [0,1,2,3,8,9,10,11]
func parseCPUList(s string) []int {
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, "-"); i >= 0 {
			from, _ := strconv.Atoi(part[:i])
			to, _ := strconv.Atoi(part[i+1:])
			for j := from; j <= to; j++ {
				cpus = append(cpus, j)
			}
		} else if n, err := strconv.Atoi(part); err == nil {
			cpus = append(cpus, n)
		}
	}
	return cpus
}
