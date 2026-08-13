//go:build linux

package collectors

import (
	"context"
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

	nodes, _ := glob("/sys/devices/system/node/node[0-9]*")
	if len(nodes) <= 1 {
		return info, nil // single-node system — not interesting
	}
	info.Available = true
	info.NodeCount = len(nodes)

	for _, nodePath := range nodes {
		info.Nodes = append(info.Nodes, parseNUMANode(nodePath))
	}
	info.Imbalanced = numaImbalanced(info.Nodes)
	return info, nil
}

// numaImbalanced reports whether the memory-bearing nodes are imbalanced (the
// max has >40% more memory than the min). Memoryless nodes (CPU-only NUMA
// domains — common with CXL memory expanders on modern multi-socket systems,
// or simply an unreadable meminfo) are excluded from the comparison entirely,
// rather than lowering the min to 0. A single such node used to disable the
// WHOLE imbalance check (the old "minMem>0" guard), even when the real
// memory-bearing nodes were wildly imbalanced relative to each other —
// exactly the asymmetric multi-node box this check exists to catch.
func numaImbalanced(nodes []models.NUMANode) bool {
	var maxMem, minMem float64
	haveMemNode := false
	for _, node := range nodes {
		if node.MemGB <= 0 {
			continue
		}
		if !haveMemNode || node.MemGB > maxMem {
			maxMem = node.MemGB
		}
		if !haveMemNode || node.MemGB < minMem {
			minMem = node.MemGB
		}
		haveMemNode = true
	}
	return haveMemNode && minMem > 0 && maxMem/minMem > 1.4
}

// IsNUMAPresent returns true when multiple NUMA nodes exist.
func IsNUMAPresent() bool {
	nodes, _ := glob("/sys/devices/system/node/node[0-9]*")
	return len(nodes) > 1
}

func parseNUMANode(path string) models.NUMANode {
	name := filepath.Base(path)
	idStr := strings.TrimPrefix(name, "node")
	id, _ := strconv.Atoi(idStr)
	node := models.NUMANode{ID: id}

	// Memory info from meminfo
	memData, err := readFile(filepath.Join(path, "meminfo"))
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
	cpuListData, err := readFile(filepath.Join(path, "cpulist"))
	if err == nil {
		node.CPUs = parseCPUList(strings.TrimSpace(string(cpuListData)))
	}
	return node
}

// maxCPUListID caps the largest CPU id / range endpoint parseCPUList will
// expand. Real hardware maxes out in the low thousands of logical CPUs; a
// cpulist source that isn't genuine kernel output (a crafted `dsd replay`
// bundle, an attacker-influenceable bind-mounted /sys tree) claiming a range
// like "0-999999999999" must not make dsd try to loop/allocate that many
// entries — a malformed or implausible range is skipped rather than expanded.
const maxCPUListID = 1 << 16 // 65536

// parseCPUList parses "0-3,8-11" → [0,1,2,3,8,9,10,11]
func parseCPUList(s string) []int {
	var cpus []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if i := strings.Index(part, "-"); i >= 0 {
			from, errFrom := strconv.Atoi(part[:i])
			to, errTo := strconv.Atoi(part[i+1:])
			if errFrom != nil || errTo != nil || from < 0 || to < from || to >= maxCPUListID {
				continue
			}
			for j := from; j <= to; j++ {
				cpus = append(cpus, j)
			}
		} else if n, err := strconv.Atoi(part); err == nil {
			cpus = append(cpus, n)
		}
	}
	return cpus
}
