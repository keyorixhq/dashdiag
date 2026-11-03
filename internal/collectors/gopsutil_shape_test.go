package collectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	gopsutildisk "github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

// cachedJSON records gopsutil result structs as JSON on capture and unmarshals
// them back into the gopsutil struct types on replay. The fixtures under
// testdata/gopsutil_shapes were produced by marshalling the gopsutil v3.24.5
// structs filled with fixed distinct sample values (64-bit fields exceed 2^32 so
// narrowing is visible). Bundles recorded by v3-era binaries therefore carry
// exactly these shapes. These tests fail if a gopsutil bump drops, renames,
// retags, retypes or adds a field the collectors decode.

func flattenJSON(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			flattenJSON(prefix+k+".", e, out)
		}
	case []any:
		for i, e := range x {
			flattenJSON(fmt.Sprintf("%s%d.", prefix, i), e, out)
		}
	default:
		out[strings.TrimSuffix(prefix, ".")] = fmt.Sprint(v)
	}
}

func flatLeaves(b []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}
	out := make(map[string]string)
	flattenJSON("", v, out)
	return out, nil
}

// shapeProblems unmarshals fixture into target (what replay does), marshals it
// back, and reports every leaf that was lost, changed or newly appeared.
// Any failure on the way (including a value that no longer fits the new type)
// is itself a reported problem, never a silent pass.
func shapeProblems(fixture []byte, target any) []string {
	if err := json.Unmarshal(fixture, target); err != nil {
		return []string{"unmarshal into target failed: " + err.Error()}
	}
	back, err := json.Marshal(target)
	if err != nil {
		return []string{"re-marshalling target failed: " + err.Error()}
	}
	want, err := flatLeaves(fixture)
	if err != nil {
		return []string{"flattening fixture failed: " + err.Error()}
	}
	got, err := flatLeaves(back)
	if err != nil {
		return []string{"flattening decoded target failed: " + err.Error()}
	}
	problems := make([]string, 0, 4)
	for k, w := range want {
		g, ok := got[k]
		switch {
		case !ok:
			problems = append(problems, "dropped: "+k)
		case g != w:
			problems = append(problems, fmt.Sprintf("changed: %s fixture=%s decoded=%s", k, w, g))
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			problems = append(problems, "added by new struct, not in fixture: "+k)
		}
	}
	sort.Strings(problems)
	return problems
}

func readShapeFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "gopsutil_shapes", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return b
}

func TestGopsutilCachedJSONShapesStable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key     string
		fixture string
		target  func() any
	}{
		{"gopsutil/mem/virtual", "gopsutil_mem_virtual.json", func() any { return new(mem.VirtualMemoryStat) }},
		{"gopsutil/mem/swap", "gopsutil_mem_swap.json", func() any { return new(mem.SwapMemoryStat) }},
		{"gopsutil/disk/partitions", "gopsutil_disk_partitions.json", func() any { return new([]gopsutildisk.PartitionStat) }},
		{"gopsutil/disk/usage/<mnt>", "gopsutil_disk_usage.json", func() any { return new(gopsutildisk.UsageStat) }},
		{"gopsutil/net/interfaces", "gopsutil_net_interfaces.json", func() any { return new(gopsutilnet.InterfaceStatList) }},
		{"gopsutil/net/iocounters", "gopsutil_net_iocounters.json", func() any { return new([]gopsutilnet.IOCountersStat) }},
		{"gopsutil/net/connections/tcp", "gopsutil_net_connections_tcp.json", func() any { return new([]gopsutilnet.ConnectionStat) }},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			problems := shapeProblems(readShapeFixture(t, tc.fixture), tc.target())
			if len(problems) > 0 {
				t.Fatalf("%s JSON shape changed vs the v3-era recording (old bundles would decode differently):\n  %s",
					tc.key, strings.Join(problems, "\n  "))
			}
		})
	}
}

// Mutant structs: copies of gopsutil's SwapMemoryStat with one deliberate shape
// change each, plus an unchanged control. shapeProblems must flag every mutant
// and stay quiet on the control, otherwise the guard above proves nothing.
type swapControl struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"usedPercent"`
	Sin         uint64  `json:"sin"`
	Sout        uint64  `json:"sout"`
	PgIn        uint64  `json:"pgIn"`
	PgOut       uint64  `json:"pgOut"`
	PgFault     uint64  `json:"pgFault"`
	PgMajFault  uint64  `json:"pgMajFault"`
}

type swapRenamedTag struct {
	Total       uint64  `json:"totl"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"usedPercent"`
	Sin         uint64  `json:"sin"`
	Sout        uint64  `json:"sout"`
	PgIn        uint64  `json:"pgIn"`
	PgOut       uint64  `json:"pgOut"`
	PgFault     uint64  `json:"pgFault"`
	PgMajFault  uint64  `json:"pgMajFault"`
}

type swapDropped struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"usedPercent"`
	Sin         uint64  `json:"sin"`
	Sout        uint64  `json:"sout"`
	PgIn        uint64  `json:"pgIn"`
	PgOut       uint64  `json:"pgOut"`
	PgFault     uint64  `json:"pgFault"`
}

type swapAdded struct {
	swapControl
	Extra uint64 `json:"extra"`
}

type swapNarrowed struct {
	Total       uint32  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"usedPercent"`
	Sin         uint64  `json:"sin"`
	Sout        uint64  `json:"sout"`
	PgIn        uint64  `json:"pgIn"`
	PgOut       uint64  `json:"pgOut"`
	PgFault     uint64  `json:"pgFault"`
	PgMajFault  uint64  `json:"pgMajFault"`
}

func TestGopsutilShapeGuardFlagsMutants(t *testing.T) {
	t.Parallel()
	fixture := readShapeFixture(t, "gopsutil_mem_swap.json")

	if p := shapeProblems(fixture, new(swapControl)); len(p) != 0 {
		t.Fatalf("control must be clean, got problems=%v", p)
	}
	mutants := map[string]any{
		"renamed tag": new(swapRenamedTag),
		"dropped":     new(swapDropped),
		"added":       new(swapAdded),
		"narrowed":    new(swapNarrowed),
	}
	for name, m := range mutants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if p := shapeProblems(fixture, m); len(p) == 0 {
				t.Fatalf("mutant %q was not detected", name)
			}
		})
	}
}
