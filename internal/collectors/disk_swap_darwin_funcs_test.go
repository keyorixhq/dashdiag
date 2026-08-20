//go:build linux

package collectors

// disk_swap_darwin_funcs_test.go — collectDarwinBase (disk.go) and
// SwapCollector.collectDarwin (swap.go) both route through gopsutil via
// cachedJSON/curSource().Cached, which only the package-level
// fakeCombinedSource test double (security_linux_source_test.go) can seed —
// hence //go:build linux here, matching that helper's own tag, even though
// the functions under test compile on every platform. DiskCollector's own
// collectDarwin (disk_linux_darwin_stub.go) is a one-line dispatcher to
// collectDarwinBase and is covered incidentally via that same call.

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCollectDarwinBase_SkipsSyntheticAndReadOnlyMounts(t *testing.T) {
	partitions := `[
		{"device":"/dev/disk1s1","mountpoint":"/","fstype":"apfs","opts":["rw"]},
		{"device":"map auto_home","mountpoint":"/System/Volumes/Data","fstype":"apfs","opts":["rw"]},
		{"device":"devfs","mountpoint":"/dev","fstype":"devfs","opts":["rw"]},
		{"device":"/dev/disk1s5","mountpoint":"/System/Volumes/VM","fstype":"apfs","opts":["rw"]},
		{"device":"/dev/disk2s1","mountpoint":"/Volumes/ROVolume","fstype":"apfs","opts":["ro"]}
	]`
	usageRoot := `{"path":"/","fstype":"apfs","total":500000000000,"free":200000000000,"used":300000000000,"usedPercent":60,"inodesTotal":0,"inodesUsed":0,"inodesFree":0,"inodesUsedPercent":0}`
	usageData := `{"path":"/System/Volumes/Data","fstype":"apfs","total":500000000000,"free":100000000000,"used":400000000000,"usedPercent":80,"inodesTotal":0,"inodesUsed":0,"inodesFree":0,"inodesUsedPercent":0}`

	withCombinedFixture(t, map[string][]byte{
		"gopsutil/disk/partitions":                 []byte(partitions),
		"gopsutil/disk/usage//":                    []byte(usageRoot),
		"gopsutil/disk/usage//System/Volumes/Data": []byte(usageData),
	}, nil, nil)

	c := &DiskCollector{}
	info, err := c.collectDarwinBase(context.Background())
	if err != nil {
		t.Fatalf("collectDarwinBase: %v", err)
	}
	if len(info.Filesystems) != 2 {
		t.Fatalf("got %d filesystems, want 2 (/ and /System/Volumes/Data) — /dev, VM, and the ro "+
			"volume must be skipped, got: %+v", len(info.Filesystems), info.Filesystems)
	}
	byMount := map[string]models.FilesystemInfo{}
	for _, fs := range info.Filesystems {
		byMount[fs.Mount] = fs
	}
	if fs, ok := byMount["/"]; !ok || fs.UsedPct != 60 {
		t.Errorf("expected / with 60%% used, got: %+v", byMount["/"])
	}
	if fs, ok := byMount["/System/Volumes/Data"]; !ok || fs.UsedPct != 80 {
		t.Errorf("expected /System/Volumes/Data with 80%% used, got: %+v", byMount["/System/Volumes/Data"])
	}
	if _, ok := byMount["/Volumes/ROVolume"]; ok {
		t.Error("read-only volume should have been skipped")
	}
}

func TestCollectDarwinBase_PartitionsErrorPropagates(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil) // "gopsutil/disk/partitions" not seeded → Cached errors
	c := &DiskCollector{}
	if _, err := c.collectDarwinBase(context.Background()); err == nil {
		t.Error("collectDarwinBase() = nil error, want an error when partitions can't be read")
	}
}

// TestDiskCollector_CollectDarwin_DelegatesToBase covers the one-line
// disk_linux_darwin_stub.go dispatcher.
func TestDiskCollector_CollectDarwin_DelegatesToBase(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"gopsutil/disk/partitions": []byte(`[{"device":"/dev/disk1s1","mountpoint":"/","fstype":"apfs","opts":["rw"]}]`),
		"gopsutil/disk/usage//":    []byte(`{"path":"/","fstype":"apfs","total":1,"free":1,"used":0,"usedPercent":0}`),
	}, nil, nil)
	c := &DiskCollector{}
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("collectDarwin: %v", err)
	}
	if len(info.Filesystems) != 1 {
		t.Errorf("expected collectDarwin to delegate to collectDarwinBase, got: %+v", info)
	}
}

func TestSwapCollector_CollectDarwin_HappyPath(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"gopsutil/mem/swap": []byte(`{"total":8589934592,"used":1073741824,"free":7516192768,"usedPercent":12.5}`),
	}, nil, nil)

	c := &SwapCollector{}
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("collectDarwin: %v", err)
	}
	if info.UsedPct != 12.5 {
		t.Errorf("UsedPct = %v, want 12.5", info.UsedPct)
	}
	if info.PagesInPerSec != -1 || info.PagesOutPerSec != -1 {
		t.Errorf("expected sentinel -1 for unmeasured page rates on macOS, got in=%v out=%v", info.PagesInPerSec, info.PagesOutPerSec)
	}
}

func TestSwapCollector_CollectDarwin_ReadErrorNotFabricatedHealthy(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil) // "gopsutil/mem/swap" not seeded → Cached errors
	c := &SwapCollector{}
	if _, err := c.collectDarwin(context.Background()); err == nil {
		t.Error("collectDarwin() = nil error, want an error — a read failure must not fabricate a " +
			"healthy-looking SwapInfo (internal-collectors-31-01's false-OK class)")
	}
}
