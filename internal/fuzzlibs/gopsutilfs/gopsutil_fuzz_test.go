// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

// Package gopsutilfs fuzzes the Linux /proc and /sys parsers of
// github.com/shirou/gopsutil/v4 that DashDiag drives as root, plus
// neighbouring exported parsers, through the library's PUBLIC fake-root
// API (common.EnvMap injected via context, as documented by gopsutil).
//
// Oracle: no panic, no hang, bounded output. These are crash-only
// harnesses for pure file parsers.
package gopsutilfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shirou/gopsutil/v4/common"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// fakeRootCtx returns a context whose common.EnvMap points HOST_PROC,
// HOST_SYS and HOST_ETC at dir. This is the officially documented way for
// a caller to redirect gopsutil's file reads (see gopsutil/v4/common docs).
func fakeRootCtx(dir string) context.Context {
	return context.WithValue(context.Background(), common.EnvKey, common.EnvMap{
		common.HostProcEnvKey:    dir,
		common.HostSysEnvKey:     filepath.Join(dir, "sys"),
		common.HostEtcEnvKey:     filepath.Join(dir, "etc"),
		common.HostProcMountinfo: "",
	})
}

// writeProc writes data to <dir>/<rel>, creating parent directories.
func writeProc(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// FuzzMeminfo drives mem.VirtualMemory / SwapMemory via /proc/meminfo.
func FuzzMeminfo(f *testing.F) {
	f.Add([]byte("MemTotal:       16384000 kB\nMemFree:         1024000 kB\nMemAvailable:    8192000 kB\n"))
	f.Add([]byte("MemTotal:0\n"))
	f.Add([]byte(":\n: \nMemTotal: kB\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		writeProc(t, dir, "meminfo", data)
		ctx := fakeRootCtx(dir)
		_, _ = mem.VirtualMemoryWithContext(ctx)
		_, _ = mem.SwapMemoryWithContext(ctx)
	})
}

// FuzzDiskstats drives disk.IOCounters via /proc/diskstats.
func FuzzDiskstats(f *testing.F) {
	f.Add([]byte("   8       0 sda 1 2 3 4 5 6 7 8 9 10 11\n"))
	f.Add([]byte(""))
	f.Add([]byte("x\n\n   \t\n8 0 sda\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		writeProc(t, dir, "diskstats", data)
		// /sys/block may be consulted for partition classification.
		ctx := fakeRootCtx(dir)
		_, _ = disk.IOCountersWithContext(ctx)
	})
}

// FuzzMountinfo drives disk.Partitions via /proc/1/mountinfo.
func FuzzMountinfo(f *testing.F) {
	f.Add([]byte("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n"))
	f.Add([]byte(" - \n"))
	f.Add([]byte("a b c d e - f g\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		writeProc(t, dir, "1/mountinfo", data)
		writeProc(t, dir, "filesystems", []byte("nodev\tproc\n\text4\n"))
		ctx := fakeRootCtx(dir)
		_, _ = disk.PartitionsWithContext(ctx, true)
		_, _ = disk.PartitionsWithContext(ctx, false)
	})
}

// FuzzMounts drives disk.Partitions via the /proc/1/mounts fallback.
func FuzzMounts(f *testing.F) {
	f.Add([]byte("/dev/sda1 / ext4 rw,relatime 0 0\n"))
	f.Add([]byte("none\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		// No mountinfo => Partitions falls back to mounts.
		writeProc(t, dir, "1/mounts", data)
		writeProc(t, dir, "filesystems", []byte("nodev\tproc\n\text4\n"))
		ctx := fakeRootCtx(dir)
		_, _ = disk.PartitionsWithContext(ctx, true)
	})
}

// FuzzNetDev drives net.IOCounters via /proc/net/dev.
func FuzzNetDev(f *testing.F) {
	f.Add([]byte("Inter-|   Receive\n face |bytes\n  eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n"))
	f.Add([]byte("a\nb\n:\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		writeProc(t, dir, "net/dev", data)
		ctx := fakeRootCtx(dir)
		_, _ = gnet.IOCountersWithContext(ctx, true)
		_, _ = gnet.IOCountersWithContext(ctx, false)
	})
}

// NOTE: net.ProtoCounters (/proc/net/snmp) has an UNFIXED upstream panic in
// v4.26.10 (slice bounds out of range on a truncated header line); see
// .scratch/records/gopsutil-1.md. It is intentionally NOT committed as a live
// fuzz target because the per-PR CI (fuzz-changed.yml) would crash on it.
// DashDiag does not call ProtoCounters, so it is not a DashDiag defect.
