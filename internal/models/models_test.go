package models

import (
	"encoding/json"
	"testing"
	"time"
)

func roundTrip(t *testing.T, in, out interface{}) {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestCPUInfo(t *testing.T) {
	in := CPUInfo{LoadAvg1: 1.5, NumCPU: 4, UsagePct: 42.1, Status: "OK", StatusReason: "nominal"}
	var out CPUInfo
	roundTrip(t, &in, &out)
	if out.LoadAvg1 != in.LoadAvg1 || out.NumCPU != in.NumCPU || out.Status != in.Status {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestMemoryInfo(t *testing.T) {
	in := MemoryInfo{TotalGB: 16, FreeGB: 4.5, UsedPct: 72.0, OverCommitted: true, Status: "WARN"}
	var out MemoryInfo
	roundTrip(t, &in, &out)
	if out.TotalGB != in.TotalGB || out.OverCommitted != in.OverCommitted || out.Status != in.Status {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestSwapInfo(t *testing.T) {
	in := SwapInfo{TotalGB: 8, UsedGB: 2, UsedPct: 25.0, PagesInPerSec: 10, ZramDevices: 1, Status: "OK"}
	var out SwapInfo
	roundTrip(t, &in, &out)
	if out.TotalGB != in.TotalGB || out.ZramDevices != in.ZramDevices || out.Status != in.Status {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestDiskInfo(t *testing.T) {
	in := DiskInfo{
		Status: "OK",
		Filesystems: []FilesystemInfo{
			{Mount: "/", Device: "/dev/sda1", FSType: "ext4", TotalGB: 100, UsedPct: 45.0, ReadOnly: false, Status: "OK"},
		},
	}
	var out DiskInfo
	roundTrip(t, &in, &out)
	if len(out.Filesystems) != 1 || out.Filesystems[0].Mount != "/" || out.Filesystems[0].FSType != "ext4" {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestIOInfo(t *testing.T) {
	in := IOInfo{
		Status: "OK",
		Devices: []IODeviceInfo{
			{Name: "sda", IsSSD: true, UtilPct: 12.5, AwaitMs: 0.8, ReadMBps: 200, Status: "OK"},
		},
	}
	var out IOInfo
	roundTrip(t, &in, &out)
	if len(out.Devices) != 1 || !out.Devices[0].IsSSD || out.Devices[0].Name != "sda" {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestNetworkInfo(t *testing.T) {
	in := NetworkInfo{
		GatewayPingMs:  1.2,
		InternetPingMs: 15.0,
		NATDetected:    true,
		Status:         "OK",
		Interfaces: []InterfaceInfo{
			{Name: "eth0", IP: "192.168.1.1", Up: true, SpeedMbps: 1000},
		},
	}
	var out NetworkInfo
	roundTrip(t, &in, &out)
	if out.NATDetected != in.NATDetected || len(out.Interfaces) != 1 || out.Interfaces[0].Name != "eth0" {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestClockInfo(t *testing.T) {
	in := ClockInfo{Synced: true, OffsetMs: -1, Source: "chronyc", Status: "OK"}
	var out ClockInfo
	roundTrip(t, &in, &out)
	if out.Synced != in.Synced || out.Source != in.Source || out.OffsetMs != in.OffsetMs {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestFDInfo(t *testing.T) {
	in := FDInfo{
		OpenCount: 1024,
		MaxCount:  65536,
		UsedPct:   1.56,
		Status:    "OK",
		HotProcesses: []FDProcessInfo{
			{PID: 100, Name: "nginx", OpenFDs: 512, SoftLimit: 1024, UsedPct: 50.0},
		},
	}
	var out FDInfo
	roundTrip(t, &in, &out)
	if out.OpenCount != in.OpenCount || len(out.HotProcesses) != 1 || out.HotProcesses[0].PID != 100 {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestProcessState(t *testing.T) {
	in := ProcessState{PID: 42, PPID: 1, Name: "bash", State: "S", CPU: 0.1, MemMB: 12.5, WChan: "wait"}
	var out ProcessState
	roundTrip(t, &in, &out)
	if out.PID != in.PID || out.Name != in.Name || out.WChan != in.WChan {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestSystemdInfo(t *testing.T) {
	in := SystemdInfo{
		Available:   true,
		FailedUnits: []string{"foo.service"},
		StuckUnits:  []string{},
		Status:      "WARN",
	}
	var out SystemdInfo
	roundTrip(t, &in, &out)
	if !out.Available || len(out.FailedUnits) != 1 || out.FailedUnits[0] != "foo.service" {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestSysctlInfo(t *testing.T) {
	in := SysctlInfo{VMSwappiness: 60, NetSomaxconn: 128, FSFileMax: 100000, KernelPIDMax: 32768, PIDCount: 400, Status: "OK"}
	var out SysctlInfo
	roundTrip(t, &in, &out)
	if out.VMSwappiness != in.VMSwappiness || out.PIDCount != in.PIDCount {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestMACPolicyInfo(t *testing.T) {
	in := MACPolicyInfo{SELinuxPresent: true, SELinuxMode: "enforcing", SELinuxDenials: 3, Status: "WARN"}
	var out MACPolicyInfo
	roundTrip(t, &in, &out)
	if !out.SELinuxPresent || out.SELinuxMode != in.SELinuxMode || out.SELinuxDenials != in.SELinuxDenials {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestLogsInfo(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	in := LogsInfo{
		ErrorCount:   5,
		WarnCount:    12,
		SinceMinutes: 60,
		Status:       "WARN",
		TopErrors: []LogError{
			{Message: "OOM", Count: 3, FirstSeen: now, LastSeen: now, Source: "kern"},
		},
	}
	var out LogsInfo
	roundTrip(t, &in, &out)
	if out.ErrorCount != in.ErrorCount || len(out.TopErrors) != 1 || out.TopErrors[0].Message != "OOM" {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
	if !out.TopErrors[0].FirstSeen.Equal(now) {
		t.Errorf("time round-trip mismatch: got %v want %v", out.TopErrors[0].FirstSeen, now)
	}
}

func TestSecurityInfo(t *testing.T) {
	in := SecurityInfo{
		FailedLogins:    10,
		SSHPermitRoot:   false,
		SSHPasswordAuth: true,
		SudoNopasswd:    []string{"deploy"},
		Status:          "WARN",
		ListeningPorts: []PortEntry{
			{Port: 22, Protocol: "tcp", Process: "sshd", Expected: true},
		},
	}
	var out SecurityInfo
	roundTrip(t, &in, &out)
	if out.FailedLogins != in.FailedLogins || len(out.ListeningPorts) != 1 || out.ListeningPorts[0].Port != 22 {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}

func TestInsight(t *testing.T) {
	in := Insight{Level: "WARN", Check: "memory", Message: "high usage", Hints: []string{"add swap", "check leaks"}}
	var out Insight
	roundTrip(t, &in, &out)
	if out.Level != in.Level || out.Check != in.Check || len(out.Hints) != 2 {
		t.Errorf("round-trip mismatch: got %+v", out)
	}
}
