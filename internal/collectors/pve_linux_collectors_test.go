//go:build linux

package collectors

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestIsPVEHost(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pvedaemon", source.FileMeta{})
	})
	if !IsPVEHost() {
		t.Error("expected IsPVEHost true when /usr/bin/pvedaemon exists")
	}
}

func TestIsPVEHost_NotPVE(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if IsPVEHost() {
		t.Error("expected IsPVEHost false when pvedaemon is absent")
	}
}

func TestPVECollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewPVECollector()
	if c.Name() != "PVE" {
		t.Errorf("Name() = %q, want PVE", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Error("Timeout() must be positive")
	}
}

func TestPVECollector_Collect_NotPVEHost(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	got, err := NewPVECollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.PVEInfo)
	if info.IsPVE {
		t.Error("expected IsPVE=false when pvedaemon absent")
	}
}

// TestPVECollector_Collect_FullHappyPath drives the entire root-path Collect()
// sequence (pvedaemon present, os.Getuid()==0 — true under the Docker test
// container's default root user) end to end against fixture pvesh output.
func TestPVECollector_Collect_FullHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pvedaemon", source.FileMeta{})
		b.PutFile("/proc/sys/kernel/osrelease", []byte("6.8.4-3-pve\n"))
		b.PutCmd("pveversion", []string{"-v"}, "pve-manager: 8.2.2 (running version: 8.2.2/abc)\n", 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/status", "--output-format", "json"},
			`{"cpu":0.15,"uptime":123456}`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/subscription", "--output-format", "json"},
			`{"status":"active","level":"c","product":"Proxmox VE Community"}`, 0)
		b.PutCmd("pvesh", []string{"get", "/cluster/status", "--output-format", "json"},
			`[{"type":"cluster","name":"pve-cluster","quorate":1},{"type":"node","name":"pve01","online":1,"pve_version":"8.2.2"}]`, 0)
		b.PutCmd("pvesh", []string{"get", "/cluster/ha/status/current", "--output-format", "json"},
			`[{"id":"quorum","type":"quorum","status":"OK"}]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/storage", "--output-format", "json"},
			`[{"storage":"local","type":"dir","used":1000000000,"total":2000000000,"active":1}]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/qemu", "--output-format", "json"},
			`[{"vmid":100,"name":"web","status":"running","cpus":2,"maxmem":2147483648}]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/lxc", "--output-format", "json"},
			`[]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/tasks", "--output-format", "json", "--typefilter", "vzdump", "--limit", "200"},
			`[]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/tasks", "--limit", "100", "--output-format", "json"},
			`[]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/network", "--output-format", "json"},
			`[{"iface":"vmbr0","type":"bridge","active":1,"bridge_ports":"eno1"}]`, 0)
		b.PutFile("/proc/cpuinfo", []byte("physical id\t: 0\ncore id\t\t: 0\n"))
		b.PutFile("/proc/meminfo", []byte("MemTotal:       16777216 kB\n"))
	})

	got, err := NewPVECollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.PVEInfo)
	if !info.IsPVE {
		t.Fatal("expected IsPVE=true")
	}
	if info.NeedsRoot {
		t.Error("expected NeedsRoot=false when running as root")
	}
	if info.PVEVersion != "8.2.2" {
		t.Errorf("PVEVersion = %q, want 8.2.2", info.PVEVersion)
	}
	if info.KernelVersion != "6.8.4-3-pve" {
		t.Errorf("KernelVersion = %q, want 6.8.4-3-pve", info.KernelVersion)
	}
	if !info.APIReachable {
		t.Error("expected APIReachable=true")
	}
	if info.ClusterName != "pve-cluster" || !info.QuorumOK {
		t.Errorf("cluster = %q quorum=%v, want pve-cluster/true", info.ClusterName, info.QuorumOK)
	}
	if len(info.Nodes) != 1 || info.Nodes[0].Name != "pve01" {
		t.Errorf("Nodes = %+v", info.Nodes)
	}
	if !info.HAFencingOK || !info.HAVerified {
		t.Errorf("HA = ok=%v verified=%v, want true/true", info.HAFencingOK, info.HAVerified)
	}
	if len(info.Storages) != 1 || info.Storages[0].Name != "local" {
		t.Errorf("Storages = %+v", info.Storages)
	}
	if !info.StoragesVerified {
		t.Error("expected StoragesVerified=true")
	}
	if len(info.Guests) != 1 || info.RunningCount != 1 {
		t.Errorf("Guests = %+v running=%d", info.Guests, info.RunningCount)
	}
	if info.TotalVCPUs != 2 {
		t.Errorf("TotalVCPUs = %d, want 2", info.TotalVCPUs)
	}
	if info.PhysicalCores != 1 {
		t.Errorf("PhysicalCores = %d, want 1", info.PhysicalCores)
	}
	if info.HostMemGB <= 0 {
		t.Error("expected HostMemGB > 0")
	}
	if !info.TasksVerified {
		t.Error("expected TasksVerified=true")
	}
	if len(info.Bridges) != 1 || info.Bridges[0].Name != "vmbr0" || !info.Bridges[0].HasUplink {
		t.Errorf("Bridges = %+v", info.Bridges)
	}
}

func TestCollectPVEVersion(t *testing.T) {
	cases := []struct {
		name string
		seed func(b *source.Bundle)
		want string
	}{
		{
			name: "verbose colon form",
			seed: func(b *source.Bundle) {
				b.PutCmd("pveversion", []string{"-v"}, "pve-manager: 8.2.2 (running version: 8.2.2/abc)\n", 0)
			},
			want: "8.2.2",
		},
		{
			name: "plain slash form fallback",
			seed: func(b *source.Bundle) {
				b.PutCmdNotFound("pveversion", []string{"-v"})
				b.PutCmd("pveversion", nil, "pve-manager/7.4-3/0d5b8f3 (running kernel: 6.8.4-3-pve)\n", 0)
			},
			want: "7.4-3",
		},
		{
			name: "both fail",
			seed: func(b *source.Bundle) {
				b.PutCmdNotFound("pveversion", []string{"-v"})
				b.PutCmdNotFound("pveversion", nil)
			},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFixtureSource(t, c.seed)
			if got := collectPVEVersion(context.Background()); got != c.want {
				t.Errorf("collectPVEVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectKernelVersion(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/osrelease", []byte("6.8.4-3-pve\n"))
	})
	if got := collectKernelVersion(); got != "6.8.4-3-pve" {
		t.Errorf("collectKernelVersion() = %q, want 6.8.4-3-pve", got)
	}
}

func TestCollectKernelVersion_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := collectKernelVersion(); got != "" {
		t.Errorf("collectKernelVersion() = %q, want empty", got)
	}
}

func TestCollectPVENodeStatus(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/status", "--output-format", "json"},
			`{"cpu":0.42,"uptime":86400}`, 0)
	})
	cpu, uptime := collectPVENodeStatus(context.Background())
	if cpu != 42 {
		t.Errorf("cpu = %v, want 42", cpu)
	}
	if uptime != 86400 {
		t.Errorf("uptime = %d, want 86400", uptime)
	}
}

func TestCollectPVENodeStatus_Error(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/status", "--output-format", "json"})
	})
	cpu, uptime := collectPVENodeStatus(context.Background())
	if cpu != 0 || uptime != 0 {
		t.Errorf("expected zero values on error, got cpu=%v uptime=%d", cpu, uptime)
	}
}

func TestCollectPVENodeStatus_BadJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/status", "--output-format", "json"},
			"not json", 0)
	})
	cpu, uptime := collectPVENodeStatus(context.Background())
	if cpu != 0 || uptime != 0 {
		t.Errorf("expected zero values on bad JSON, got cpu=%v uptime=%d", cpu, uptime)
	}
}

func TestCollectPVESubscription(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/subscription", "--output-format", "json"},
			`{"status":"active","level":"c","product":"Proxmox VE Community"}`, 0)
	})
	got := collectPVESubscription(context.Background())
	want := models.PVESubscription{Status: "active", Level: "c", Product: "Proxmox VE Community"}
	if got != want {
		t.Errorf("collectPVESubscription() = %+v, want %+v", got, want)
	}
}

func TestCollectPVESubscription_FallsBackToFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/subscription", "--output-format", "json"})
		b.PutFile("/etc/apt/auth.conf.d/pve.conf", []byte("login user\n"))
	})
	got := collectPVESubscription(context.Background())
	if got.Status != "unverified" {
		t.Errorf("Status = %q, want unverified", got.Status)
	}
}

func TestCollectPVESubscriptionFile(t *testing.T) {
	cases := []struct {
		name string
		seed func(b *source.Bundle)
		want string
	}{
		{"missing file", func(b *source.Bundle) {}, "notfound"},
		{"login key present", func(b *source.Bundle) {
			b.PutFile("/etc/apt/auth.conf.d/pve.conf", []byte("login user\npassword secret\n"))
		}, "unverified"},
		{"file present no login", func(b *source.Bundle) {
			b.PutFile("/etc/apt/auth.conf.d/pve.conf", []byte("# empty\n"))
		}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFixtureSource(t, c.seed)
			if got := collectPVESubscriptionFile(); got.Status != c.want {
				t.Errorf("Status = %q, want %q", got.Status, c.want)
			}
		})
	}
}

func TestCollectPVECluster_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/status", "--output-format", "json"},
			`[{"type":"cluster","name":"prod-cluster","quorate":1},{"type":"node","name":"node-a","online":1,"pve_version":"8.2.2"},{"type":"node","name":"node-b","online":0,"pve_version":"8.2.2"}]`, 0)
	})
	name, quorumOK, nodes, reachable := collectPVECluster(context.Background())
	if name != "prod-cluster" || !quorumOK || !reachable {
		t.Errorf("name=%q quorum=%v reachable=%v", name, quorumOK, reachable)
	}
	if len(nodes) != 2 || nodes[1].Online {
		t.Errorf("nodes = %+v", nodes)
	}
}

func TestCollectPVECluster_NotQuorate(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/status", "--output-format", "json"},
			`[{"type":"cluster","name":"prod-cluster","quorate":0}]`, 0)
	})
	_, quorumOK, _, reachable := collectPVECluster(context.Background())
	if quorumOK || !reachable {
		t.Errorf("quorum=%v reachable=%v, want false/true", quorumOK, reachable)
	}
}

func TestCollectPVECluster_Unreachable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/cluster/status", "--output-format", "json"})
	})
	name, quorumOK, nodes, reachable := collectPVECluster(context.Background())
	if name != "" || quorumOK || nodes != nil || reachable {
		t.Errorf("expected zero values, got name=%q quorum=%v nodes=%v reachable=%v", name, quorumOK, nodes, reachable)
	}
}

func TestCollectPVECluster_BadJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/status", "--output-format", "json"}, "garbage", 0)
	})
	_, _, _, reachable := collectPVECluster(context.Background())
	if reachable {
		t.Error("expected reachable=false on unparseable body")
	}
}

func TestCollectPVEHAFencing_NoHAConfigured(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/ha/status/current", "--output-format", "json"},
			`[{"id":"quorum","type":"quorum","status":"OK"}]`, 0)
	})
	ok, msg, verified := collectPVEHAFencing(context.Background())
	if !ok || msg != "" || !verified {
		t.Errorf("ok=%v msg=%q verified=%v, want true/empty/true", ok, msg, verified)
	}
}

func TestCollectPVEHAFencing_Fenced(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/ha/status/current", "--output-format", "json"},
			`[{"id":"quorum","type":"quorum","status":"OK"},{"id":"vm:100","type":"service","status":"fence"}]`, 0)
	})
	ok, msg, verified := collectPVEHAFencing(context.Background())
	if ok || msg == "" || !verified {
		t.Errorf("ok=%v msg=%q verified=%v, want false/nonempty/true", ok, msg, verified)
	}
}

func TestCollectPVEHAFencing_APIAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/cluster/ha/status/current", "--output-format", "json"})
	})
	ok, msg, verified := collectPVEHAFencing(context.Background())
	if !ok || msg != "" || !verified {
		t.Errorf("ok=%v msg=%q verified=%v, want true/empty/true (HA not available is not a failure)", ok, msg, verified)
	}
}

func TestCollectPVEHAFencing_Unparseable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/cluster/ha/status/current", "--output-format", "json"}, "garbage", 0)
	})
	ok, _, verified := collectPVEHAFencing(context.Background())
	if !ok || verified {
		t.Errorf("ok=%v verified=%v, want true/false", ok, verified)
	}
}

func TestCollectPVEStorages_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/storage", "--output-format", "json"},
			`[{"storage":"local","type":"dir","used":5368709120,"total":10737418240,"active":1}]`, 0)
	})
	storages, verified := collectPVEStorages(context.Background())
	if !verified {
		t.Fatal("expected verified=true")
	}
	if len(storages) != 1 {
		t.Fatalf("expected 1 storage, got %d", len(storages))
	}
	s := storages[0]
	if s.Name != "local" || s.UsedGB != 5 || s.TotalGB != 10 || s.UsedPct != 50 {
		t.Errorf("storage = %+v", s)
	}
}

func TestCollectPVEStorages_Error(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/storage", "--output-format", "json"})
	})
	storages, verified := collectPVEStorages(context.Background())
	if storages != nil || verified {
		t.Errorf("expected nil/false on error, got %v/%v", storages, verified)
	}
}

func TestCollectPVEGuests_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/qemu", "--output-format", "json"},
			`[{"vmid":100,"name":"web","status":"running","cpus":2,"maxmem":2147483648},{"vmid":101,"name":"tpl","status":"stopped","template":1}]`, 0)
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/lxc", "--output-format", "json"},
			`[{"vmid":200,"name":"ct1","status":"paused"}]`, 0)
	})
	guests, running, stopped, paused := collectPVEGuests(context.Background())
	if len(guests) != 3 {
		t.Fatalf("expected 3 guests, got %d", len(guests))
	}
	if running != 1 || stopped != 1 || paused != 1 {
		t.Errorf("running=%d stopped=%d paused=%d, want 1/1/1", running, stopped, paused)
	}
}

func TestCollectPVEGuests_QemuFailsLXCSucceeds(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/qemu", "--output-format", "json"})
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/lxc", "--output-format", "json"},
			`[{"vmid":200,"name":"ct1","status":"running"}]`, 0)
	})
	guests, running, _, _ := collectPVEGuests(context.Background())
	if len(guests) != 1 || running != 1 {
		t.Errorf("expected 1 running guest from lxc despite qemu failure, got %d guests running=%d", len(guests), running)
	}
}

func TestCollectPVEResourceUsage(t *testing.T) {
	t.Parallel()
	guests := []models.PVEGuest{
		{VMID: 100, Status: "running", CPUs: 2, MaxMemGB: 4},
		{VMID: 101, Status: "stopped", CPUs: 4, MaxMemGB: 8},
		{VMID: 102, Status: "running", CPUs: 1, MaxMemGB: 2},
	}
	vcpus, memGB := collectPVEResourceUsage(guests)
	if vcpus != 3 {
		t.Errorf("vcpus = %d, want 3 (stopped guest excluded)", vcpus)
	}
	if memGB != 6 {
		t.Errorf("memGB = %v, want 6", memGB)
	}
}

func TestCollectPhysicalCores_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/cpuinfo", []byte(
			"physical id\t: 0\ncore id\t\t: 0\n\nphysical id\t: 0\ncore id\t\t: 1\n\nphysical id\t: 0\ncore id\t\t: 0\n"))
	})
	// Two distinct (physical,core) pairs seen: (0,0) and (0,1); (0,0) repeats (hyperthread sibling).
	if got := collectPhysicalCores(); got != 2 {
		t.Errorf("collectPhysicalCores() = %d, want 2", got)
	}
}

func TestCollectPhysicalCores_FallsBackToNumCPU(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/cpuinfo", []byte("model name\t: Fake CPU\n"))
	})
	if got := collectPhysicalCores(); got <= 0 {
		t.Errorf("collectPhysicalCores() = %d, want runtime.NumCPU() fallback (>0)", got)
	}
}

func TestCollectHostMemGB(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/meminfo", []byte("MemTotal:       16777216 kB\nMemFree:        1000 kB\n"))
	})
	if got := collectHostMemGB(); got != 16 {
		t.Errorf("collectHostMemGB() = %v, want 16", got)
	}
}

func TestCollectHostMemGB_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := collectHostMemGB(); got != 0 {
		t.Errorf("collectHostMemGB() = %v, want 0", got)
	}
}

func TestCollectPVETaskErrors_Happy(t *testing.T) {
	now := time.Now()
	withFixtureSource(t, func(b *source.Bundle) {
		recent := now.Add(-1 * time.Hour).Unix()
		old := now.Add(-48 * time.Hour).Unix()
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/tasks", "--limit", "100", "--output-format", "json"},
			`[{"type":"vzdump","id":"100","exitstatus":"backup failed","status":"stopped","starttime":`+strconv.FormatInt(recent, 10)+`},`+
				`{"type":"qmigrate","id":"101","exitstatus":"OK","status":"stopped","starttime":`+strconv.FormatInt(recent, 10)+`},`+
				`{"type":"vzdump","id":"102","exitstatus":"failed","status":"stopped","starttime":`+strconv.FormatInt(old, 10)+`}]`, 0)
	})
	errs, verified := collectPVETaskErrors(context.Background())
	if !verified {
		t.Fatal("expected verified=true")
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 recent task error (old one excluded by 24h cutoff), got %d: %+v", len(errs), errs)
	}
	if errs[0].VMID != "100" || errs[0].Msg != "backup failed" {
		t.Errorf("err = %+v", errs[0])
	}
}

func TestCollectPVETaskErrors_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/tasks", "--limit", "100", "--output-format", "json"})
	})
	errs, verified := collectPVETaskErrors(context.Background())
	if errs != nil || verified {
		t.Errorf("expected nil/false on query failure, got %v/%v", errs, verified)
	}
}

func TestCollectPVEBridges_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/network", "--output-format", "json"},
			`[{"iface":"vmbr0","type":"bridge","active":1,"bridge_ports":"eno1"},{"iface":"eno1","type":"eth","active":1}]`, 0)
		b.PutFile("/sys/class/net/vmbr0/bridge/stp_state", []byte("1\n"))
	})
	bridges := collectPVEBridges(context.Background())
	if len(bridges) != 1 {
		t.Fatalf("expected 1 bridge (eth iface excluded), got %d", len(bridges))
	}
	br := bridges[0]
	if br.Name != "vmbr0" || !br.Active || !br.HasUplink || !br.STPEnabled {
		t.Errorf("bridge = %+v", br)
	}
}

func TestCollectPVEBridges_QueryFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/network", "--output-format", "json"})
	})
	if got := collectPVEBridges(context.Background()); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestBridgeSTPEnabled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/net/vmbr0/bridge/stp_state", []byte("1\n"))
	})
	if !bridgeSTPEnabled("vmbr0") {
		t.Error("expected STP enabled")
	}
}

func TestBridgeSTPEnabled_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if bridgeSTPEnabled("vmbr0") {
		t.Error("expected STP disabled when sysfs file unreadable")
	}
}

func TestNewestBackupTime(t *testing.T) {
	t.Parallel()
	now := time.Now()
	byVM := map[int]time.Time{
		100: now.Add(-2 * 24 * time.Hour),
		101: now.Add(-5 * 24 * time.Hour),
	}
	got := newestBackupTime(byVM)
	if !got.Equal(byVM[100]) {
		t.Errorf("newestBackupTime() = %v, want %v (VMID 100, most recent)", got, byVM[100])
	}
}

func TestNewestBackupTime_Empty(t *testing.T) {
	t.Parallel()
	if got := newestBackupTime(nil); !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}

func TestScanBackupDumpDir(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		path := "/mnt/data/dump/vzdump-qemu-100-2024_06_03-19_16_09.vma.zst"
		b.PutGlob("/mnt/data/dump/vzdump-*.vma.zst", []string{path})
		b.PutStat(path, source.FileMeta{ModTime: time.Now().Add(-3 * 24 * time.Hour)})
	})
	got := scanBackupDumpDir()
	if len(got) != 1 {
		t.Fatalf("expected 1 VMID, got %d: %v", len(got), got)
	}
	if _, ok := got[100]; !ok {
		t.Error("expected VMID 100 present")
	}
}

func TestCollectPVEBackupAgeFromLogs_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/var/log/vzdump/*.log", []string{"/var/log/vzdump/qemu-100.log"})
		b.PutStat("/var/log/vzdump/qemu-100.log", source.FileMeta{ModTime: time.Now().Add(-4 * 24 * time.Hour)})
		b.PutFile("/var/log/vzdump/qemu-100.log", []byte("INFO: starting backup\nINFO: Backup job finished successfully\n"))
	})
	got := collectPVEBackupAgeFromLogs()
	if got != 4 {
		t.Errorf("collectPVEBackupAgeFromLogs() = %d, want 4", got)
	}
}

func TestCollectPVEBackupAgeFromLogs_NoSuccessLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/var/log/vzdump/*.log", []string{"/var/log/vzdump/qemu-100.log"})
		b.PutStat("/var/log/vzdump/qemu-100.log", source.FileMeta{ModTime: time.Now()})
		b.PutFile("/var/log/vzdump/qemu-100.log", []byte("ERROR: backup job failed\n"))
	})
	if got := collectPVEBackupAgeFromLogs(); got != -1 {
		t.Errorf("collectPVEBackupAgeFromLogs() = %d, want -1 (no success line)", got)
	}
}

func TestCollectPVEBackupAgeFromLogs_NoLogs(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := collectPVEBackupAgeFromLogs(); got != -1 {
		t.Errorf("collectPVEBackupAgeFromLogs() = %d, want -1", got)
	}
}

func TestCollectPVEBackups_ViaTasks(t *testing.T) {
	now := time.Now()
	withFixtureSource(t, func(b *source.Bundle) {
		end := now.Add(-2 * 24 * time.Hour).Unix()
		b.PutCmd("pvesh", []string{"get", "/nodes/localhost/tasks", "--output-format", "json", "--typefilter", "vzdump", "--limit", "200"},
			`[{"id":"100","status":"OK","endtime":`+strconv.FormatInt(end, 10)+`}]`, 0)
	})
	guests := []models.PVEGuest{{VMID: 100, Name: "web"}}
	tasks, ageDays, statuses, verified := collectPVEBackups(context.Background(), guests)
	if !verified {
		t.Fatal("expected verified=true")
	}
	if ageDays != 2 {
		t.Errorf("ageDays = %d, want 2", ageDays)
	}
	if len(tasks) == 0 {
		t.Error("expected recent task recorded (within 7-day window)")
	}
	if len(statuses) != 1 || statuses[0].LastBackupDays != 2 {
		t.Errorf("statuses = %+v", statuses)
	}
}

func TestCollectPVEBackups_PveshFailsFallsBackToDisk(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/tasks", "--output-format", "json", "--typefilter", "vzdump", "--limit", "200"})
		path := "/mnt/data/dump/vzdump-qemu-100-2024_06_03-19_16_09.vma.zst"
		b.PutGlob("/mnt/data/dump/vzdump-*.vma.zst", []string{path})
		b.PutStat(path, source.FileMeta{ModTime: time.Now().Add(-6 * 24 * time.Hour)})
	})
	guests := []models.PVEGuest{{VMID: 100, Name: "web"}}
	_, ageDays, statuses, verified := collectPVEBackups(context.Background(), guests)
	if !verified {
		t.Error("expected verified=true from disk fallback")
	}
	if ageDays != 6 {
		t.Errorf("ageDays = %d, want 6", ageDays)
	}
	if len(statuses) != 1 || statuses[0].LastBackupDays != 6 {
		t.Errorf("statuses = %+v", statuses)
	}
}

func TestCollectPVEBackups_PveshFailsNoDiskData(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pvesh", []string{"get", "/nodes/localhost/tasks", "--output-format", "json", "--typefilter", "vzdump", "--limit", "200"})
	})
	guests := []models.PVEGuest{{VMID: 100, Name: "web"}}
	_, ageDays, statuses, verified := collectPVEBackups(context.Background(), guests)
	if verified {
		t.Error("expected verified=false when neither pvesh nor disk scan found anything")
	}
	if ageDays != -1 {
		t.Errorf("ageDays = %d, want -1", ageDays)
	}
	if len(statuses) != 1 || statuses[0].LastBackupDays != -1 {
		t.Errorf("statuses = %+v", statuses)
	}
}

func TestCollectPVEPerf_Available(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pveperf", source.FileMeta{})
		b.PutCmd("pveperf", []string{"/"},
			"CPU BOGOMIPS:      44800.00\nREGEX/SECOND:      1234567\nBUFFERED READS:    469.31 MB/sec\nAVERAGE SEEK TIME: 0.15 ms\nFSYNCS/SECOND:     2500.00\nDNS EXT:           25.30 ms\nDNS INT:           1.20 ms\n", 0)
	})
	perf := CollectPVEPerf(context.Background(), "/")
	if !perf.Available {
		t.Fatal("expected Available=true")
	}
	if perf.CPUBogomips != 44800.00 {
		t.Errorf("CPUBogomips = %v, want 44800", perf.CPUBogomips)
	}
	if perf.BufferedReadMB != 469.31 {
		t.Errorf("BufferedReadMB = %v, want 469.31", perf.BufferedReadMB)
	}
	if perf.FsyncsPerSec != 2500.00 {
		t.Errorf("FsyncsPerSec = %v, want 2500", perf.FsyncsPerSec)
	}
}

func TestCollectPVEPerf_NotAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	perf := collectPVEPerf(context.Background(), "/")
	if perf.Available {
		t.Error("expected Available=false when pveperf binary absent")
	}
}
