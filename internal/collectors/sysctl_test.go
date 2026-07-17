package collectors

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeLoadavgSource serves a fixed /proc/loadavg body and falls back to Live
// for everything else.
type fakeLoadavgSource struct {
	source.Live
	content string
}

func (f fakeLoadavgSource) ReadFile(path string) ([]byte, error) {
	if path == "/proc/loadavg" {
		return []byte(f.content), nil
	}
	return f.Live.ReadFile(path)
}

// TestReadTaskCount is a regression guard: kernel.pid_max governs the WHOLE
// task space (processes AND threads — every CLONE_THREAD thread gets its own
// slot under /proc/<pid>/task/<tid>), but countProcDirs() only counts
// top-level processes via /proc/[0-9]*. On a thread-heavy host (JVM/Go clone
// storm), that undercounts real PID-space usage, so genuine task exhaustion
// could read as a small, unconcerning percentage. readTaskCount must use
// /proc/loadavg's "running/total" field instead.
func TestReadTaskCount(t *testing.T) {
	t.Run("well-formed loadavg", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "0.52 0.43 0.32 3/412 8932\n"})
		defer SetSource(prev)
		if got := readTaskCount(); got != 412 {
			t.Errorf("got %d, want 412 (the total tasks field, not the process count)", got)
		}
	})

	t.Run("malformed loadavg falls back to process count", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "not loadavg data"})
		defer SetSource(prev)
		// Falls back to countProcDirs(); just confirm it doesn't panic and
		// returns a non-negative count (0 is valid on a host with no /proc glob
		// match, e.g. this test running on darwin).
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})

	t.Run("unreadable loadavg falls back to process count", func(t *testing.T) {
		prev := SetSource(erroringLoadavgSource{})
		defer SetSource(prev)
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})

	t.Run("running/total field has no slash falls back to process count", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "0.52 0.43 0.32 412 8932\n"})
		defer SetSource(prev)
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})

	t.Run("non-numeric total falls back to process count", func(t *testing.T) {
		prev := SetSource(fakeLoadavgSource{content: "0.52 0.43 0.32 3/notanumber 8932\n"})
		defer SetSource(prev)
		if got := readTaskCount(); got < 0 {
			t.Errorf("got %d, want >= 0", got)
		}
	})
}

type erroringLoadavgSource struct{ source.Live }

func (erroringLoadavgSource) ReadFile(string) ([]byte, error) {
	return nil, os.ErrPermission
}

func TestNewSysctlCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSysctlCollector()
	if c.Name() != "Sysctl" {
		t.Errorf("Name() = %q, want Sysctl", c.Name())
	}
	if c.Timeout() != 1*time.Second {
		t.Errorf("Timeout() = %v, want 1s", c.Timeout())
	}
}

// fakeSysctlSource serves a fixed set of /proc/sys/* and /proc files, and
// glob results for /proc/[0-9]* (used by detectWorkload), falling back to
// Live for everything else.
type fakeSysctlSource struct {
	source.Live
	files map[string]string
	glob  []string
}

func (f fakeSysctlSource) ReadFile(path string) ([]byte, error) {
	if v, ok := f.files[path]; ok {
		return []byte(v), nil
	}
	return nil, os.ErrNotExist
}

func (f fakeSysctlSource) Glob(pattern string) ([]string, error) {
	if pattern == "/proc/[0-9]*" {
		return f.glob, nil
	}
	return f.Live.Glob(pattern)
}

func TestSysctlCollector_CollectLinux_FullHappyPath(t *testing.T) {
	files := map[string]string{
		"/proc/sys/vm/swappiness":                "60\n",
		"/proc/sys/net/core/somaxconn":           "4096\n",
		"/proc/sys/fs/file-max":                  "9223372036854775807\n",
		"/proc/sys/kernel/pid_max":               "4194304\n",
		"/proc/sys/net/core/rmem_max":            "212992\n",
		"/proc/sys/net/core/wmem_max":            "212992\n",
		"/proc/sys/net/ipv4/tcp_tw_reuse":        "2\n",
		"/proc/sys/net/ipv4/tcp_max_syn_backlog": "4096\n",
		"/proc/sys/vm/max_map_count":             "65530\n",
		"/proc/sys/vm/dirty_ratio":               "20\n",
		"/proc/sys/vm/dirty_background_ratio":    "10\n",
		"/proc/sys/vm/overcommit_memory":         "0\n",
		"/proc/sys/fs/inotify/max_user_watches":  "8192\n",
		"/proc/loadavg":                          "0.52 0.43 0.32 3/412 8932\n",
		"/proc/uptime":                           "12345.67 98765.43\n",
	}
	prev := SetSource(fakeSysctlSource{files: files, glob: []string{"/proc/100"}})
	t.Cleanup(func() { SetSource(prev) })
	files["/proc/100/comm"] = "nginx\n"

	c := NewSysctlCollector()
	info, err := c.collectLinux()
	if err != nil {
		t.Fatalf("collectLinux() error: %v", err)
	}
	if !info.Available {
		t.Error("Available = false, want true")
	}
	if info.VMSwappiness != 60 || info.NetSomaxconn != 4096 || info.FSFileMax != 9223372036854775807 {
		t.Errorf("info = %+v, want VMSwappiness=60 NetSomaxconn=4096 FSFileMax=maxint64", info)
	}
	if info.KernelPIDMax != 4194304 {
		t.Errorf("KernelPIDMax = %d, want 4194304", info.KernelPIDMax)
	}
	if info.PIDCount != 412 {
		t.Errorf("PIDCount = %d, want 412 (from /proc/loadavg)", info.PIDCount)
	}
	if info.NetRmemMax != 212992 || info.NetWmemMax != 212992 {
		t.Errorf("info = %+v, want NetRmemMax=NetWmemMax=212992", info)
	}
	if info.TCPTWReuse != 2 {
		t.Errorf("TCPTWReuse = %d, want 2", info.TCPTWReuse)
	}
	if info.TCPSynBacklog != 4096 || info.VMMaxMapCount != 65530 {
		t.Errorf("info = %+v, want TCPSynBacklog=4096 VMMaxMapCount=65530", info)
	}
	if info.VMDirtyRatio != 20 || info.VMDirtyBackgroundRatio != 10 || info.VMOvercommit != 0 {
		t.Errorf("info = %+v, want VMDirtyRatio=20 VMDirtyBackgroundRatio=10 VMOvercommit=0", info)
	}
	if info.FSInotifyWatches != 8192 {
		t.Errorf("FSInotifyWatches = %d, want 8192", info.FSInotifyWatches)
	}
	if info.UptimeSeconds != 12345 {
		t.Errorf("UptimeSeconds = %d, want 12345", info.UptimeSeconds)
	}
	if info.Workload != "webserver" {
		t.Errorf("Workload = %q, want webserver", info.Workload)
	}
}

// TestSysctlCollector_CollectLinux_TCPTWReuseBoundary is a regression guard:
// a readable-and-0 tcp_tw_reuse must be recorded as 0 (not confused with the
// -1 "unknown" sentinel used when the file can't be read at all).
func TestSysctlCollector_CollectLinux_TCPTWReuseBoundary(t *testing.T) {
	t.Run("readable and 0", func(t *testing.T) {
		prev := SetSource(fakeSysctlSource{files: map[string]string{
			"/proc/sys/net/ipv4/tcp_tw_reuse": "0\n",
		}})
		t.Cleanup(func() { SetSource(prev) })
		c := NewSysctlCollector()
		info, err := c.collectLinux()
		if err != nil {
			t.Fatalf("collectLinux() error: %v", err)
		}
		if info.TCPTWReuse != 0 {
			t.Errorf("TCPTWReuse = %d, want 0 (real value, not the sentinel)", info.TCPTWReuse)
		}
	})

	t.Run("unreadable falls back to -1 sentinel", func(t *testing.T) {
		prev := SetSource(fakeSysctlSource{files: map[string]string{}})
		t.Cleanup(func() { SetSource(prev) })
		c := NewSysctlCollector()
		info, err := c.collectLinux()
		if err != nil {
			t.Fatalf("collectLinux() error: %v", err)
		}
		if info.TCPTWReuse != -1 {
			t.Errorf("TCPTWReuse = %d, want -1 sentinel", info.TCPTWReuse)
		}
	})
}

func TestSysctlCollector_CollectLinux_MissingFilesStayZeroValue(t *testing.T) {
	prev := SetSource(fakeSysctlSource{files: map[string]string{}})
	t.Cleanup(func() { SetSource(prev) })
	c := NewSysctlCollector()
	info, err := c.collectLinux()
	if err != nil {
		t.Fatalf("collectLinux() error: %v (best-effort, must never error)", err)
	}
	if !info.Available {
		t.Error("Available = false, want true (best-effort even with nothing readable)")
	}
	if info.VMSwappiness != 0 || info.NetSomaxconn != 0 || info.FSFileMax != 0 {
		t.Errorf("info = %+v, want all zero-value on missing files", info)
	}
	if info.TCPTWReuse != -1 {
		t.Errorf("TCPTWReuse = %d, want -1 sentinel", info.TCPTWReuse)
	}
}

func TestDetectWorkload(t *testing.T) {
	tests := []struct {
		name  string
		comms []string
		want  string
	}{
		{"k8s via kubelet", []string{"kubelet"}, "k8s"},
		{"k8s via k3s", []string{"k3s"}, "k8s"},
		{"k8s via k3s-server", []string{"k3s-server"}, "k8s"},
		{"webserver via nginx", []string{"nginx"}, "webserver"},
		{"webserver via apache2", []string{"apache2"}, "webserver"},
		{"webserver via httpd", []string{"httpd"}, "webserver"},
		{"webserver via caddy", []string{"caddy"}, "webserver"},
		{"webserver via haproxy", []string{"haproxy"}, "webserver"},
		{"database via postgres", []string{"postgres"}, "database"},
		{"database via mysqld", []string{"mysqld"}, "database"},
		{"database via mongod", []string{"mongod"}, "database"},
		{"database via redis-server", []string{"redis-server"}, "database"},
		{"database via mariadbd", []string{"mariadbd"}, "database"},
		{"elasticsearch requires java AND elasticsearch", []string{"java", "elasticsearch"}, "elasticsearch"},
		{"elasticsearch requires java AND kibana", []string{"java", "kibana"}, "elasticsearch"},
		{"java alone does not trigger elasticsearch", []string{"java"}, "default"},
		{"elasticsearch process alone does not trigger elasticsearch", []string{"elasticsearch"}, "default"},
		{"container via dockerd", []string{"dockerd"}, "container"},
		{"container via containerd", []string{"containerd"}, "container"},
		{"default when none match", []string{"bash", "sshd"}, "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			var dirs []string
			for i, comm := range tt.comms {
				dir := "/proc/" + string(rune('0'+i))
				dirs = append(dirs, dir)
				files[dir+"/comm"] = comm + "\n"
			}
			prev := SetSource(fakeSysctlSource{files: files, glob: dirs})
			t.Cleanup(func() { SetSource(prev) })
			if got := detectWorkload(); got != tt.want {
				t.Errorf("detectWorkload() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDetectWorkload_UnreadableCommSkipped guards the readFile-error branch:
// a /proc/<pid>/comm that can't be read must be skipped, not abort the scan
// or count as an empty-string workload match.
func TestDetectWorkload_UnreadableCommSkipped(t *testing.T) {
	files := map[string]string{
		"/proc/1/comm": "nginx\n",
		// /proc/2/comm intentionally unseeded -> readFile fails -> skipped.
	}
	prev := SetSource(fakeSysctlSource{files: files, glob: []string{"/proc/1", "/proc/2"}})
	t.Cleanup(func() { SetSource(prev) })
	if got := detectWorkload(); got != "webserver" {
		t.Errorf("detectWorkload() = %q, want webserver (unreadable comm skipped, not fatal)", got)
	}
}

func TestSysctlCollector_CollectDarwin(t *testing.T) {
	t.Parallel()
	c := NewSysctlCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("collectDarwin() error: %v", err)
	}
	if info.Available {
		t.Error("Available = true, want false")
	}
}

// TestSysctlCollector_Collect_DispatchesOnGOOS confirms Collect() routes to
// whichever branch matches the actual test-runtime GOOS -- this test suite
// runs under linux (per the Docker coverage harness), so Available should be
// true there; the assertion is written generically so it also holds on darwin.
func TestSysctlCollector_Collect_DispatchesOnGOOS(t *testing.T) {
	prev := SetSource(fakeSysctlSource{files: map[string]string{
		"/proc/sys/vm/swappiness": "60\n",
	}})
	t.Cleanup(func() { SetSource(prev) })
	c := NewSysctlCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.SysctlInfo)
	wantAvailable := runtime.GOOS != "darwin"
	if info.Available != wantAvailable {
		t.Errorf("Available = %v, want %v for GOOS=%s", info.Available, wantAvailable, runtime.GOOS)
	}
}

func TestReadIntFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		content string
		want    int
		wantErr bool
	}{
		{"integer value", "128\n", 128, false},
		{"integer no newline", "4096", 4096, false},
		{"zero", "0\n", 0, false},
		{"large value", "1048576\n", 1048576, false},
		{"empty file", "", 0, true},
		{"non-numeric", "abc\n", 0, true},
		{"float value", "1.5\n", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := os.CreateTemp(t.TempDir(), "sysctl-*")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(tc.content); err != nil {
				t.Fatal(err)
			}
			f.Close()

			got, err := readIntFile(f.Name())
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				return
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestReadIntFile_ReadError_Source covers sysctl.go:29.16,31.3 — the readFile
// error branch when the fixture bundle has no entry for the path.
func TestReadIntFile_ReadError_Source(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("source-routed reads only on Linux")
	}
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {})
	_, err := readIntFile("/proc/sys/vm/swappiness")
	if err == nil {
		t.Error("expected error when file is not in replay bundle")
	}
}

// TestReadIntFile_ParseError_Source covers sysctl.go:33.25,35.3 — the
// strconv.Atoi error branch when the file contains non-numeric content.
func TestReadIntFile_ParseError_Source(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("source-routed reads only on Linux")
	}
	// no t.Parallel(): withFixtureSource mutates the package-level activeSource.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/vm/swappiness", []byte("not-a-number\n"))
	})
	_, err := readIntFile("/proc/sys/vm/swappiness")
	if err == nil {
		t.Error("expected error parsing non-numeric sysctl content")
	}
}
