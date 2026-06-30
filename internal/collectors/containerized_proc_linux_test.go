//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

// On a Docker host the container's processes are visible in the host PID namespace,
// so a host-level service collector that scans /proc/<pid>/comm would otherwise pick
// up a containerized service and run a host check against it — found on an Alpine
// Docker host (VM 106, 2026-07-01): a container's nginx was flagged as a host nginx
// with a bogus "needs root" config message. Process-scan detection must ignore
// processes whose cgroup says they live in a container.
func TestProcessScanIgnoresContainerizedPIDs(t *testing.T) {
	// Real cgroup lines captured from the Alpine Docker host's /proc.
	const dockerCgroup = "0::/docker/4d41585046ddb8abb101e1d3328dfff0304bc959991d90cdbba5d121240d481c\n"
	const hostCgroup = "0::/system.slice/named.service\n"

	mkproc := func(dir, pid, comm, cgroup string) {
		base := filepath.Join(dir, pid)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Only a containerized named → NOT a host BIND service.
	onlyContainer := t.TempDir()
	mkproc(onlyContainer, "100", "named", dockerCgroup)
	if anyProcessNamedIn(onlyContainer, "named") {
		t.Errorf("a containerized named must NOT be detected as a host BIND service")
	}

	// A host named alongside a containerized one → host service is present.
	mixed := t.TempDir()
	mkproc(mixed, "100", "named", dockerCgroup)
	mkproc(mixed, "200", "named", hostCgroup)
	if !anyProcessNamedIn(mixed, "named") {
		t.Errorf("a host named must still be detected when a containerized named is also present")
	}

	// Direct helper checks against the real bytes.
	if !pidIsContainerizedIn(onlyContainer, "100") {
		t.Errorf("/docker/<id> cgroup must classify as containerized")
	}
	if pidIsContainerizedIn(mixed, "200") {
		t.Errorf("/system.slice/named.service cgroup must classify as host (not container)")
	}
	// Unreadable cgroup → treated as host (never hide a real host service).
	noCgroup := t.TempDir()
	if err := os.MkdirAll(filepath.Join(noCgroup, "300"), 0o755); err != nil {
		t.Fatal(err)
	}
	if pidIsContainerizedIn(noCgroup, "300") {
		t.Errorf("an unreadable cgroup must default to host, not container")
	}
}
