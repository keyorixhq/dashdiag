//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withContainerdFixture seeds a dial/unix/<path> outcome (dialOutcome routes
// through Cached) alongside Bundle fixtures (PutCmd etc.) into ONE source, via
// the shared withCombinedFixture guard — dialOutcome and runCmd both route
// through activeSource, and only one SetSource can be active at a time.
func withContainerdFixture(t *testing.T, dial map[string]byte, seed func(b *source.Bundle)) {
	t.Helper()
	cached := make(map[string][]byte, len(dial))
	for path, outcome := range dial {
		cached["dial/unix/"+path] = []byte{outcome}
	}
	withCombinedFixture(t, cached, nil, seed)
}

func TestContainerdCollectorIdentity(t *testing.T) {
	c := NewContainerdCollector()
	if c == nil {
		t.Fatal("NewContainerdCollector returned nil")
	}
	if c.Name() != "Containerd" {
		t.Errorf("Name() = %q, want Containerd", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
}

func TestFindCtr_First(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"version"}, "Client:\n  Version: 1.6.24\n", 0)
	})
	if got := findCtr(context.Background()); got != "ctr" {
		t.Errorf("findCtr() = %q, want ctr", got)
	}
}

func TestFindCtr_FallsBackToK3sPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ctr", []string{"version"})
		b.PutCmdNotFound("containerd-ctr", []string{"version"})
		b.PutCmd("/usr/local/bin/ctr", []string{"version"}, "Client:\n  Version: 1.7.0\n", 0)
	})
	if got := findCtr(context.Background()); got != "/usr/local/bin/ctr" {
		t.Errorf("findCtr() = %q, want /usr/local/bin/ctr", got)
	}
}

// TestFindCtr_SkipsEmptyOutput guards the `out != ""` condition: a binary
// that runs successfully (exit 0) but prints nothing must be treated as not
// usable, and the search must continue to the next candidate.
func TestFindCtr_SkipsEmptyOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"version"}, "", 0) // exits 0 but no output — not usable
		b.PutCmd("containerd-ctr", []string{"version"}, "Client:\n  Version: 1.6.24\n", 0)
	})
	if got := findCtr(context.Background()); got != "containerd-ctr" {
		t.Errorf("findCtr() = %q, want containerd-ctr (ctr's empty-output result must be skipped)", got)
	}
}

func TestFindCtr_NoneFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		for _, bin := range ctrBinaries {
			b.PutCmdNotFound(bin, []string{"version"})
		}
	})
	if got := findCtr(context.Background()); got != "" {
		t.Errorf("findCtr() = %q, want empty", got)
	}
}

// TestFindCtr_ContextCancelled guards subprocess-wrappers-02: findCtr
// previously ran each candidate binary's `version` probe via
// runCmd(context.Background(), ...), decoupled from the collector's own ctx.
// Inject a mock Exec that only resolves after a real ctx.Done() (or a 2s
// fallback per candidate) and call with an already-cancelled ctx: with the
// collector's ctx genuinely threaded through, every candidate's runCmd call
// returns almost immediately; the pre-fix code (a hidden context.Background()
// call) would instead ride out the full 2s window on EACH of the four
// candidates in ctrBinaries.
func TestFindCtr_ContextCancelled(t *testing.T) {
	prev := SetSource(source.Live{Exec: func(ctx context.Context, _ string, _ ...string) (source.Result, error) {
		select {
		case <-ctx.Done():
			return source.Result{}, ctx.Err()
		case <-time.After(2 * time.Second):
			return source.Result{Stdout: []byte("Client:\n  Version: 1.6.24\n")}, nil
		}
	}})
	defer SetSource(prev)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before findCtr ever runs

	start := time.Now()
	got := findCtr(ctx)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("findCtr took %v with an already-cancelled ctx — want a fast return via ctx.Done() for every candidate, not riding out the mock's 2s window per binary (ctx not propagated to runCmd)", elapsed)
	}
	if got != "" {
		t.Errorf("findCtr() = %q, want empty — every candidate's version probe should have been cancelled", got)
	}
}

func TestContainerdK8sManaged_True(t *testing.T) {
	seedDialOutcome(t, "unix", "/run/k3s/containerd/containerd.sock", '1')
	if !ContainerdK8sManaged() {
		t.Error("ContainerdK8sManaged() = false, want true")
	}
}

func TestContainerdK8sManaged_False(t *testing.T) {
	seedDialOutcome(t, "unix", "/run/k3s/containerd/containerd.sock", '0')
	if ContainerdK8sManaged() {
		t.Error("ContainerdK8sManaged() = true, want false")
	}
}

func TestContainerdServiceState_Active(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "containerd", "--property=ActiveState"}, "ActiveState=active\n", 0)
	})
	if got := containerdServiceState(context.Background()); got != "active" {
		t.Errorf("containerdServiceState() = %q, want active", got)
	}
}

func TestContainerdServiceState_Unknown(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "containerd", "--property=ActiveState"})
	})
	if got := containerdServiceState(context.Background()); got != "unknown" {
		t.Errorf("containerdServiceState() = %q, want unknown", got)
	}
}

// TestContainerdServiceState_NoActiveStateLine guards the fall-through when
// the command succeeds with non-empty output but no line carries the
// "ActiveState=" prefix — must return "unknown", not panic or return "".
func TestContainerdServiceState_NoActiveStateLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "containerd", "--property=ActiveState"}, "SomeOtherProperty=foo\n", 0)
	})
	if got := containerdServiceState(context.Background()); got != "unknown" {
		t.Errorf("containerdServiceState() = %q, want unknown when no ActiveState= line is present", got)
	}
}

const ctrVersionOutput = `Client:
  Version:  1.6.24
  Revision: 61f9fd88f79f081d64d6fa3bb1a0dc71ec870523
  Go version: go1.20.10

Server:
  Version:  1.6.24
  Revision: 61f9fd88f79f081d64d6fa3bb1a0dc71ec870523
  UUID: 12345678-1234-1234-1234-123456789012
`

func TestContainerdVersion_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"version"}, ctrVersionOutput, 0)
	})
	if got := containerdVersion(context.Background(), "ctr"); got != "1.6.24" {
		t.Errorf("containerdVersion() = %q, want 1.6.24 (the Server block)", got)
	}
}

func TestContainerdVersion_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ctr", []string{"version"})
	})
	if got := containerdVersion(context.Background(), "ctr"); got != "" {
		t.Errorf("containerdVersion() = %q, want empty", got)
	}
}

func TestContainerdVersion_NoServerBlock(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"version"}, "Client:\n  Version: 1.6.24\n", 0)
	})
	if got := containerdVersion(context.Background(), "ctr"); got != "" {
		t.Errorf("containerdVersion() = %q, want empty (no Server: block)", got)
	}
}

// TestContainerdVersion_ServerBlockEndsBeforeVersionLine guards the early
// break: once inside the Server: block, a non-indented, non-empty line (the
// start of a new top-level section) before any "Version:" line is found must
// stop the scan and return "" rather than keep scanning past the block.
func TestContainerdVersion_ServerBlockEndsBeforeVersionLine(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"version"},
			"Server:\nUUID: 12345678-1234-1234-1234-123456789012\n  Version:  1.6.24\n", 0)
	})
	if got := containerdVersion(context.Background(), "ctr"); got != "" {
		t.Errorf("containerdVersion() = %q, want empty (Server block ended before a Version: line)", got)
	}
}

func TestContainerdNamespaces_Multiple(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "default\nk8s.io\n", 0)
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "c1\nc2\n", 0)
		b.PutCmd("ctr", []string{"-n", "k8s.io", "containers", "list", "-q"}, "", 0)
	})
	ns, truncated := containerdNamespaces(context.Background(), "ctr")
	if truncated {
		t.Error("truncated = true, want false — only 2 namespaces, well under the cap")
	}
	if len(ns) != 2 {
		t.Fatalf("namespaces = %+v, want 2", ns)
	}
	if ns[0].Name != "default" || ns[0].ContainerCount != 2 {
		t.Errorf("ns[0] = %+v, want default/2", ns[0])
	}
	if ns[1].Name != "k8s.io" || ns[1].ContainerCount != 0 {
		t.Errorf("ns[1] = %+v, want k8s.io/0", ns[1])
	}
}

// TestContainerdNamespaces_SkipsBlankLines guards the mid-list blank-line
// continue: a stray blank line between two real namespace names must not
// produce a spurious empty-named entry.
func TestContainerdNamespaces_SkipsBlankLines(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "default\n\nk8s.io\n", 0)
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "", 0)
		b.PutCmd("ctr", []string{"-n", "k8s.io", "containers", "list", "-q"}, "", 0)
	})
	ns, truncated := containerdNamespaces(context.Background(), "ctr")
	if truncated {
		t.Error("truncated = true, want false — only 2 namespaces, well under the cap")
	}
	if len(ns) != 2 {
		t.Fatalf("namespaces = %+v, want 2 (blank line skipped, not a 3rd empty entry)", ns)
	}
	for _, n := range ns {
		if n.Name == "" {
			t.Errorf("a blank namespace name leaked through: %+v", ns)
		}
	}
}

func TestContainerdNamespaces_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ctr", []string{"namespaces", "list", "-q"})
	})
	if ns, truncated := containerdNamespaces(context.Background(), "ctr"); ns != nil || truncated {
		t.Errorf("containerdNamespaces() = (%+v,%v), want (nil,false)", ns, truncated)
	}
}

// TestContainerdNamespaces_CapsAtMax is the regression guard for
// internal-collectors-05-04: containerdNamespaces used to fan out ONE `ctr -n
// <ns> containers list -q` subprocess per reported namespace with no upper
// bound — a namespace-bombing host could exhaust the process table. With more
// than maxContainerdNamespaces namespaces reported, only the first
// maxContainerdNamespaces (sorted, for reproducibility) must actually be
// enumerated, and truncated must be true so the caller can't mistake the
// partial count for the complete namespace list.
func TestContainerdNamespaces_CapsAtMax(t *testing.T) {
	total := maxContainerdNamespaces + 5
	names := make([]string, total)
	for i := range names {
		names[i] = fmt.Sprintf("ns%03d", i) // zero-padded so lexical sort == numeric order
	}
	nsListOutput := strings.Join(names, "\n") + "\n"

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, nsListOutput, 0)
		// Seed a container for each namespace that must actually be
		// enumerated (the first maxContainerdNamespaces, sorted) so a bug
		// that enumerates the WRONG subset — rather than merely too many —
		// is also caught.
		for i := range maxContainerdNamespaces {
			b.PutCmd("ctr", []string{"-n", names[i], "containers", "list", "-q"}, "c1\n", 0)
		}
	})

	ns, truncated := containerdNamespaces(context.Background(), "ctr")
	if !truncated {
		t.Fatal("truncated = false, want true when more namespaces were reported than the cap")
	}
	if len(ns) != maxContainerdNamespaces {
		t.Fatalf("len(ns) = %d, want %d (capped)", len(ns), maxContainerdNamespaces)
	}
	if ns[0].Name != "ns000" || ns[0].ContainerCount != 1 {
		t.Errorf("ns[0] = %+v, want ns000/1", ns[0])
	}
	if last := ns[len(ns)-1]; last.Name != fmt.Sprintf("ns%03d", maxContainerdNamespaces-1) {
		t.Errorf("last enumerated namespace = %q, want the (maxContainerdNamespaces-1)th sorted name — got the wrong subset, not just the wrong count", last.Name)
	}
}

// TestContainerdCollector_Collect_NamespacesTruncated drives the cap through
// the full Collect() pipeline, confirming ContainerdInfo.NamespacesTruncated
// is wired from containerdNamespaces' second return value.
func TestContainerdCollector_Collect_NamespacesTruncated(t *testing.T) {
	total := maxContainerdNamespaces + 1
	names := make([]string, total)
	for i := range names {
		names[i] = fmt.Sprintf("ns%03d", i)
	}
	nsListOutput := strings.Join(names, "\n") + "\n"

	withContainerdFixture(t, map[string]byte{containerdSocketCandidates[0]: '1'}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "containerd", "--property=ActiveState"}, "ActiveState=active\n", 0)
		b.PutCmd("ctr", []string{"version"}, ctrVersionOutput, 0)
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, nsListOutput, 0)
	})

	c := NewContainerdCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerdInfo)
	if !info.NamespacesTruncated {
		t.Error("NamespacesTruncated = false, want true when more namespaces were reported than the cap")
	}
	if len(info.Namespaces) != maxContainerdNamespaces {
		t.Errorf("len(Namespaces) = %d, want %d (capped)", len(info.Namespaces), maxContainerdNamespaces)
	}
}

func TestContainerdContainerCount(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "abc123\ndef456\nghi789\n", 0)
	})
	if got := containerdContainerCount(context.Background(), "ctr", "default"); got != 3 {
		t.Errorf("containerdContainerCount() = %d, want 3", got)
	}
}

func TestContainerdContainerCount_Empty(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "", 0)
	})
	if got := containerdContainerCount(context.Background(), "ctr", "default"); got != 0 {
		t.Errorf("containerdContainerCount() = %d, want 0", got)
	}
}

func TestContainerdContainerCount_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ctr", []string{"-n", "default", "containers", "list", "-q"})
	})
	if got := containerdContainerCount(context.Background(), "ctr", "default"); got != 0 {
		t.Errorf("containerdContainerCount() = %d, want 0", got)
	}
}

// TestContainerdCollector_Collect_SocketAbsent covers the "not installed" gate:
// Status/StatusReason are set and no further probing happens.
func TestContainerdCollector_Collect_SocketAbsent(t *testing.T) {
	dial := map[string]byte{}
	for _, c := range containerdSocketCandidates {
		dial[c] = '0'
	}
	withContainerdFixture(t, dial, nil)
	c := NewContainerdCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerdInfo)
	if info.Available || info.Status != "unavailable" || info.StatusReason == "" {
		t.Errorf("info = %+v, want Available=false Status=unavailable with a reason", info)
	}
}

// TestContainerdCollector_Collect_SocketPermDenied covers the "installed but
// permission-denied" gate (distinct from genuinely absent): Collect must set
// SocketPermDenied and a human-readable StatusReason without probing further
// (no ctr call attempted).
func TestContainerdCollector_Collect_SocketPermDenied(t *testing.T) {
	dial := map[string]byte{containerdSocketCandidates[0]: 'p'} // 'p' = permission-denied outcome
	withContainerdFixture(t, dial, nil)
	c := NewContainerdCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerdInfo)
	if info.Available {
		t.Error("Available = true, want false when the socket is permission-denied")
	}
	if !info.SocketPermDenied {
		t.Error("SocketPermDenied = false, want true")
	}
	if info.Status != "unavailable" || info.StatusReason == "" {
		t.Errorf("info = %+v, want Status=unavailable with a non-empty reason", info)
	}
	if info.SocketPath != containerdSocketCandidates[0] {
		t.Errorf("SocketPath = %q, want %q even though permission was denied", info.SocketPath, containerdSocketCandidates[0])
	}
}

// TestContainerdCollector_Collect_FullHappyPath drives the entire pipeline once
// the socket is reachable: service active, ctr found, two namespaces with
// containers, TotalContainers summed across both.
func TestContainerdCollector_Collect_FullHappyPath(t *testing.T) {
	withContainerdFixture(t, map[string]byte{containerdSocketCandidates[0]: '1'}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "containerd", "--property=ActiveState"}, "ActiveState=active\n", 0)
		b.PutCmd("ctr", []string{"version"}, ctrVersionOutput, 0)
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "default\nmoby\n", 0)
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "c1\n", 0)
		b.PutCmd("ctr", []string{"-n", "moby", "containers", "list", "-q"}, "c2\nc3\n", 0)
	})

	c := NewContainerdCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerdInfo)

	if !info.Available || info.SocketPath != containerdSocketCandidates[0] {
		t.Errorf("Available=%v SocketPath=%q, unexpected", info.Available, info.SocketPath)
	}
	if info.ServiceState != "active" {
		t.Errorf("ServiceState = %q, want active", info.ServiceState)
	}
	if info.Version != "1.6.24" {
		t.Errorf("Version = %q, want 1.6.24", info.Version)
	}
	if len(info.Namespaces) != 2 || info.TotalContainers != 3 {
		t.Errorf("Namespaces=%+v TotalContainers=%d, want 2 namespaces / 3 total", info.Namespaces, info.TotalContainers)
	}
	if !info.CtrBinaryFound {
		t.Error("CtrBinaryFound must be true when ctr version succeeded")
	}
}

// TestContainerdCollector_Collect_CtrBinaryMissing is a regression guard for
// internal-collectors-05-01: when the socket is reachable and the service is
// active but no ctr/containerd-ctr binary can be found, Namespaces/
// TotalContainers stay at their zero value — identical to a genuinely idle
// containerd — so CtrBinaryFound must be false to disclose that enumeration
// was never attempted.
func TestContainerdCollector_Collect_CtrBinaryMissing(t *testing.T) {
	withContainerdFixture(t, map[string]byte{containerdSocketCandidates[0]: '1'}, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "containerd", "--property=ActiveState"}, "ActiveState=active\n", 0)
		// No ctr/containerd-ctr/k3s-path/openSUSE-path binaries seeded — findCtr
		// returns "" for every candidate.
	})

	c := NewContainerdCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ContainerdInfo)

	if !info.Available {
		t.Error("Available must be true — the socket is reachable")
	}
	if info.CtrBinaryFound {
		t.Error("CtrBinaryFound must be false when no ctr binary was found")
	}
	if info.TotalContainers != 0 || info.Namespaces != nil {
		t.Errorf("expected zero-value Namespaces/TotalContainers, got %+v / %d", info.Namespaces, info.TotalContainers)
	}
}
