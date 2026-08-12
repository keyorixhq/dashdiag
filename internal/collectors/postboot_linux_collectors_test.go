//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// withPostBootFixture needs the Cached dimension the shared withCombinedFixture
// (see security_linux_source_test.go) provides — lookPathOK("journalctl")
// (routes through lookPath -> Cached "lookpath/...") and
// ContainerContextViaSource (routes through cachedJSON
// "platform/container-context") both go through Cached.
func withPostBootFixture(t *testing.T, cached map[string][]byte, seed func(b *source.Bundle)) {
	t.Helper()
	withCombinedFixture(t, cached, nil, seed)
}

func containerContextJSON(t *testing.T, cc platform.ContainerContext) []byte {
	t.Helper()
	data, err := json.Marshal(cc)
	if err != nil {
		t.Fatalf("marshal ContainerContext: %v", err)
	}
	return data
}

func TestPostBootCollectorIdentity(t *testing.T) {
	c := NewPostBootCollector()
	if c == nil {
		t.Fatal("NewPostBootCollector returned nil")
	}
	if c.Name() != "PostBoot" {
		t.Errorf("Name() = %q, want PostBoot", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

func TestPostBootAvailable_InContainer(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{InContainer: true}),
		"lookpath/journalctl":        []byte("/usr/bin/journalctl"),
	}, nil)
	if PostBootAvailable() {
		t.Error("PostBootAvailable() = true in a container, want false")
	}
}

func TestPostBootAvailable_JournalctlPresent(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
		"lookpath/journalctl":        []byte("/usr/bin/journalctl"),
	}, nil)
	if !PostBootAvailable() {
		t.Error("PostBootAvailable() = false, want true (journalctl present)")
	}
}

func TestPostBootAvailable_WtmpOnly(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
	}, func(b *source.Bundle) {
		b.PutStat("/var/log/wtmp", source.FileMeta{})
	})
	if !PostBootAvailable() {
		t.Error("PostBootAvailable() = false, want true (wtmp present)")
	}
}

func TestPostBootAvailable_NeitherSource(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
	}, nil)
	if PostBootAvailable() {
		t.Error("PostBootAvailable() = true, want false (no journalctl, no wtmp)")
	}
}

func TestLivePostBootEnv(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"lookpath/journalctl": []byte("/usr/bin/journalctl"),
	}, func(b *source.Bundle) {
		b.PutStat("/var/log/wtmp", source.FileMeta{})
	})
	env := livePostBootEnv(context.Background())
	if !env.isSystemd {
		t.Error("isSystemd = false, want true (journalctl found)")
	}
	if !env.hasWtmp {
		t.Error("hasWtmp = false, want true")
	}
	if env.readDir == nil || env.countPriorBoots == nil {
		t.Error("readDir/countPriorBoots must be wired, not nil")
	}
}

func TestCountPriorBootsLive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--list-boots", "--no-pager", "-q"},
			"-2 abc 2026-05-01\n-1 def 2026-05-15\n 0 ghi 2026-06-01\n", 0)
	})
	n, err := countPriorBootsLive(context.Background())
	if err != nil {
		t.Fatalf("countPriorBootsLive error: %v", err)
	}
	if n != 2 {
		t.Errorf("countPriorBootsLive = %d, want 2 (3 lines - current)", n)
	}
}

func TestCountPriorBootsLive_OnlyCurrentBoot(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--list-boots", "--no-pager", "-q"}, " 0 ghi 2026-06-01\n", 0)
	})
	n, err := countPriorBootsLive(context.Background())
	if err != nil || n != 0 {
		t.Errorf("countPriorBootsLive = (%d,%v), want (0,nil)", n, err)
	}
}

func TestCountPriorBootsLive_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--list-boots", "--no-pager", "-q"}, "", 1)
	})
	if _, err := countPriorBootsLive(context.Background()); err == nil {
		t.Error("countPriorBootsLive error = nil, want an error (EACCES-style failure)")
	}
}

const postBootOOMJournal = `2026-05-17T09:12:34+0000 kernel: Out of memory: Kill process 12345 (nginx) score 900 or sacrifice child
2026-05-17T09:12:34+0000 kernel: Killed process 12345 (nginx) total-vm:2048kB, anon-rss:1024kB, file-rss:0kB
2026-05-17T09:12:41+0000 kernel: Out of memory: Kill process 23456 (php-fpm) score 750 or sacrifice child
2026-05-17T09:12:41+0000 kernel: Killed process 23456 (php-fpm) total-vm:4096kB, anon-rss:3072kB, file-rss:0kB
`

func TestPriorBootOOM_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			postBootOOMJournal, 0)
	})
	kills, victims, checked := priorBootOOM(context.Background())
	// parseOOMEvents dedupes by pid+process, so the matching "Out of memory" and
	// "Killed process" lines for the SAME pid collapse to one event each — 2
	// distinct victims here, not 4 matching lines.
	if kills != 2 {
		t.Errorf("kills = %d, want 2 (deduped by pid+process)", kills)
	}
	if len(victims) != 2 || victims[0] != "nginx" || victims[1] != "php-fpm" {
		t.Errorf("victims = %v, want [nginx php-fpm]", victims)
	}
	if !checked {
		t.Error("checked = false, want true — the sub-call succeeded and the scan was clean")
	}
}

// TestPriorBootOOM_GrepNoMatchIsChecked is the regression guard for
// internal-collectors-26-01: journalctl --grep exits 1 on zero matches — the
// routine, healthy case of finding nothing — and must set checked=true, not
// be confused with a genuine sub-call failure.
func TestPriorBootOOM_GrepNoMatchIsChecked(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			"", 1)
	})
	kills, victims, checked := priorBootOOM(context.Background())
	if kills != 0 || victims != nil {
		t.Errorf("priorBootOOM = (%d,%v), want (0,nil) on zero matches", kills, victims)
	}
	if !checked {
		t.Error("checked = false, want true — exit 1 with no output is journalctl's zero-matches convention, not a failure")
	}
}

// TestPriorBootOOM_CommandFails covers a GENUINE sub-call failure (the binary
// itself can't run), distinct from the grep-no-match convention above —
// checked must be false so the caller doesn't read this as a clean prior boot.
func TestPriorBootOOM_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"})
	})
	kills, victims, checked := priorBootOOM(context.Background())
	if kills != 0 || victims != nil {
		t.Errorf("priorBootOOM = (%d,%v), want (0,nil) on command failure", kills, victims)
	}
	if checked {
		t.Error("checked = true, want false — the sub-call itself failed, not a zero-match result")
	}
}

func TestPriorBootOOM_CapsVictimsAtFive(t *testing.T) {
	var sb strings.Builder
	for i := range 8 {
		sb.WriteString("2026-05-17T09:12:34+0000 kernel: Killed process ")
		sb.WriteString(string(rune('1' + i)))
		sb.WriteString("00 (proc")
		sb.WriteString(string(rune('a' + i)))
		sb.WriteString(") total-vm:1kB\n")
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			sb.String(), 0)
	})
	_, victims, _ := priorBootOOM(context.Background())
	if len(victims) != 5 {
		t.Errorf("len(victims) = %d, want 5 (capped)", len(victims))
	}
}

func TestPriorBootPanic_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"},
			"Kernel panic - not syncing: VFS: Unable to mount root fs\n", 0)
	})
	panicked, hint, checked := priorBootPanic(context.Background())
	if !panicked {
		t.Error("panicked = false, want true")
	}
	if !strings.Contains(hint, "Kernel panic") {
		t.Errorf("hint = %q, want it to contain the panic line", hint)
	}
	if !checked {
		t.Error("checked = false, want true")
	}
}

func TestPriorBootPanic_NoMatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"},
			"", 0)
	})
	panicked, hint, checked := priorBootPanic(context.Background())
	if panicked || hint != "" {
		t.Errorf("priorBootPanic = (%v,%q), want (false,\"\")", panicked, hint)
	}
	if !checked {
		t.Error("checked = false, want true — an empty, error-free read was still a valid check")
	}
}

// TestPriorBootPanic_GrepNoMatchIsChecked mirrors
// TestPriorBootOOM_GrepNoMatchIsChecked for the panic sub-call.
func TestPriorBootPanic_GrepNoMatchIsChecked(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"},
			"", 1)
	})
	panicked, hint, checked := priorBootPanic(context.Background())
	if panicked || hint != "" {
		t.Errorf("priorBootPanic = (%v,%q), want (false,\"\") on zero matches", panicked, hint)
	}
	if !checked {
		t.Error("checked = false, want true — exit 1 with no output is journalctl's zero-matches convention, not a failure")
	}
}

func TestPriorBootPanic_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"})
	})
	panicked, hint, checked := priorBootPanic(context.Background())
	if panicked || hint != "" {
		t.Errorf("priorBootPanic = (%v,%q), want (false,\"\") on command failure", panicked, hint)
	}
	if checked {
		t.Error("checked = true, want false — the sub-call itself failed, not a zero-match result")
	}
}

func TestTruncatePanic(t *testing.T) {
	short := "Kernel panic - not syncing"
	if got := truncatePanic(short); got != short {
		t.Errorf("truncatePanic(short) = %q, want unchanged %q", got, short)
	}
	long := strings.Repeat("x", 200)
	got := truncatePanic(long)
	const wantLen = 160 + len("…") // "…" is a 3-byte UTF-8 rune, len() counts bytes
	if len(got) != wantLen || !strings.HasSuffix(got, "…") {
		t.Errorf("truncatePanic(long) len = %d, want %d (160 bytes + ellipsis), got %q", len(got), wantLen, got)
	}
}

func TestPriorBootUncleanJournal_CleanShutdown(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"},
			"some line\nReached target Shutdown\nsystemd-shutdown[1]: Powering off.\n", 0)
	})
	unclean, checked := priorBootUncleanJournal(context.Background())
	if unclean || !checked {
		t.Errorf("priorBootUncleanJournal = (%v,%v), want (false,true) — shutdown marker present", unclean, checked)
	}
}

func TestPriorBootUncleanJournal_UncleanStop(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"},
			"some ordinary line\nanother line, no shutdown marker\n", 0)
	})
	unclean, checked := priorBootUncleanJournal(context.Background())
	if !unclean || !checked {
		t.Errorf("priorBootUncleanJournal = (%v,%v), want (true,true) — no shutdown marker", unclean, checked)
	}
}

func TestPriorBootUncleanJournal_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"}, "", 1)
	})
	unclean, checked := priorBootUncleanJournal(context.Background())
	if unclean || checked {
		t.Errorf("priorBootUncleanJournal = (%v,%v), want (false,false) on command failure", unclean, checked)
	}
}

func TestPriorBootUncleanJournal_EmptyTail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"}, "   \n", 0)
	})
	unclean, checked := priorBootUncleanJournal(context.Background())
	if unclean || checked {
		t.Errorf("priorBootUncleanJournal = (%v,%v), want (false,false) on empty tail", unclean, checked)
	}
}

func TestPriorBootUncleanWtmp_Crash(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("last", []string{"-x", "-n", "20"}, "reboot   system boot  crash  Sat May 17 09:00\n", 0)
	})
	unclean, checked := priorBootUncleanWtmp(context.Background())
	if !unclean || !checked {
		t.Errorf("priorBootUncleanWtmp = (%v,%v), want (true,true)", unclean, checked)
	}
}

func TestPriorBootUncleanWtmp_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("last", []string{"-x", "-n", "20"}, "reboot   system boot  Sat May 17 09:00\n", 0)
	})
	unclean, checked := priorBootUncleanWtmp(context.Background())
	if unclean || !checked {
		t.Errorf("priorBootUncleanWtmp = (%v,%v), want (false,true)", unclean, checked)
	}
}

func TestPriorBootUncleanWtmp_LastUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("last", []string{"-x", "-n", "20"})
	})
	unclean, checked := priorBootUncleanWtmp(context.Background())
	if unclean || checked {
		t.Errorf("priorBootUncleanWtmp = (%v,%v), want (false,false) when `last` is absent", unclean, checked)
	}
}

func TestReadPriorBootJournal(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			postBootOOMJournal, 0)
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"},
			"", 0)
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"},
			"Reached target Shutdown\n", 0)
	})
	info := &models.PostBootInfo{}
	readPriorBootJournal(context.Background(), info)
	if info.OOMKills != 2 || len(info.OOMVictims) != 2 {
		t.Errorf("OOMKills=%d OOMVictims=%v, want 2/[nginx php-fpm]", info.OOMKills, info.OOMVictims)
	}
	if info.KernelPanic {
		t.Error("KernelPanic = true, want false")
	}
	if info.UncleanShutdown || !info.ShutdownChecked {
		t.Errorf("UncleanShutdown=%v ShutdownChecked=%v, want false/true (clean shutdown marker present)", info.UncleanShutdown, info.ShutdownChecked)
	}
}

// TestPostBootCollector_Collect_FoundJournal drives the full Collect() path
// through the persistent-journal branch end to end.
func TestPostBootCollector_Collect_FoundJournal(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
		"lookpath/journalctl":        []byte("/usr/bin/journalctl"),
	}, func(b *source.Bundle) {
		b.PutDir("/var/log/journal", []string{"machine-abc"})
		b.PutDir("/var/log/journal/machine-abc", []string{"system.journal"})
		b.PutCmd("journalctl", []string{"--list-boots", "--no-pager", "-q"},
			"-1 def 2026-05-15\n 0 ghi 2026-06-01\n", 0)
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-o", "short-iso", "--grep", "Out of memory|Killed process"},
			"", 0)
		b.PutCmd("journalctl", []string{"-k", "--boot=-1", "--no-pager", "-q", "-o", "cat",
			"--grep", "Kernel panic|Oops:|general protection fault|BUG: unable to handle|kernel BUG at"},
			"", 0)
		b.PutCmd("journalctl", []string{"--boot=-1", "--no-pager", "-q", "-o", "cat", "-n", "200"},
			"Reached target Shutdown\n", 0)
	})

	c := NewPostBootCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostBootInfo)
	if !info.Available || info.State != "found" || info.Source != string(PBSourcePersistentJournal) {
		t.Errorf("Available=%v State=%q Source=%q, want true/found/persistent_journal", info.Available, info.State, info.Source)
	}
	if info.PriorBoots != 1 {
		t.Errorf("PriorBoots = %d, want 1", info.PriorBoots)
	}
}

// TestPostBootCollector_Collect_FoundWtmp drives Collect() through the coarse
// wtmp branch (non-systemd host).
func TestPostBootCollector_Collect_FoundWtmp(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
	}, func(b *source.Bundle) {
		b.PutStat("/var/log/wtmp", source.FileMeta{})
		b.PutCmd("last", []string{"-x", "-n", "20"}, "reboot   system boot  Sat May 17 09:00\n", 0)
	})

	c := NewPostBootCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostBootInfo)
	if info.State != "found" || info.Source != string(PBSourceWtmp) {
		t.Errorf("State=%q Source=%q, want found/wtmp", info.State, info.Source)
	}
	if info.UncleanShutdown || !info.ShutdownChecked {
		t.Errorf("UncleanShutdown=%v ShutdownChecked=%v, want false/true", info.UncleanShutdown, info.ShutdownChecked)
	}
}

// TestPostBootCollector_Collect_Unmeasurable covers the non-systemd/no-wtmp gap.
func TestPostBootCollector_Collect_Unmeasurable(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
	}, nil)

	c := NewPostBootCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostBootInfo)
	if info.State != "unmeasurable" || info.Reason != string(PBReasonNonSystemdNoWtmp) {
		t.Errorf("State=%q Reason=%q, want unmeasurable/non_systemd_no_wtmp", info.State, info.Reason)
	}
}

// TestPostBootCollector_Collect_AbsentFirstBoot covers postboot_linux.go:54.21,55.24 —
// the PBStateAbsent case in Collect's switch: journald is persistent and readable, but
// --list-boots shows only the current boot (priorBoots=0), meaning this is genuinely
// the first recorded boot. info.State must be "absent", not "found" or "unmeasurable".
func TestPostBootCollector_Collect_AbsentFirstBoot(t *testing.T) {
	withPostBootFixture(t, map[string][]byte{
		"platform/container-context": containerContextJSON(t, platform.ContainerContext{}),
		"lookpath/journalctl":        []byte("/usr/bin/journalctl"),
	}, func(b *source.Bundle) {
		b.PutDir("/var/log/journal", []string{"machine-abc"})
		b.PutDir("/var/log/journal/machine-abc", []string{"system.journal"})
		// Only the current boot on record — no prior boot exists.
		b.PutCmd("journalctl", []string{"--list-boots", "--no-pager", "-q"},
			" 0 ghi 2026-06-01\n", 0)
	})

	c := NewPostBootCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.PostBootInfo)
	if info.State != "absent" {
		t.Errorf("State = %q, want absent (first boot on record)", info.State)
	}
	if info.Reason != string(PBReasonFirstBoot) {
		t.Errorf("Reason = %q, want %q", info.Reason, PBReasonFirstBoot)
	}
}
