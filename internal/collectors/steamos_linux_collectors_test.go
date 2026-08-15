//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestSteamOSCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewSteamOSCollector()
	if c.Name() != "SteamOS" {
		t.Errorf("Name() = %q, want SteamOS", c.Name())
	}
	if c.Deep {
		t.Error("NewSteamOSCollector must not be Deep")
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("non-deep Timeout() = %v, want 6s", c.Timeout())
	}
	deep := NewSteamOSDeepCollector()
	if !deep.Deep {
		t.Error("NewSteamOSDeepCollector must set Deep=true")
	}
	if deep.Timeout() <= c.Timeout() {
		t.Error("deep Timeout() must exceed the non-deep timeout")
	}
}

// TestSteamOSCollector_Collect_NotSteamOS exercises Collect()'s early-return
// gate. platform.Detect() reads the real host's /etc/os-release directly (the
// platform package can't import internal/source per the layer contract), so
// under the golang:1.26 test container this is always the not-SteamOS branch —
// the only branch of Collect() itself reachable without a real SteamOS host.
func TestSteamOSCollector_Collect_NotSteamOS(t *testing.T) {
	t.Parallel()
	got, err := NewSteamOSCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.SteamOSInfo)
	if info.Detected {
		t.Error("expected Detected=false on a non-SteamOS test host")
	}
}

func TestDirExists(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/home/deck/.steam", source.FileMeta{IsDir: true})
	})
	if !dirExists("/home/deck/.steam") {
		t.Error("expected dirExists=true")
	}
	if dirExists("/nonexistent") {
		t.Error("expected dirExists=false for unseeded path")
	}
}

func TestCollectDevice_SteamDeck(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/product_name", []byte("Jupiter\n"))
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectDevice(info)
	if !info.DeviceRecognised {
		t.Error("expected Jupiter to be recognised as a Steam Deck")
	}
	if info.SecureBootApplicable {
		t.Error("Steam Deck firmware does not enforce Secure Boot — SecureBootApplicable must be false")
	}
}

func TestCollectDevice_NonDeckWithSecureBoot(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/product_name", []byte("ROG Ally RC71L\n"))
		b.PutFile(secureBootEfivar, []byte{6, 0, 0, 0, 1})
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectDevice(info)
	if !info.SecureBootApplicable {
		t.Error("expected SecureBootApplicable=true for a non-Deck device")
	}
	if info.SecureBootEnabled == nil || !*info.SecureBootEnabled {
		t.Errorf("expected SecureBootEnabled=true, got %v", info.SecureBootEnabled)
	}
}

func TestCollectDevice_NonDeckEfivarsAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/dmi/id/product_name", []byte("Some Other Handheld\n"))
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectDevice(info)
	if info.SecureBootEnabled != nil {
		t.Errorf("expected nil (unknown) when efivars absent, got %v", *info.SecureBootEnabled)
	}
}

func TestCollectSystem_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("BUILD_ID=20240610.100\n"))
		b.PutFile("/etc/steamos-atomupd/client.conf", []byte("[Choices]\nRelease=stable\n"))
		b.PutCmd("steamos-readonly", []string{"status"}, "enabled\n", 0)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectSystem(context.Background(), info)
	if info.BuildID != "20240610.100" {
		t.Errorf("BuildID = %q, want 20240610.100", info.BuildID)
	}
	if !info.ReadonlyKnown || !info.ReadonlyEnabled {
		t.Errorf("expected readonly known+enabled, got known=%v enabled=%v", info.ReadonlyKnown, info.ReadonlyEnabled)
	}
	if info.ChannelConfigMissing {
		t.Error("expected ChannelConfigMissing=false when the config file is present")
	}
}

func TestCollectSystem_ChannelConfigMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("steamos-readonly", []string{"status"})
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectSystem(context.Background(), info)
	// The Bundle fixture API has no way to seed a genuine fs.ErrNotExist for
	// ReadFile — an unseeded path replays as ErrNotRecorded, which does not
	// satisfy os.IsNotExist, so the ChannelConfigMissing branch can't fire here.
	// Same accepted gap as parsePasswordAging's absent-vs-unreadable shadow-file
	// handling (security_linux_source_test.go).
	if info.ChannelConfigMissing {
		t.Error("expected ChannelConfigMissing=false — ErrNotRecorded isn't os.IsNotExist")
	}
	if info.ReadonlyKnown {
		t.Error("expected ReadonlyKnown=false when steamos-readonly is unavailable")
	}
}

func TestCollectRAUC_JSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("rauc", []string{"status", "--output-format=json"},
			`{"compatible":"steamos-amd64","booted":"rootfs.0","slots":[`+
				`{"rootfs.0":{"class":"rootfs","state":"booted","boot_status":"good","bootname":"A"}},`+
				`{"rootfs.1":{"class":"rootfs","state":"inactive","boot_status":"good","bootname":"B"}}]}`, 0)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRAUC(context.Background(), info)
	if !info.RAUCAvailable {
		t.Fatal("expected RAUCAvailable=true")
	}
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted = %q/%q, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
}

func TestCollectRAUC_TextFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rauc", []string{"status", "--output-format=json"})
		b.PutCmd("rauc", []string{"status"},
			"=== System Info ===\ncompatible     = steamos-amd64\nbooted         = A\n\n"+
				"=== Slot States ===\n"+
				"o [rootfs.A] (/dev/dummy1, ext4, booted)\n        state: booted\n        boot status: good\n\n"+
				"  [rootfs.B] (/dev/dummy2, ext4, inactive)\n        state: inactive\n        boot status: good\n\n", 0)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRAUC(context.Background(), info)
	if !info.RAUCAvailable {
		t.Error("expected RAUCAvailable=true via text fallback")
	}
}

func TestCollectRAUC_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rauc", []string{"status", "--output-format=json"})
		b.PutCmdNotFound("rauc", []string{"status"})
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRAUC(context.Background(), info)
	if info.RAUCAvailable {
		t.Error("expected RAUCAvailable=false when rauc binary is absent")
	}
}

func TestCollectSession(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "gamescope-session.service"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "steam-launcher.service"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "sddm.service"}, "inactive\n", 3)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectSession(context.Background(), info)
	if !info.GamescopeActive || !info.SteamLauncherActive || info.SDDMActive {
		t.Errorf("session = %+v", info)
	}
	if info.SessionMode != "gamemode" {
		t.Errorf("SessionMode = %q, want gamemode", info.SessionMode)
	}
}

// TestDetectSessionMode covers every branch: the XDG_SESSION_DESKTOP
// fast-path signals (gamescope and plasma/KDE), and the fallback switch on
// GamescopeActive/SDDMActive/neither once XDG_SESSION_DESKTOP is unset.
func TestDetectSessionMode(t *testing.T) {
	tests := []struct {
		name   string
		xdg    string
		info   models.SteamOSInfo
		want   string
		seeded bool // whether env/XDG_SESSION_DESKTOP is seeded at all
	}{
		{name: "xdg gamescope-wayland", xdg: "gamescope-wayland", want: "gamemode", seeded: true},
		{name: "xdg plasma", xdg: "plasma", want: "desktop", seeded: true},
		{name: "xdg kde", xdg: "kde", want: "desktop", seeded: true},
		{name: "fallback gamescope active", info: models.SteamOSInfo{GamescopeActive: true}, want: "gamemode"},
		{name: "fallback sddm active", info: models.SteamOSInfo{SDDMActive: true}, want: "desktop"},
		{name: "fallback neither", want: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cached := map[string][]byte{}
			if tc.seeded {
				cached["env/XDG_SESSION_DESKTOP"] = []byte(tc.xdg)
			}
			withCombinedFixture(t, cached, nil, nil)
			info := tc.info
			if got := detectSessionMode(&info); got != tc.want {
				t.Errorf("detectSessionMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStatfsUsage_ErrorOrZeroBlocks guards the early-return branch: a statfs
// error or a Blocks==0 (some pseudo-filesystems, or a query failure) result
// must report ok=false, not a divide-by-zero or bogus percentage.
func TestStatfsUsage_ErrorOrZeroBlocks(t *testing.T) {
	prev := SetSource(&fakeStatfsMultiSource{
		Replay: source.NewReplay(source.NewBundle()),
		info: map[string]source.StatfsInfo{
			"/zeroblocks": {Blocks: 0, Bfree: 0, Bavail: 0, Bsize: 4096},
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	if _, _, _, ok := statfsUsage("/zeroblocks"); ok {
		t.Error("expected ok=false when Blocks==0")
	}
	if _, _, _, ok := statfsUsage("/never-seeded"); ok {
		t.Error("expected ok=false when statFs errors (path never seeded)")
	}
}

func TestCollectStorage(t *testing.T) {
	prev := SetSource(&fakeStatfsMultiSource{
		Replay: source.NewReplay(source.NewBundle()),
		info: map[string]source.StatfsInfo{
			"/var":  {Blocks: 1000, Bfree: 400, Bavail: 400, Bsize: 1000},
			"/home": {Blocks: 2000, Bfree: 1000, Bavail: 1000, Bsize: 1000},
		},
	})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectStorage(info)
	if info.VarTotalMB != 1.0 {
		t.Errorf("VarTotalMB = %v, want 1.0", info.VarTotalMB)
	}
	if info.VarUsedPct != 60 {
		t.Errorf("VarUsedPct = %v, want 60", info.VarUsedPct)
	}
	if info.HomeUsedPct != 50 {
		t.Errorf("HomeUsedPct = %v, want 50", info.HomeUsedPct)
	}
}

// fakeStatfsMultiSource overrides Statfs for several exact paths — the Bundle
// API has no public statfs-seeding method (see fakeStatfsOverrideSource in
// logs_linux_collectors_test.go, which handles the single-path case).
type fakeStatfsMultiSource struct {
	*source.Replay
	info map[string]source.StatfsInfo
}

func (f *fakeStatfsMultiSource) Statfs(path string) (source.StatfsInfo, error) {
	if v, ok := f.info[path]; ok {
		return v, nil
	}
	return f.Replay.Statfs(path)
}

func TestCollectNetwork(t *testing.T) {
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"steamos/update-server": []byte(`{"ok":true,"ms":42}`)},
	})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectNetwork(context.Background(), info)
	if !info.UpdateServerKnown || !info.UpdateServerReachable || info.UpdateServerLatencyMs != 42 {
		t.Errorf("network = %+v", info)
	}
}

// TestCollectNetwork_DSD_OFFLINE_SkipsDial is a regression guard for
// egress-gate-04: collectNetwork used to unconditionally dial
// steamdeck-atomupd.steamos.cloud:443 (an external internet host) on every
// default `dsd health` run on a Steam Deck, with no opt-out. Under
// DSD_OFFLINE, UpdateServerKnown must stay false rather than true+false — the
// existing "reachability test never ran" sentinel checkSteamOSNetwork
// already treats as silent (never a false WARN). The source here is fully
// mocked either way, so this test cannot itself perform a live dial; it
// verifies the collector never even reaches for the cached/live probe.
func TestCollectNetwork_DSD_OFFLINE_SkipsDial(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")
	prev := SetSource(&fakeCombinedSource{
		Replay: source.NewReplay(source.NewBundle()),
		cached: map[string][]byte{"steamos/update-server": []byte(`{"ok":true,"ms":42}`)},
	})
	t.Cleanup(func() { SetSource(prev) })

	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectNetwork(context.Background(), info)
	if info.UpdateServerKnown {
		t.Error("expected UpdateServerKnown=false under DSD_OFFLINE (the dial must be skipped, not attempted)")
	}
	if info.UpdateServerReachable || info.UpdateServerLatencyMs != 0 {
		t.Errorf("expected zero-value reachability fields under DSD_OFFLINE, got %+v", info)
	}
}

func TestCollectRemotePlay_Bound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ss", []string{"-tulpn"},
			"Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"+
				`udp   UNCONN 0      0            0.0.0.0:27031      0.0.0.0:*    users:(("steam",pid=1842,fd=50))`+"\n", 0)
		b.PutCmd("nft", []string{"list", "ruleset"}, "table inet filter { chain input { } }", 0)
		b.PutFile("/proc/uptime", []byte("10.0 5.0\n")) // < 120s — ARP check skipped
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRemotePlay(context.Background(), info)
	if info.RemotePlay == nil {
		t.Fatal("expected non-nil RemotePlay")
	}
	if !info.RemotePlay.FirewallKnown || info.RemotePlay.FirewallBlocking {
		t.Errorf("firewall = known=%v blocking=%v, want true/false", info.RemotePlay.FirewallKnown, info.RemotePlay.FirewallBlocking)
	}
	if info.RemotePlay.ARPChecked {
		t.Error("expected ARPChecked=false — uptime below the 120s gate")
	}
	var found bool
	for _, p := range info.RemotePlay.Ports {
		if p.Protocol == "udp" && p.Port == 27031 {
			found = true
			if !p.Bound || p.Process != "steam" {
				t.Errorf("port 27031 = %+v, want bound/steam", p)
			}
		}
	}
	if !found {
		t.Error("expected port 27031 present in Ports")
	}
}

func TestCollectRemotePlay_APIsolationSuspected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ss", []string{"-tulpn"})
		b.PutCmdNotFound("nft", []string{"list", "ruleset"})
		b.PutCmdNotFound("iptables", []string{"-L", "INPUT", "-n"})
		b.PutFile("/proc/uptime", []byte("500.0 200.0\n")) // >= 120s — ARP check runs
		b.PutCmd("ip", []string{"route", "show", "default"}, "default via 192.168.10.1 dev wlan0 proto dhcp metric 600\n", 0)
		b.PutCmd("ip", []string{"neigh", "show"}, "192.168.10.1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n", 0)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRemotePlay(context.Background(), info)
	if info.RemotePlay.FirewallKnown {
		t.Error("expected FirewallKnown=false when neither nft nor iptables is available")
	}
	if !info.RemotePlay.ARPChecked {
		t.Fatal("expected ARPChecked=true — uptime above the 120s gate and a gateway was found")
	}
	if info.RemotePlay.LANPeersVisible != 0 || !info.RemotePlay.APIsolationSuspected {
		t.Errorf("expected 0 peers / isolation suspected, got %+v", info.RemotePlay)
	}
}

// TestCollectRemotePlay_IptablesFallback guards the nft-unavailable/iptables-
// succeeds firewall branch — distinct from both TestCollectRemotePlay_Bound
// (nft succeeds) and _APIsolationSuspected (neither tool available).
func TestCollectRemotePlay_IptablesFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ss", []string{"-tulpn"})
		b.PutCmdNotFound("nft", []string{"list", "ruleset"})
		b.PutCmd("iptables", []string{"-L", "INPUT", "-n"},
			"Chain INPUT (policy DROP)\nnum  target  prot opt source  destination\n"+
				"1    DROP    tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:27036\n", 0)
		b.PutFile("/proc/uptime", []byte("10.0 5.0\n")) // < 120s — ARP check skipped
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{}).collectRemotePlay(context.Background(), info)
	if !info.RemotePlay.FirewallKnown {
		t.Error("expected FirewallKnown=true via the iptables fallback")
	}
}

func TestCollectSteamOSDisk(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/home/deck", source.FileMeta{IsDir: true})
		b.PutStat("/home/deck/.steam/steam/shadercache", source.FileMeta{IsDir: true})
		b.PutCmd("du", []string{"-sb", "/home/deck/.steam/steam/shadercache"}, "5000000000\t/home/deck/.steam/steam/shadercache\n", 0)
		// A bind mount's /proc/mounts entry shows the ORIGINAL path (/opt, /root)
		// as the mount point — that's what dirExists(bm.Target) && mounts[bm.Path]
		// checks: the offload target exists AND something is bind-mounted onto
		// the original in-rootfs path.
		b.PutFile("/proc/mounts",
			[]byte("/home/.steamos/offload/opt /opt ext4 rw,bind 0 0\n"+
				"/home/.steamos/offload/root /root ext4 rw,bind 0 0\n"))
		b.PutStat("/home/.steamos/offload/opt", source.FileMeta{IsDir: true})
		b.PutStat("/home/.steamos/offload/root", source.FileMeta{IsDir: true})
	})
	d := collectSteamOSDisk()
	if d.ShaderCacheGB != 5.0 {
		t.Errorf("ShaderCacheGB = %v, want 5.0", d.ShaderCacheGB)
	}
	if len(d.BindMounts) != 2 {
		t.Fatalf("expected 2 bind mounts, got %d", len(d.BindMounts))
	}
	for _, bm := range d.BindMounts {
		if !bm.OK {
			t.Errorf("bind mount %+v should be OK", bm)
		}
	}
}

func TestCollectSteamOSDisk_NoHomeDeck(t *testing.T) {
	t.Setenv("HOME", "/home/other")
	withFixtureSource(t, func(b *source.Bundle) {})
	d := collectSteamOSDisk()
	if d.ShaderCacheGB != 0 {
		t.Errorf("ShaderCacheGB = %v, want 0", d.ShaderCacheGB)
	}
	for _, bm := range d.BindMounts {
		if bm.OK {
			t.Errorf("bind mount %+v should not be OK with nothing seeded", bm)
		}
	}
}

func TestCollectSteamOSWifi_ConnectedIWD(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "iwd.service"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "wpa_supplicant.service"}, "inactive\n", 3)
		b.PutCmd("iw", []string{"dev"},
			"phy#0\n\tInterface wlan0\n\t\tssid HomeNet\n\t\tchannel 36 (5180 MHz), width: 80 MHz\n", 0)
		b.PutCmd("iw", []string{"dev", "wlan0", "link"},
			"Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tsignal: -45 dBm\n", 0)
	})
	w := collectSteamOSWifi(context.Background())
	if w.Backend != "iwd" || w.BothBackends {
		t.Errorf("backend = %q bothBackends=%v, want iwd/false", w.Backend, w.BothBackends)
	}
	if !w.Connected || w.Interface != "wlan0" {
		t.Errorf("connected=%v iface=%q, want true/wlan0", w.Connected, w.Interface)
	}
	if w.SignalDBm != -45 {
		t.Errorf("SignalDBm = %d, want -45", w.SignalDBm)
	}
	if w.CDNDNSKnown {
		t.Error("expected CDNDNSKnown=false — steamos/cdn-dns cache key not seeded")
	}
}

// TestCollectSteamOSWifi_DSD_OFFLINE_SkipsCDNLookup is the regression test
// for the missing DSD_OFFLINE gate on collectSteamOSWifi's Steam CDN DNS
// probe (steamdeck-images.steamos.cloud) — every other live network probe in
// this file honors DSD_OFFLINE, this one didn't. Proven by recording every
// Cached() key requested, same technique as network_quick_test.go's
// TestProbeConnectivity_DSD_OFFLINE_SkipsPingAndDNS.
func TestCollectSteamOSWifi_DSD_OFFLINE_SkipsCDNLookup(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")
	var calls []string
	prev := SetSource(recordingCacheSource{Replay: source.NewReplay(source.NewBundle()), calls: &calls})
	defer SetSource(prev)

	w := collectSteamOSWifi(context.Background())
	if w.CDNDNSKnown {
		t.Error("expected CDNDNSKnown=false when DSD_OFFLINE is set")
	}
	for _, k := range calls {
		if k == "steamos/cdn-dns" {
			t.Fatal(`cachedJSON("steamos/cdn-dns", ...) was called despite DSD_OFFLINE — the live DNS lookup path was reached`)
		}
	}
}

// TestCollectSteamOSWifi_BothBackendsActive guards the iwd&&wpa branch — a
// misconfigured device with both network daemons running, which BothBackends
// exists to surface (neither of the single-backend cases exercise it).
func TestCollectSteamOSWifi_BothBackendsActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "iwd.service"}, "active\n", 0)
		b.PutCmd("systemctl", []string{"is-active", "wpa_supplicant.service"}, "active\n", 0)
		b.PutCmdNotFound("iw", []string{"dev"})
	})
	w := collectSteamOSWifi(context.Background())
	if w.Backend != "iwd" || !w.BothBackends {
		t.Errorf("backend = %q bothBackends=%v, want iwd/true", w.Backend, w.BothBackends)
	}
}

// TestCollectSteamOSWifi_WpaSupplicantOnly guards the wpa-only branch
// (DevMode=true), and the SSID-conflict detection across two interfaces
// sharing the same SSID (the dual-band Steam Deck OLED reliability issue).
func TestCollectSteamOSWifi_WpaSupplicantOnly(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "iwd.service"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "wpa_supplicant.service"}, "active\n", 0)
		b.PutCmd("iw", []string{"dev"},
			"phy#0\n\tInterface wlan0\n\t\tssid HomeNet\n\t\tchannel 36 (5180 MHz), width: 80 MHz\n"+
				"phy#1\n\tInterface wlan1\n\t\tssid HomeNet\n\t\tchannel 1 (2412 MHz), width: 20 MHz\n", 0)
		b.PutCmd("iw", []string{"dev", "wlan0", "link"}, "Connected to aa:bb:cc:dd:ee:ff\n\tsignal: -50 dBm\n", 0)
	})
	w := collectSteamOSWifi(context.Background())
	if w.Backend != "wpa_supplicant" || !w.DevMode {
		t.Errorf("backend = %q devMode=%v, want wpa_supplicant/true", w.Backend, w.DevMode)
	}
	if !w.SSIDConflict || w.ConflictSSID != "HomeNet" {
		t.Errorf("SSIDConflict = %v ConflictSSID = %q, want true/HomeNet", w.SSIDConflict, w.ConflictSSID)
	}
}

func TestCollectSteamOSWifi_UnknownBackend(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "iwd.service"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "wpa_supplicant.service"})
		b.PutCmdNotFound("iw", []string{"dev"})
	})
	w := collectSteamOSWifi(context.Background())
	if w.Backend != "unknown" {
		t.Errorf("Backend = %q, want unknown", w.Backend)
	}
	if w.Connected {
		t.Error("expected Connected=false with no interfaces")
	}
}

func TestSteamHostUptimeSeconds(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/uptime", []byte("12345.67 54321.00\n"))
	})
	if got := steamHostUptimeSeconds(); got != 12345.67 {
		t.Errorf("steamHostUptimeSeconds() = %v, want 12345.67", got)
	}
}

func TestSteamHostUptimeSeconds_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := steamHostUptimeSeconds(); got != 0 {
		t.Errorf("steamHostUptimeSeconds() = %v, want 0", got)
	}
}

// TestSteamHostUptimeSeconds_EmptyFile guards the "readable but has no
// whitespace-separated fields" branch — distinct from Unreadable (a read
// error): the file exists and reads successfully, but its content is blank.
func TestSteamHostUptimeSeconds_EmptyFile(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/uptime", []byte(""))
	})
	if got := steamHostUptimeSeconds(); got != 0 {
		t.Errorf("steamHostUptimeSeconds() = %v, want 0 for an empty file", got)
	}
}

func TestSteamUserHome_DeckPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/home/deck", source.FileMeta{IsDir: true})
	})
	if got := steamUserHome(); got != "/home/deck" {
		t.Errorf("steamUserHome() = %q, want /home/deck", got)
	}
}

func TestSteamUserHome_FallsBackToHomeEnv(t *testing.T) {
	t.Setenv("HOME", "/home/bazzite-user")
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := steamUserHome(); got != "/home/bazzite-user" {
		t.Errorf("steamUserHome() = %q, want /home/bazzite-user", got)
	}
}

// TestSteamUserHome_NeitherDeckNorHomeEnv guards the final "/home/deck"
// fallback: neither /home/deck exists nor is HOME set.
func TestSteamUserHome_NeitherDeckNorHomeEnv(t *testing.T) {
	t.Setenv("HOME", "")
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := steamUserHome(); got != "/home/deck" {
		t.Errorf("steamUserHome() = %q, want /home/deck (final fallback)", got)
	}
}

func TestDuGB(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("du", []string{"-sb", "/some/dir"}, "2500000000\t/some/dir\n", 0)
	})
	if got := duGB(context.Background(), "/some/dir"); got != 2.5 {
		t.Errorf("duGB() = %v, want 2.5", got)
	}
}

func TestDuGB_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("du", []string{"-sb", "/some/dir"})
	})
	if got := duGB(context.Background(), "/some/dir"); got != 0 {
		t.Errorf("duGB() = %v, want 0", got)
	}
}

// TestDuGB_EmptyOutput guards the len(fields)==0 branch: `du` succeeding with
// blank stdout must not panic on fields[0] and must return 0.
func TestDuGB_EmptyOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("du", []string{"-sb", "/some/dir"}, "", 0)
	})
	if got := duGB(context.Background(), "/some/dir"); got != 0 {
		t.Errorf("duGB() = %v, want 0 for empty output", got)
	}
}

// TestDuGB_UnparseableSize guards the parseFiniteFloat failure branch: a
// non-numeric first field must return 0, not a garbage value.
func TestDuGB_UnparseableSize(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("du", []string{"-sb", "/some/dir"}, "notanumber\t/some/dir\n", 0)
	})
	if got := duGB(context.Background(), "/some/dir"); got != 0 {
		t.Errorf("duGB() = %v, want 0 for an unparseable size field", got)
	}
}

func TestUnitActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "gamescope-session.service"}, "active\n", 0)
	})
	if !unitActive(context.Background(), "gamescope-session.service") {
		t.Error("expected true")
	}
}

func TestUnitActive_Inactive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "sddm.service"}, "inactive\n", 3)
	})
	if unitActive(context.Background(), "sddm.service") {
		t.Error("expected false")
	}
}

func TestLastNonEmptyLine(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"a\nb\n\n", "b"},
		{"", ""},
		{"\n\n\n", ""},
		{"only", "only"},
	}
	for _, c := range cases {
		if got := lastNonEmptyLine(c.in); got != c.want {
			t.Errorf("lastNonEmptyLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	t.Parallel()
	if got := countNonEmptyLines("a\n\nb\nc\n"); got != 3 {
		t.Errorf("countNonEmptyLines() = %d, want 3", got)
	}
	if got := countNonEmptyLines(""); got != 0 {
		t.Errorf("countNonEmptyLines(empty) = %d, want 0", got)
	}
}

func TestCollectDeep(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"-u", "gamescope-session", "-n", "50", "--no-pager"},
			"Jun 10 12:00:00 deck gamescope[100]: error: something broke\n", 0)
		b.PutCmd("journalctl", []string{"-u", "rauc", "-n", "30", "--no-pager"},
			"Jun 10 12:00:00 deck rauc[1]: installing bundle succeeded\n", 0)
		b.PutStat("/home/deck", source.FileMeta{IsDir: true})
		b.PutStat("/home/deck/.steam/steam/steamapps/compatdata", source.FileMeta{IsDir: true})
		b.PutDir("/home/deck/.steam/steam/steamapps/compatdata", []string{"1091500", "570"})
		b.PutCmd("du", []string{"-sb", "/home/deck/.steam/steam/steamapps/compatdata"}, "8000000000\t\n", 0)
		b.PutCmd("flatpak", []string{"list", "--app"}, "org.mozilla.firefox\ncom.valvesoftware.Steam\n", 0)
		b.PutStat("/home/deck/.local/share/flatpak", source.FileMeta{IsDir: true})
		b.PutCmd("du", []string{"-sb", "/home/deck/.local/share/flatpak"}, "1000000000\t\n", 0)
		b.PutCmd("dmidecode", []string{"-s", "bios-version"}, "F7A0113\n", 0)
	})
	info := &models.SteamOSInfo{}
	(&SteamOSCollector{Deep: true}).collectDeep(context.Background(), info)
	if len(info.GamescopeErrors) != 1 {
		t.Errorf("GamescopeErrors = %v, want 1 entry", info.GamescopeErrors)
	}
	if info.RAUCLastLog == "" {
		t.Error("expected RAUCLastLog populated")
	}
	if info.ProtonPrefixCount != 2 {
		t.Errorf("ProtonPrefixCount = %d, want 2", info.ProtonPrefixCount)
	}
	if info.CompatDataGB != 8.0 {
		t.Errorf("CompatDataGB = %v, want 8.0", info.CompatDataGB)
	}
	if info.FlatpakAppCount != 2 {
		t.Errorf("FlatpakAppCount = %d, want 2", info.FlatpakAppCount)
	}
	if info.FlatpakDataGB != 1.0 {
		t.Errorf("FlatpakDataGB = %v, want 1.0", info.FlatpakDataGB)
	}
	if info.BIOSVersion != "F7A0113" {
		t.Errorf("BIOSVersion = %q, want F7A0113", info.BIOSVersion)
	}
}
