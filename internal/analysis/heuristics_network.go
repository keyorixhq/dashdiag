package analysis

import (
	"fmt"
	"math"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	netCatBonding        = "Bonding"
	netCatBIND           = "BIND"
	netCatNFS            = "NFS"
	netInspectIPLink     = "to inspect: ip link show"
	netInspectIPRoute    = "to inspect: ip route"
	netInspectBondingFmt = "to inspect: cat /proc/net/bonding/%s"
	netKwSynRetrans      = "syn_retrans"
	netKwRetransFail     = "retrans_fail"
	netKwListenOverflow  = "listen_overflow"
)

func checkNFS(nfs models.NFSInfo) []models.Insight {
	var out []models.Insight
	for _, m := range nfs.Mounts {
		if m.Stale {
			hints := []string{
				fmt.Sprintf("to unmount (safe): umount -l %s", m.Mount),
				fmt.Sprintf("to remount after recovery: mount -o remount %s", m.Mount),
			}
			if !m.ServerReachable {
				hints = append(hints,
					fmt.Sprintf("server %s unreachable — check network/firewall", m.Server))
			}
			out = append(out, insight("CRIT", netCatNFS,
				fmt.Sprintf("mount %s is STALE — processes accessing it will hang in D-state", m.Mount),
				hints))
		} else if !m.Healthy {
			// statfs returned promptly with a non-ESTALE/EIO error (e.g. EACCES after
			// an export-permission change). The collector marks the mount unhealthy and
			// the `dsd net` renderer shows it as "error", but checkNFS keyed only on
			// Stale — so dsd health emitted nothing and the mount read green (false-OK).
			out = append(out, insight("WARN", netCatNFS,
				fmt.Sprintf("mount %s is not responding normally (statfs error) — check exports/permissions", m.Mount),
				[]string{
					fmt.Sprintf("to inspect: stat -f %s", m.Mount),
					fmt.Sprintf("to inspect: showmount -e %s   (verify the export still grants this client)", m.Server),
				}))
		}
		for _, warn := range m.OptionsWarnings {
			out = append(out, insight("WARN", netCatNFS,
				fmt.Sprintf("%s: %s", m.Mount, warn),
				[]string{"to fix: remount with correct options in /etc/fstab"},
			))
		}
	}
	// retrans and calls are both cumulative since boot, so a raw retrans threshold
	// fires forever after a transient blip. Gate on the retrans RATE (retrans/calls)
	// instead, with a call-volume floor so a freshly-mounted share isn't flagged on a
	// handful of calls. >5% retransmitted is the conventional nfsstat concern line.
	if NFSRetransConcern(nfs) {
		out = append(out, insight("WARN", netCatNFS,
			fmt.Sprintf("NFS retransmission rate %.1f%% (%.0f/%.0f calls) — transport may be unreliable",
				nfs.RetransPerMin/nfs.RPCCalls*100, nfs.RetransPerMin, nfs.RPCCalls),
			[]string{
				"to inspect: nfsstat -rc",
				"to inspect: cat /proc/net/rpc/nfs",
			},
		))
	}
	// rpcbind only matters for NFSv3 (portmapper). NFSv4 uses the single
	// well-known port 2049 and needs no rpcbind, so a v4-only host legitimately
	// runs without it — don't warn unless at least one v3 mount is present.
	if !nfs.RpcbindActive && NFSHasV3Mount(nfs.Mounts) {
		out = append(out, insight("WARN", netCatNFS,
			"rpcbind inactive with NFSv3 mounts present — NFS client operations may fail",
			[]string{
				"to fix: systemctl enable --now rpcbind",
			},
		))
	}
	return out
}

// NFSRetransConcern reports whether the NFS retransmission RATE is high enough to
// flag. retrans and calls are both cumulative since boot, so a raw count fires
// forever after a transient blip; gate on the rate (>5%, the conventional nfsstat
// line) with a call-volume floor. Exported so the `dsd net deep` renderer uses the
// identical rule as checkNFS (dsd health) and the two cannot drift.
func NFSRetransConcern(nfs models.NFSInfo) bool {
	return nfs.StaleMounts == 0 && nfs.RPCCalls > 1000 &&
		nfs.RetransPerMin/nfs.RPCCalls > 0.05
}

// NFSHasV3Mount reports whether any mount might be NFSv3 (and thus needs
// rpcbind). It is conservative: only a mount explicitly typed "nfs4" is treated
// as definitely-not-v3, so an ambiguous "nfs" fstype (which can be v3 OR a
// vers=4 mount the kernel labelled generically) still counts — better a rare
// extra WARN than re-introducing the rpcbind false-negative for a real v3 host.
// Exported so the `dsd net deep` renderer shares it with checkNFS (no drift).
func NFSHasV3Mount(mounts []models.NFSMount) bool {
	for _, m := range mounts {
		if m.FSType != "nfs4" {
			return true
		}
	}
	return false
}

func checkBIND(b models.BINDInfo) []models.Insight {
	var out []models.Insight
	if !b.Detected {
		return out
	}
	if !b.ServiceActive {
		out = append(out, insight("CRIT", netCatBIND,
			"named service is not active — DNS server not running",
			[]string{
				"to start: systemctl start named",
				"to inspect: journalctl -u named -n 50 --no-pager",
			},
		))
		return out
	}
	if b.PortsChecked && (!b.Port53TCP || !b.Port53UDP) {
		out = append(out, insight("WARN", netCatBIND,
			"named is running but not listening on port 53 — config error or firewall",
			[]string{
				"to inspect: ss -tulpn | grep :53",
				"to inspect: journalctl -u named -n 20 --no-pager",
			},
		))
	} else if !b.PortsChecked {
		out = append(out, insight("INFO", netCatBIND,
			"could not verify named is listening on port 53 — ss (iproute2) unavailable",
			[]string{"to install: apt install iproute2  /  dnf install iproute"},
		))
	}
	if !b.ConfigOK {
		out = append(out, insight("CRIT", netCatBIND,
			fmt.Sprintf("named-checkconf error: %s", b.ConfigError),
			[]string{
				fmt.Sprintf("to fix: named-checkconf %s", b.ConfigFile),
				"to reload after fix: rndc reload",
			},
		))
	}
	if b.ZonesFailed > 0 {
		var failed []string
		for _, z := range b.Zones {
			if !z.OK {
				failed = append(failed, z.Name)
			}
		}
		out = append(out, insight("CRIT", netCatBIND,
			fmt.Sprintf("%d zone file(s) failed validation: %s",
				b.ZonesFailed, strings.Join(firstN(failed, 3), ", ")),
			[]string{
				"to inspect: named-checkzone <zone> <file>",
				"to reload after fix: rndc reload <zone>",
			},
		))
	}
	switch {
	case b.QueryTested && !b.QueryOK:
		out = append(out, insight("CRIT", netCatBIND,
			"named is running but not answering DNS queries on 127.0.0.1:53",
			[]string{
				"to test: dig @127.0.0.1 localhost A +time=2 +tries=1",
				"to inspect: journalctl -u named -n 50 --no-pager",
			},
		))
	case !b.QueryTested:
		// dig isn't installed, so we couldn't verify named is answering — say so
		// rather than falsely asserting an outage.
		out = append(out, insight("INFO", netCatBIND,
			"could not verify named is answering — dig not installed",
			[]string{"to enable the check: install bind-utils (RHEL) / dnsutils (Debian)"},
		))
	}
	return out
}

// eventsPerHour turns a since-boot cumulative counter into a per-hour rate.
// A return of -1 means uptime is unknown (couldn't be read) — callers then report
// the raw since-boot total without asserting a rate they can't compute.
func eventsPerHour(count int, uptimeSec float64) float64 {
	if uptimeSec <= 0 {
		return -1
	}
	return float64(count) / (uptimeSec / 3600.0)
}

// rateSuffix renders a "(~N/hr)" qualifier, or "" when the rate is unknown.
func rateSuffix(rate float64) string {
	if rate < 0 {
		return ""
	}
	return fmt.Sprintf(" (~%.1f/hr)", rate)
}

// Floors (minimum since-boot total worth reporting) and per-hour rate boundaries
// for the cumulative TcpExt counters. A critRate of 0 means the counter has no
// CRIT tier (its worst live state is WARN).
const (
	synRetransFloor, synRetransWarnRate                     = 100, 60.0 // ≥1/sec sustained
	listenOverflowFloor, listenOverflowWarnRate, listenCrit = 0, 1.0, 10.0
	retransFailFloor, retransFailWarnRate                   = 10, 6.0
)

// DeepTCPCounterLevel is the single source of truth for how a cumulative
// since-boot TcpExt counter maps to a health severity, shared by the health
// heuristics and the `dsd net` renderer so the two never diverge. kind is one of
// netKwSynRetrans, netKwListenOverflow, netKwRetransFail. It returns "", "INFO",
// "WARN", or "CRIT": at/below the floor is ""; above it, a sustained per-hour
// rate (relative to uptime) escalates, while a small historical total — or one
// that can't be rated because uptime is unknown — stays INFO.
func DeepTCPCounterLevel(kind string, count int, uptimeSec float64) string {
	switch kind {
	case netKwSynRetrans:
		if count <= synRetransFloor {
			return ""
		}
		return tcpCounterLevel(count, uptimeSec, synRetransWarnRate, 0)
	case netKwListenOverflow:
		if count <= listenOverflowFloor {
			return ""
		}
		return tcpCounterLevel(count, uptimeSec, listenOverflowWarnRate, listenCrit)
	case netKwRetransFail:
		if count <= retransFailFloor {
			return ""
		}
		return tcpCounterLevel(count, uptimeSec, retransFailWarnRate, 0)
	}
	return ""
}

// tcpCounterLevel classifies a counter already known to be above its floor by its
// per-hour rate. An unknown rate (uptime unreadable → eventsPerHour returns -1)
// falls through to INFO, so we never escalate on a total we can't normalize.
func tcpCounterLevel(count int, uptimeSec, warnRate, critRate float64) string {
	rate := eventsPerHour(count, uptimeSec)
	switch {
	case critRate > 0 && rate >= critRate:
		return "CRIT"
	case rate >= warnRate:
		return "WARN"
	default:
		return "INFO"
	}
}

// deepTCPCounterInsights evaluates the cumulative-since-boot TcpExt counters
// (SYN retransmissions, listen-queue overflows, retransmit failures). These are
// totals since boot, not live readings, so a single old spike on a long-uptime
// host would otherwise read as a current outage. Severity comes from the shared
// DeepTCPCounterLevel; the wording here makes the since-boot/rate nature explicit.
func deepTCPCounterInsights(net models.NetworkInfo) []models.Insight {
	var out []models.Insight

	if lvl := DeepTCPCounterLevel(netKwSynRetrans, net.SynRetransCount, net.UptimeSec); lvl != "" {
		rate := eventsPerHour(net.SynRetransCount, net.UptimeSec)
		if lvl == "WARN" { // sustained — active packet loss or overload
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("~%.0f SYN retransmissions/hr since boot (%d total) — packet loss or server overload", rate, net.SynRetransCount),
				[]string{"to inspect: cat /proc/net/netstat | grep TCPSynRetrans", "to inspect: ss -tan state syn-sent"},
			))
		} else {
			out = append(out, insight("INFO", "Network",
				fmt.Sprintf("%d SYN retransmissions since boot%s — cumulative, low ongoing rate", net.SynRetransCount, rateSuffix(rate)),
				[]string{"to inspect: cat /proc/net/netstat | grep TCPSynRetrans"},
			))
		}
	}

	if lvl := DeepTCPCounterLevel(netKwListenOverflow, net.ListenOverflows, net.UptimeSec); lvl != "" {
		rate := eventsPerHour(net.ListenOverflows, net.UptimeSec)
		fix := []string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096", "to fix: sysctl -w net.ipv4.tcp_max_syn_backlog=4096"}
		switch lvl {
		case "CRIT": // sustained saturation — connections actively dropped
			out = append(out, insight("CRIT", "Network",
				fmt.Sprintf("listen queue overflowing (~%.0f/hr, %d since boot) — SYN backlog saturated, connections being dropped", rate, net.ListenOverflows),
				fix,
			))
		case "WARN":
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("%d listen-queue overflow(s) since boot (~%.1f/hr) — SYN backlog saturated at times", net.ListenOverflows, rate),
				fix,
			))
		default: // a handful since boot, or uptime unknown — historical, not necessarily live
			out = append(out, insight("INFO", "Network",
				fmt.Sprintf("%d listen-queue overflow(s) since boot%s — backlog saturated at least once, not necessarily ongoing", net.ListenOverflows, rateSuffix(rate)),
				fix,
			))
		}
	}

	if lvl := DeepTCPCounterLevel(netKwRetransFail, net.RetransFailCount, net.UptimeSec); lvl != "" {
		rate := eventsPerHour(net.RetransFailCount, net.UptimeSec)
		if lvl == "WARN" { // retransmits giving up entirely at a real rate — active failure
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("~%.0f TCP retransmit failures/hr since boot (%d total) — persistent connectivity problems", rate, net.RetransFailCount),
				[]string{"to inspect: cat /proc/net/netstat | grep TCPRetransFail", "to inspect: ss -ti"},
			))
		} else {
			out = append(out, insight("INFO", "Network",
				fmt.Sprintf("%d TCP retransmit failures since boot%s — cumulative, low ongoing rate", net.RetransFailCount, rateSuffix(rate)),
				[]string{"to inspect: cat /proc/net/netstat | grep TCPRetransFail"},
			))
		}
	}

	return out
}

// nicErrorRateHigh reports whether a NIC's cumulative error counter represents a
// sustained link-layer fault rather than a stale boot-time blip. It requires both an
// absolute floor (>100 errors, so trivial counts on idle links are ignored) and an
// error rate above 0.01% of packets (so 100 errors across billions of packets on a
// long-lived host does not fire a perpetual "happening now" warning).
func nicErrorRateHigh(errors, packets uint64) bool {
	const (
		absFloor  = 100
		rateLimit = 0.0001 // 0.01% of packets
	)
	if errors <= absFloor || packets == 0 {
		return false
	}
	return float64(errors)/float64(packets) > rateLimit
}

func checkNetwork(net models.NetworkInfo) []models.Insight { //nolint:funlen,cyclop // network checks are a flat list; splitting would hurt readability
	var out []models.Insight

	if net.SteamOSWifi != nil {
		out = append(out, checkSteamOSWifi(net.SteamOSWifi)...)
	}

	// WiFi signal quality checks
	for _, iface := range net.Interfaces {
		if iface.WiFi == nil || iface.WiFi.SignalDBm == 0 {
			continue
		}
		dbm := iface.WiFi.SignalDBm
		ssid := iface.WiFi.SSID
		if ssid == "" {
			ssid = iface.Name
		}
		switch {
		case dbm < -80:
			out = append(out, insight("CRIT", "Network",
				fmt.Sprintf("WiFi signal very weak on %s: %ddBm (ssid: %s) — connection likely unstable", iface.Name, dbm, ssid),
				[]string{
					"move closer to the access point",
					"check for interference on this channel",
					fmt.Sprintf("to inspect: nmcli dev wifi list ifname %s", iface.Name),
				},
			))
		case dbm < -70:
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("WiFi signal weak on %s: %ddBm (ssid: %s) — expect packet loss", iface.Name, dbm, ssid),
				[]string{
					"move closer to the access point or switch to 5GHz band",
					fmt.Sprintf("to inspect: nmcli dev wifi list ifname %s", iface.Name),
				},
			))
		}
	}

	// Note: bond WARN/CRIT insights are generated by the BondingCollector
	// and appear in the dedicated Bonding row. The Network row shows bond
	// status inline via networkInline() only — no duplicate WARN/CRIT here.
	// INFO insights for USB slaves are added here so the Network row shows ℹ️.
	for _, b := range net.Bonds {
		if b.Degraded || b.AllDown {
			continue // WARN/CRIT handled by BondingCollector
		}
		for _, s := range b.Slaves {
			if isUSBNetworkInterface(s.Name) {
				out = append(out, insight("INFO", "Network",
					fmt.Sprintf("bond %s: slave %s is a USB NIC — less reliable than PCIe for production bonding", b.Name, s.Name),
					[]string{
						"note: USB adapters can be accidentally unplugged; USB bus is a single point of failure",
						"note: consider replacing with a PCIe or onboard NIC for production HA",
					},
				))
			}
		}
	}

	// Link speed check — 100Mbps on a server primary interface suggests wrong
	// cable (Cat5 instead of Cat5e/Cat6) or switch port misconfiguration.
	for _, iface := range net.Interfaces {
		if iface.Name == net.PrimaryInterface && iface.SpeedMbps > 0 && iface.SpeedMbps < 1000 {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("primary interface %s linked at %d Mbps — expected 1000+ Mbps (check cable or switch port)", iface.Name, iface.SpeedMbps),
				[]string{
					"to inspect: ethtool " + iface.Name,
					"to inspect: cat /sys/class/net/" + iface.Name + "/speed",
				},
			))
		}
		// USB-attached NIC as primary interface
		if iface.Name == net.PrimaryInterface && iface.IsUSB {
			driver := iface.Driver
			if driver == "" {
				driver = "USB NIC"
			}
			speedInfo := ""
			if iface.SpeedMbps >= 1000 {
				speedInfo = fmt.Sprintf(" @ %dGbps", iface.SpeedMbps/1000)
			} else if iface.SpeedMbps > 0 {
				speedInfo = fmt.Sprintf(" @ %dMbps", iface.SpeedMbps)
			}
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("primary interface %s is USB-attached (%s%s) — susceptible to disconnect/reset, not recommended for production", iface.Name, driver, speedInfo),
				[]string{
					"to inspect: dmesg | grep -i usb",
					"to inspect: lsusb",
				},
			))
		}
		// Hardware NIC errors (CRC, frame, overrun) — distinct from drops.
		// rx/tx_errors are cumulative since boot, so a flat count fires forever after a
		// one-time boot event. Gate on the error RATE (errors as a fraction of packets):
		// require both a meaningful absolute floor AND >0.01% of traffic erroring.
		if nicErrorRateHigh(iface.RxErrors, iface.RxPackets) ||
			nicErrorRateHigh(iface.TxErrors, iface.TxPackets) {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("%s has hardware errors: rx:%d tx:%d — may indicate bad cable, NIC, or switch port", iface.Name, iface.RxErrors, iface.TxErrors),
				[]string{
					"to inspect: ethtool -S " + iface.Name,
					"to inspect: ip -s link show " + iface.Name,
				},
			))
		}
	}

	if net.PrimaryInterfaceDown {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("primary interface %s is DOWN", net.PrimaryInterface),
			[]string{netInspectIPLink, netInspectIPRoute, fmt.Sprintf("to fix: ip link set %s up", net.PrimaryInterface)},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs < 0 {
		out = append(out, insight("CRIT", "Network",
			"gateway and internet unreachable — host appears offline",
			[]string{netInspectIPRoute, netInspectIPLink, "to inspect: ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs >= 0 {
		out = append(out, insight("INFO", "Network",
			"gateway not responding to probes — internet traffic is flowing",
			[]string{"to inspect: traceroute 8.8.8.8", "to inspect: ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs > 200 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — severe latency", net.GatewayPingMs),
			[]string{"to inspect: ping -c5 $(ip route | awk '/default/{print $3}')", netInspectIPRoute},
		))
	} else if net.GatewayPingMs > 50 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — elevated latency", net.GatewayPingMs),
			[]string{"to inspect: ping -c5 $(ip route | awk '/default/{print $3}')"},
		))
	}
	if !net.PrimaryInterfaceDown && net.GatewayPingMs >= 0 {
		// Shared with dsd net (analysis.GatewayPacketLossLevel). Loss is sampled from
		// 2-3 pings, so 10/50 is the meaningful granularity — see thresholds.go.
		if lv := GatewayPacketLossLevel(net.GatewayPacketLossPct); lv != "" {
			hints := []string{"to inspect: ping -c20 $(ip route | awk '/default/{print $3}')"}
			if lv == "CRIT" {
				hints = append(hints, netInspectIPLink)
			}
			out = append(out, insight(lv, "Network",
				fmt.Sprintf("gateway packet loss %.0f%%", net.GatewayPacketLossPct), hints))
		}
	}
	if net.DNSFailed {
		out = append(out, insight("CRIT", "Network/DNS",
			"DNS resolution failed — cannot resolve hostnames",
			[]string{"to inspect: dig @8.8.8.8 google.com", "to inspect: cat /etc/resolv.conf", "to inspect: systemctl status systemd-resolved"},
		))
	} else if lv := DNSResolveLevel(net.DNSResolvesMs); lv != "" {
		// Shared with dsd net (analysis.DNSResolveLevel): WARN 250ms, CRIT 500ms.
		hints := []string{"to inspect: dig @8.8.8.8 google.com", "to inspect: cat /etc/resolv.conf"}
		if lv == "CRIT" {
			hints = append(hints, "to inspect: systemctl status systemd-resolved")
		}
		out = append(out, insight(lv, "Network/DNS",
			fmt.Sprintf("DNS resolution took %.0f ms", net.DNSResolvesMs), hints))
	}
	if net.CloseWaitCount > 500 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections — likely connection leak", net.CloseWaitCount),
			[]string{"to inspect: ss -s", "to inspect: ss -tan state close-wait | head -20"},
		))
	} else if net.CloseWaitCount > 100 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections", net.CloseWaitCount),
			[]string{"to inspect: ss -s", "to inspect: netstat -an | grep CLOSE_WAIT | wc -l"},
		))
	}

	// Deep TCP metrics — only populated when NetworkDeepCollector is used.
	// Shared with dsd net (analysis.TimeWaitLevel): WARN 1000, CRIT 5000 — health
	// previously had no CRIT tier, so a host with 60k TIME_WAIT read the same WARN
	// as one with 1001 (BUG-050 class).
	if lv := TimeWaitLevel(net.TimeWaitCount); lv != "" {
		out = append(out, insight(lv, "Network",
			fmt.Sprintf("%d TIME_WAIT sockets — high connection churn or missing tcp_tw_reuse", net.TimeWaitCount),
			[]string{"to inspect: ss -tan | grep TIME-WAIT | wc -l", "to inspect: ss -tan state time-wait | head -10", "to fix: sysctl -w net.ipv4.tcp_tw_reuse=1"},
		))
	}
	out = append(out, deepTCPCounterInsights(net)...)
	if net.ConntrackUsedPct >= 80 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("conntrack table %.0f%% full — new connections will be dropped when full", net.ConntrackUsedPct),
			[]string{"to inspect: conntrack -C", "to inspect: cat /proc/sys/net/netfilter/nf_conntrack_count", "to fix: sysctl -w net.netfilter.nf_conntrack_max=262144"},
		))
	} else if net.ConntrackUsedPct >= 60 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("conntrack table %.0f%% full", net.ConntrackUsedPct),
			[]string{"to inspect: conntrack -C", "to inspect: cat /proc/sys/net/netfilter/nf_conntrack_count"},
		))
	}
	return out
}

func checkClock(clock models.ClockInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if !clock.Synced {
		// RTCInLocalTZ alone doesn't mean NTP is truly broken — the kernel
		// reports unsynchronized when RTC is in local time (dual-boot Windows),
		// but NTP may be actively syncing. Downgrade to WARN in this case.
		level := "CRIT"
		if clock.RTCInLocalTZ {
			level = "WARN"
		}
		msg := "NTP is not synchronized"
		hints := []string{
			"to inspect: timedatectl status",
			"to inspect: chronyc tracking",
			"to inspect: systemctl status chronyd ntpd",
		}
		if clock.RTCInLocalTZ {
			msg = "RTC is in local timezone — NTP reports unsync (common on dual-boot with Windows)"
			hints = append(hints, "to fix: timedatectl set-local-rtc 0 (switches RTC to UTC, resolves the false CRIT)")
		}
		out = append(out, insight(level, "Clock", msg, hints))
	}
	if clock.OffsetMs != -1 {
		abs := math.Abs(clock.OffsetMs)
		if l := levelPct(abs, thresh.NTPOffsetWarnMs, thresh.NTPOffsetCritMs); l != "" {
			out = append(out, insight(l, "Clock",
				fmt.Sprintf("NTP offset is %.1f ms (source: %s)", clock.OffsetMs, clock.Source),
				[]string{"to inspect: chronyc tracking", "to inspect: ntpq -p", "to inspect: timedatectl status"},
			))
		}
	}
	return out
}

func checkBonding(b models.BondingInfo) []models.Insight {
	if len(b.Bonds) == 0 {
		return nil
	}
	var out []models.Insight
	for _, bond := range b.Bonds {
		// Single-slave bond — no redundancy
		if len(bond.Slaves) < 2 {
			out = append(out, insight("WARN", netCatBonding,
				fmt.Sprintf("%s has only 1 slave — no redundancy (second NIC missing or disconnected)", bond.Name),
				[]string{
					fmt.Sprintf(netInspectBondingFmt, bond.Name),
					netInspectIPLink,
					"note:       bonding provides no benefit with a single slave",
				},
			))
		}
		// 802.3ad (LACP) bond whose links are MII-up but not actually aggregating. The
		// MII/DownSlaves checks above read this as healthy — every slave is "up" — yet the
		// bond carries no traffic because LACP never negotiated (the switch ports aren't in
		// a matching LACP port-channel, or only some links joined the aggregator). This is
		// the dangerous false-OK: green link state over a dead bond and zero redundancy.
		if bond.NotAggregating {
			reason := "links carry no traffic and there is no redundancy"
			cause := "the switch ports are not configured in a matching LACP port-channel"
			if !isZeroMACHeuristic(bond.PartnerMAC) {
				cause = "some links failed to join the active aggregator"
			}
			out = append(out, insight("WARN", netCatBonding,
				fmt.Sprintf("%s: 802.3ad (LACP) bond is link-up but NOT aggregating — %s (%s)",
					bond.Name, reason, cause),
				[]string{
					fmt.Sprintf("to inspect: cat /proc/net/bonding/%s   (check Partner Mac Address + per-slave Aggregator ID)", bond.Name),
					"to inspect: verify the switch ports are in one LACP (802.3ad) port-channel / bond",
					"to inspect: confirm lacp_rate and that both ends agree on active/passive LACP",
				},
			))
		}
		if bond.DownSlaves == 0 {
			// Healthy — check for USB slaves as a reliability advisory
			for _, s := range bond.Slaves {
				if isUSBNetworkInterface(s.Name) {
					out = append(out, insight("INFO", netCatBonding,
						fmt.Sprintf("%s: slave %s is a USB NIC — USB adapters are less reliable than PCIe NICs for production bonding (can be unplugged, USB bus is a single point of failure)",
							bond.Name, s.Name),
						[]string{
							"note: consider replacing with a PCIe or onboard NIC for production HA",
							fmt.Sprintf("to inspect: readlink /sys/class/net/%s/device/subsystem", s.Name),
						},
					))
				}
			}
			continue
		}
		if bond.DownSlaves == len(bond.Slaves) {
			out = append(out, insight("CRIT", netCatBonding,
				fmt.Sprintf("%s: all %d slaves down — bond is completely failed", bond.Name, bond.DownSlaves),
				[]string{
					fmt.Sprintf(netInspectBondingFmt, bond.Name),
					netInspectIPLink,
				},
			))
		} else {
			out = append(out, insight("WARN", netCatBonding,
				fmt.Sprintf("%s: %d/%d slave(s) down (%s mode) — running degraded",
					bond.Name, bond.DownSlaves, len(bond.Slaves), bond.ModeShort),
				[]string{
					fmt.Sprintf(netInspectBondingFmt, bond.Name),
					netInspectIPLink,
					"to inspect: ethtool <slave-interface>",
				},
			))
		}
		// Surface individual down slaves
		for _, s := range bond.Slaves {
			if s.State == "down" {
				out = append(out, insight("INFO", netCatBonding,
					fmt.Sprintf("%s: slave %s is down (MII: %s)", bond.Name, s.Name, s.MIIStatus),
					[]string{
						fmt.Sprintf("to inspect: ethtool %s", s.Name),
						fmt.Sprintf("to inspect: ip link show %s", s.Name),
					},
				))
			}
		}
		// High link failures on any slave
		for _, s := range bond.Slaves {
			if s.LinkFails > 10 {
				out = append(out, insight("WARN", netCatBonding,
					fmt.Sprintf("%s: slave %s has %d link failures — check cable or switch port",
						bond.Name, s.Name, s.LinkFails),
					[]string{fmt.Sprintf("to inspect: ethtool %s", s.Name)},
				))
			}
		}
	}
	return out
}

func checkVLAN(v models.VLANInfo) []models.Insight {
	if len(v.Interfaces) == 0 {
		return nil
	}
	var down []string
	for _, iface := range v.Interfaces {
		if !iface.Up {
			down = append(down, fmt.Sprintf("%s (VLAN %d)", iface.Name, iface.VLANID))
		}
	}
	if len(down) == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "VLAN",
		fmt.Sprintf("%d VLAN interface(s) down: %s", len(down), strings.Join(down, ", ")),
		[]string{
			netInspectIPLink,
			"to inspect: cat /proc/net/vlan/config",
		})}
}

func checkInfiniBand(ib models.InfiniBandInfo) []models.Insight {
	if len(ib.Ports) == 0 {
		return nil
	}
	var down []string
	for _, p := range ib.Ports {
		state := strings.ToUpper(p.State)
		// An unreadable state ("") is NOT treated as active — the inline renderer
		// already counts it as not-active, so whitelisting it here was a divergence
		// false-OK. Surface it as unreadable.
		if state != "ACTIVE" {
			label := p.State
			if label == "" {
				label = "unreadable"
			}
			down = append(down, fmt.Sprintf("%s port %d (%s)", p.Device, p.Port, label))
		}
	}
	if len(down) == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "InfiniBand",
		fmt.Sprintf("%d IB port(s) not active: %s", len(down), strings.Join(down, ", ")),
		[]string{
			"to inspect: ibstat",
			"to inspect: cat /sys/class/infiniband/*/ports/*/state",
			"note: check cable and switch port",
		})}
}

func checkSRIOV(s models.SRIOVInfo) []models.Insight {
	// SR-IOV doesn't have a clear failure state — surface INFO if VFs are enabled
	if len(s.Devices) == 0 {
		return nil
	}
	total := 0
	for _, d := range s.Devices {
		total += d.NumVFs
	}
	if total == 0 {
		return nil // capable but no VFs active — expected
	}
	return nil // VFs active — healthy, shown in inline
}

// isZeroMACHeuristic reports whether a MAC string is present but all zeros — the
// kernel's "no LACP partner heard" sentinel. Mirrors the collector's isZeroMAC so the
// bonding heuristic can distinguish "no partner" from "partial aggregation" without
// importing the linux-only collector package. Empty (field absent) is not zero.
func isZeroMACHeuristic(mac string) bool {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return false
	}
	return strings.Trim(mac, "0:") == ""
}

// isUSBNetworkInterface returns true if the network interface is USB-based.
// Checks /sys/class/net/<iface>/device/subsystem symlink for "usb". Routed through
// the active source so capture/replay reproduces it instead of hitting live sysfs.
func isUSBNetworkInterface(iface string) bool {
	subsystem, err := collectors.ReadlinkViaSource(fmt.Sprintf("/sys/class/net/%s/device/subsystem", iface))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(subsystem), "usb")
}
