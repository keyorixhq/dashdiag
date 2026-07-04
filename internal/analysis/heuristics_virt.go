package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkKVMVMs covers the per-domain state verdicts (crashed, abnormal/stuck,
// unreadable, paused, shut-off-with-autostart, disk I/O). Split out of checkKVM
// to keep each under the funlen limit; the two compose into the full KVM verdict.
func checkKVMVMs(kvm models.KVMInfo) []models.Insight {
	var out []models.Insight
	// Crashed VMs — always CRIT
	for _, vm := range kvm.VMs {
		if vm.State == models.KVMCrashed {
			hints := []string{
				fmt.Sprintf("to inspect: virsh console %s", vm.Name),
				fmt.Sprintf("to inspect: cat /var/log/libvirt/qemu/%s.log | tail -50", vm.Name),
				fmt.Sprintf("to restart: virsh start %s", vm.Name),
			}
			if vm.LastLogError != "" {
				hints = append([]string{"last log: " + vm.LastLogError}, hints...)
			}
			out = append(out, insight("CRIT", "KVM",
				fmt.Sprintf("VM %s is in CRASHED state", vm.Name), hints))
		}
	}
	// Abnormal non-running states (pmsuspended / in shutdown / idle / blocked) —
	// not running and not cleanly stopped, so they'd otherwise read as healthy.
	if kvm.VMsAbnormal > 0 {
		var names []string
		for _, vm := range kvm.VMs {
			switch vm.State {
			case models.KVMPMSuspended, models.KVMInShutdown, models.KVMIdle, models.KVMBlocked:
				names = append(names, fmt.Sprintf("%s (%s)", vm.Name, vm.State))
			}
		}
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) in an abnormal state: %s — not running and not cleanly stopped",
				kvm.VMsAbnormal, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: virsh dominfo <name>",
				"to recover: virsh dompmwakeup <name> (pmsuspended), or virsh destroy then virsh start",
			},
		))
	}
	// State could not be read (virsh dominfo failed) — couldn't verify, not healthy.
	if kvm.VMsUnreadable > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) defined but their state could not be read (virsh dominfo failed) — true state unknown", kvm.VMsUnreadable),
			[]string{
				"to inspect: virsh dominfo <name>",
				"note: a transient libvirt error or permission issue hid the VM's real state",
			},
		))
	}
	// Paused VMs — WARN
	if kvm.VMsPaused > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) paused — may indicate a problem or forgotten snapshot", kvm.VMsPaused),
			[]string{
				"to inspect: virsh list --all | grep paused",
				"to resume:  virsh resume <name>",
			},
		))
	}
	// Shut-off VMs with autostart=yes — WARN
	if kvm.VMsDownAutostart > 0 {
		var names []string
		for _, vm := range kvm.VMs {
			if (vm.State == models.KVMShutOff || vm.State == models.KVMShutDown) && vm.AutoStart {
				names = append(names, vm.Name)
			}
		}
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) shut off with autostart=yes: %s",
				kvm.VMsDownAutostart, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to start:   virsh start <name>",
				"to inspect: virsh dominfo <name>",
			},
		))
	}
	// Disk I/O errors — CRIT
	if kvm.DiskIOErrors > 0 {
		out = append(out, insight("CRIT", "KVM",
			fmt.Sprintf("%d VM(s) have recorded disk I/O errors", kvm.DiskIOErrors),
			[]string{
				"to inspect: virsh domblkerror <name>",
				"to inspect: dmesg | grep -i 'error\\|failed'",
				"note:       disk I/O errors persist across VM reboots until cleared",
			},
		))
	}
	out = append(out, checkKVMVMsXMLDeep(kvm)...)
	return out
}

// checkKVMVMsXMLDeep covers the deep-only (`dsd kvm --deep` / `dsd health --deep`)
// per-VM XML config checks: emulated NIC/disk devices and a missing backing-file.
// Split out of checkKVMVMs to keep it under the funlen limit.
func checkKVMVMsXMLDeep(kvm models.KVMInfo) []models.Insight {
	var out []models.Insight
	for _, vm := range kvm.VMs {
		if vm.MissingDiskPath != "" {
			out = append(out, insight("CRIT", "KVM",
				fmt.Sprintf("VM %s's disk image is missing: %s — the VM cannot start", vm.Name, vm.MissingDiskPath),
				[]string{
					fmt.Sprintf("to inspect: virsh domblklist %s", vm.Name),
					"note: the backing file was moved, deleted, or is on an unmounted volume",
				},
			))
		}
		if len(vm.EmulatedNICs) > 0 {
			out = append(out, insight("WARN", "KVM",
				fmt.Sprintf("VM %s: NIC(s) on an emulated driver (%s) — switch to VirtIO (virtio-net) for higher throughput at lower host CPU",
					vm.Name, strings.Join(vm.EmulatedNICs, ", ")),
				[]string{fmt.Sprintf("to inspect: virsh dumpxml %s | grep -A2 '<interface'", vm.Name)},
			))
		}
		if len(vm.EmulatedDisks) > 0 {
			out = append(out, insight("WARN", "KVM",
				fmt.Sprintf("VM %s: disk(s) on an emulated bus (%s) — switch to VirtIO Block/SCSI; emulated IDE/SATA is a common cause of slow guest I/O",
					vm.Name, strings.Join(vm.EmulatedDisks, ", ")),
				[]string{
					fmt.Sprintf("to inspect: virsh dumpxml %s | grep -A2 '<disk'", vm.Name),
					"note: changing the boot disk's bus may need the guest's bootloader/initramfs to include virtio_blk/virtio_scsi",
				},
			))
		}
	}
	return out
}

func checkKVM(kvm models.KVMInfo) []models.Insight {
	var out []models.Insight
	if !kvm.Detected {
		return out
	}
	// libvirt is up but its domains couldn't be enumerated — surface that rather than
	// letting an empty VM list read as "no VMs / healthy" (a crashed VM would be hidden).
	if kvm.Status == "enum-failed" {
		return []models.Insight{insight("WARN", "KVM", kvm.StatusReason,
			[]string{"to inspect: virsh list --all", "to inspect: systemctl status libvirtd"})}
	}
	out = append(out, checkKVMVMs(kvm)...)

	// Inactive networks — WARN
	if kvm.NetworksInactive > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d virtual network(s) inactive — VMs may lose connectivity", kvm.NetworksInactive),
			[]string{
				"to inspect: virsh net-list --all",
				"to start:   virsh net-start <name>",
				"to autostart: virsh net-autostart <name>",
			},
		))
	}
	// Inactive storage pools — WARN
	if kvm.PoolsInactive > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d storage pool(s) inactive — disk images may be inaccessible", kvm.PoolsInactive),
			[]string{
				"to inspect: virsh pool-list --all",
				"to start:   virsh pool-start <name>",
			},
		))
	}
	// Full storage pools — WARN/CRIT
	if kvm.PoolsNearFull > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d storage pool(s) >85%% full — VMs may fail to write disk", kvm.PoolsNearFull),
			[]string{
				"to inspect: virsh pool-info <name>",
				"to inspect: du -sh /var/lib/libvirt/images/*",
			},
		))
	}
	return out
}

func checkDocker(d models.DockerInfo) []models.Insight {
	var out []models.Insight

	if !d.Available {
		// 7h: socket found but permission denied. This is a non-root
		// measurement gap, not a fault — degrade to INFO ("couldn't
		// measure"), never WARN. collectSocketPermReason already carries
		// the runtime-specific fix (usermod -aG <runtime>), so don't append
		// a generic "systemctl status docker" hint that names the wrong
		// runtime for podman/crio.
		if d.SocketPermDenied {
			if d.StatusReason != "" {
				out = append(out, insight("INFO", "Docker", d.StatusReason, nil))
			}
			return out
		}
		if d.StatusReason != "" {
			out = append(out, insight("WARN", "Docker",
				d.StatusReason,
				[]string{"to inspect: systemctl status docker"},
			))
		}
		return out
	}

	// The daemon was reachable (Available) but enumerating containers failed — the
	// counts/Containers are empty, so the sub-checks below would emit nothing and
	// the host would read "Docker healthy". Surface the failure instead of letting
	// an un-enumerated daemon pass as all-clean (false-OK).
	if d.Status == "error" {
		reason := d.StatusReason
		if reason == "" {
			reason = "Docker daemon is reachable but its containers could not be listed — health not verified"
		}
		return []models.Insight{insight("WARN", "Docker", reason,
			[]string{"to inspect: docker ps -a", "to inspect: journalctl -u docker --since '10 min ago'"})}
	}

	out = append(out, checkDockerContainers(d)...)
	out = append(out, checkDockerResources(d)...)
	out = append(out, checkDockerSecurity(d)...)
	out = append(out, checkPodmanQuadlets(d)...)
	return out
}

// checkContainerd surfaces health issues for a standalone containerd runtime
// (running without a Kubernetes layer). Only called when ContainerdAvailable()
// is true and K8sAvailable() is false — avoids double-counting with dsd k8s.
func checkContainerd(d models.ContainerdInfo) []models.Insight {
	var out []models.Insight

	if !d.Available {
		// Socket found but permission denied: containerd IS installed, dsd just
		// lacks access — a non-root measurement gap, not a fault. Degrade to
		// INFO like checkDocker's identical SocketPermDenied case, never WARN.
		if d.SocketPermDenied {
			if d.StatusReason != "" {
				out = append(out, insight("INFO", "Containerd", d.StatusReason, nil))
			}
			return out
		}
		// Socket not found but service might be installed — give actionable hint
		out = append(out, insight("WARN", "Containerd",
			d.StatusReason,
			[]string{
				"to inspect: systemctl status containerd",
				"to inspect: ls /run/containerd/containerd.sock",
			},
		))
		return out
	}

	// Service not active despite socket being reachable — transient state
	if d.ServiceState != "" && d.ServiceState != "active" && d.ServiceState != "unknown" {
		out = append(out, insight("CRIT", "Containerd",
			fmt.Sprintf("containerd.service is %s — runtime may be unstable", d.ServiceState),
			[]string{
				"to inspect: systemctl status containerd",
				"to fix:     systemctl restart containerd",
				"to inspect: journalctl -u containerd -n 50 --no-pager",
			},
		))
	}

	return out
}

// checkPodmanQuadlets warns when any systemd-managed Podman quadlet has failed.
// Zero failed quadlets → no insight (no noise).
func checkPodmanQuadlets(d models.DockerInfo) []models.Insight {
	var failed, inactive, unverified []string
	var firstFailed, firstInactive string
	for _, q := range d.PodmanQuadlets {
		switch {
		case q.State == "":
			// systemctl errored / was unavailable — state genuinely unknown. Don't
			// let an unreadable quadlet pass as healthy (the silent false-OK).
			unverified = append(unverified, q.Name)
		case q.Failed || q.State == "failed":
			failed = append(failed, q.Name)
			if firstFailed == "" {
				firstFailed = q.ServiceUnit
			}
		case q.Active || q.State == "active":
			// running — healthy
		case q.State == "inactive":
			// A quadlet file exists but its generated unit is not running — genuinely
			// down or a unit-name mismatch (templated/renamed → LoadState=not-found →
			// ActiveState=inactive). Transient states (activating/deactivating/
			// reloading) are deliberately not flagged to avoid boot-time false alarms.
			inactive = append(inactive, q.Name)
			if firstInactive == "" {
				firstInactive = q.ServiceUnit
			}
		}
	}

	var out []models.Insight
	if len(failed) > 0 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d Podman quadlet(s) failed: %s", len(failed), strings.Join(failed, ", ")),
			[]string{fmt.Sprintf("to inspect: systemctl status %s", firstFailed)},
		))
	}
	if len(inactive) > 0 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d Podman quadlet(s) present but not active: %s", len(inactive), strings.Join(inactive, ", ")),
			[]string{
				fmt.Sprintf("to inspect: systemctl status %s", firstInactive),
				"note: the quadlet file exists but its generated unit is not running (stopped, or a unit-name mismatch)",
			},
		))
	}
	if len(unverified) > 0 {
		out = append(out, insight("INFO", "Docker",
			fmt.Sprintf("could not determine state of %d Podman quadlet(s): %s", len(unverified), strings.Join(unverified, ", ")),
			[]string{"to inspect: systemctl show <unit> --property=ActiveState,LoadState   (systemctl unavailable or unit not found)"},
		))
	}
	return out
}

func checkDockerContainers(d models.DockerInfo) []models.Insight {
	var out []models.Insight
	for _, name := range d.CrashLooping {
		out = append(out, insight("CRIT", "Docker",
			fmt.Sprintf("container %q is crash looping (restarted >5 times)", name),
			[]string{
				fmt.Sprintf("to inspect: docker logs %s --tail 50", name),
				fmt.Sprintf("to inspect: docker inspect %s | grep -A5 RestartCount", name),
			},
		))
	}
	for _, name := range d.Unhealthy {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("container %q health check failing", name),
			[]string{
				fmt.Sprintf("to inspect: docker inspect %s | grep -A10 Health", name),
				fmt.Sprintf("to inspect: docker logs %s --tail 20", name),
			},
		))
	}
	// Count stopped containers that FAILED (non-zero exit), not every stopped one.
	// Clean-exit (exit 0) init/oneshot containers — DB migrations, secret-init,
	// test fixtures — are EXPECTED to be exited, so counting them as "accumulating"
	// false-positives on any normal Compose stack. The collector only sets ExitCode
	// for non-running containers that exited non-zero, so it's the failure marker.
	failedStopped := 0
	for _, c := range d.Containers {
		if st := strings.ToLower(c.State); (st == "exited" || st == "dead") && c.ExitCode != 0 {
			failedStopped++
		}
	}
	if failedStopped > 5 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d stopped container(s) exited with errors — crashes or failed jobs (clean-exit init/oneshot containers not counted)", failedStopped),
			[]string{
				"to inspect: docker ps -a --filter status=exited --filter status=dead",
				"to prune:   docker container prune",
			},
		))
	}
	if d.OOMEvents > 0 {
		out = append(out, insight("CRIT", "Docker",
			fmt.Sprintf("%d container OOM kill(s) in the last hour — containers are out of memory", d.OOMEvents),
			[]string{
				"to inspect: docker events --filter event=oom",
				"to fix: set memory limits in container config",
				"to inspect: docker stats --no-stream",
			},
		))
	}
	// 7i: image architecture mismatch
	if d.ArchMismatchCount > 0 {
		var mismatched []string
		for _, c := range d.Containers {
			if c.ArchMismatch {
				mismatched = append(mismatched, fmt.Sprintf("%s (image: %s, host: %s)", c.Name, c.ImageArch, d.HostArch))
			}
		}
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d container(s) have image architecture mismatch — will fail with 'exec format error': %s",
				d.ArchMismatchCount, strings.Join(firstN(mismatched, 3), ", ")),
			[]string{
				fmt.Sprintf("note: host is %s — pull or rebuild images for the correct platform", d.HostArch),
				"to fix: docker buildx build --platform linux/" + d.HostArch + " -t <image> .",
				"to fix: docker pull --platform linux/" + d.HostArch + " <image>",
			},
		))
	}
	return out
}

func checkDockerResources(d models.DockerInfo) []models.Insight { //nolint:funlen
	var out []models.Insight
	// Deprecated storage driver
	if d.Daemon != nil && d.Daemon.StorageDriver == "devicemapper" {
		out = append(out, insight("WARN", "Docker",
			"storage driver is devicemapper (deprecated) — known performance and stability issues",
			[]string{
				"to fix: migrate to overlay2 (requires re-creating all containers and images)",
				"to inspect: docker info | grep 'Storage Driver'",
				"note: devicemapper in loop mode has known data corruption risks",
			},
		))
	}
	// Spec 7d: Compose version
	if d.Daemon != nil {
		if d.Daemon.ComposeStandalone != "" && d.Daemon.ComposePlugin != "" {
			out = append(out, insight("WARN", "Docker",
				fmt.Sprintf("both docker-compose v1 (%s) and docker compose v2 (%s) installed — scripts may use the wrong one",
					d.Daemon.ComposeStandalone, d.Daemon.ComposePlugin),
				[]string{
					"to fix: remove docker-compose (v1) and use docker compose (v2) plugin only",
					"to inspect: which docker-compose && docker compose version",
				},
			))
		} else if d.Daemon.ComposeStandalone != "" && d.Daemon.ComposePlugin == "" {
			out = append(out, insight("WARN", "Docker",
				fmt.Sprintf("docker-compose v1 (%s) installed — standalone is deprecated, migrate to docker compose plugin",
					d.Daemon.ComposeStandalone),
				[]string{
					"to fix: apt install docker-compose-plugin  OR  dnf install docker-compose-plugin",
					"to migrate: replace 'docker-compose' with 'docker compose' in scripts",
				},
			))
		}
	}
	// Recent daemon errors
	if d.Daemon != nil && d.Daemon.RecentErrors > 0 {
		hints := []string{"to inspect: journalctl -u docker -n 50 --no-pager"}
		if d.Daemon.LastDaemonError != "" {
			hints = append([]string{"last error: " + d.Daemon.LastDaemonError}, hints...)
		}
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d Docker daemon error(s) in the last 10 minutes", d.Daemon.RecentErrors),
			hints,
		))
	}
	// Log driver unbounded (deep mode only). Keyed on the per-container
	// UnboundedContainers list, not the daemon-wide default: a per-container
	// --log-opt (or Compose's `logging:` stanza) commonly overrides the daemon
	// default, and checking only the daemon default false-WARNed those containers.
	if d.LogDriver != nil && len(d.LogDriver.UnboundedContainers) > 0 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d container(s) logging json-file with no max-size — logs grow unbounded: %s",
				len(d.LogDriver.UnboundedContainers), strings.Join(firstN(d.LogDriver.UnboundedContainers, 3), ", ")),
			[]string{
				"to fix (daemon-wide): add to /etc/docker/daemon.json: {\"log-opts\":{\"max-size\":\"100m\",\"max-file\":\"3\"}}, then systemctl restart docker",
				"to fix (per-container): add --log-opt max-size=100m --log-opt max-file=3 (or Compose's logging: stanza), then recreate the container",
			},
		))
	}
	// Containers whose inspect call failed/was unparseable — their log config
	// could not be checked at all; must not be silently dropped from the
	// unbounded-logging picture as if confirmed clean.
	if d.LogDriver != nil && len(d.LogDriver.UnverifiedContainers) > 0 {
		out = append(out, insight("INFO", "Docker",
			fmt.Sprintf("%d container(s) log config could not be verified (inspect failed): %s",
				len(d.LogDriver.UnverifiedContainers), strings.Join(firstN(d.LogDriver.UnverifiedContainers, 3), ", ")),
			[]string{"to inspect: docker inspect <container>"},
		))
	}
	if d.LogDriver != nil && d.LogDriver.LargeLogCount > 0 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d container log file(s) >500MB — disk usage risk", d.LogDriver.LargeLogCount),
			[]string{
				"to inspect: ls -lh /var/lib/docker/containers/*/*-json.log",
				"to fix: truncate -s 0 /var/lib/docker/containers/<id>/<id>-json.log",
			},
		))
	}
	// Dangling-image COUNT is collected (untagged images from the images API); the
	// size and orphaned-volume tiers were dead — DanglingImagesMB and OrphanedVolumes
	// were never populated, so the ">=1GB" WARN and ">3 orphaned" WARN never fired and
	// the INFO printed "0 MB". Surfacing real sizes/orphans needs `docker system df` /
	// a dangling-volume query validated against a live daemon — deferred.
	if d.DanglingImages > 0 {
		out = append(out, insight("INFO", "Docker",
			fmt.Sprintf("%d dangling image(s) — reclaimable with a prune", d.DanglingImages),
			[]string{"to fix: docker image prune"},
		))
	}
	if d.MTUMismatch {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("container network MTU (%d) > host interface MTU (%d) — silent packet fragmentation",
				d.ContainerMTU, d.HostMTU),
			[]string{
				fmt.Sprintf("to fix: set MTU %d in container network config to match host", d.HostMTU),
				"to inspect (docker): docker network inspect bridge | grep mtu",
				"to inspect (podman): podman network inspect podman | grep mtu",
				"note: MTU mismatch causes connection timeouts for large payloads (HTTP, TLS handshakes)",
			},
		))
	}
	// IP forwarding disabled — all container outbound traffic fails.
	// Gate on IPForwardChecked: an unreadable /proc path (macOS, proc-less
	// container) means state is unknown, not disabled — don't fire a false CRIT.
	if d.IPForwardChecked && !d.IPForwardEnabled && d.Available {
		out = append(out, insight("CRIT", "Docker",
			"IP forwarding disabled (net.ipv4.ip_forward=0) — container outbound traffic will fail",
			[]string{
				"to fix:    sysctl -w net.ipv4.ip_forward=1",
				"to persist: echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-docker.conf && sysctl -p",
				"note: Docker sets this on start, but systemd-networkd restart can reset it",
			},
		))
	}
	// firewalld with nftables backend — silently drops Docker iptables rules,
	// UNLESS docker0 has already been added to the trusted zone (the documented
	// fix below). Skip the WARN when that fix is in place, or we flag a host the
	// admin already remediated.
	if d.FirewalldActive && d.FirewalldBackend == "nftables" && !d.DockerZoneTrusted {
		out = append(out, insight("WARN", "Docker",
			"firewalld is active with nftables backend — Docker iptables rules are silently ignored",
			[]string{
				"fix A (switch backend): sed -i 's/FirewallBackend=nftables/FirewallBackend=iptables/' /etc/firewalld/firewalld.conf && systemctl restart firewalld docker",
				"fix B (trust docker0): firewall-cmd --permanent --zone=trusted --add-interface=docker0 && firewall-cmd --reload",
			},
		))
	}
	// 7g: DNS trap — host resolv.conf uses loopback; containers fall back to 8.8.8.8
	if d.DNSTrap {
		if d.DaemonDNSConfigured && len(d.DaemonDNSServers) > 0 {
			// Mitigated: the daemon hands containers explicit DNS, so the host's
			// loopback resolv.conf is not the resolver they use. Informational —
			// not a WARN (the admin already did the documented fix).
			out = append(out, insight("INFO", "Docker",
				fmt.Sprintf("host resolv.conf uses %s (loopback), but Docker daemon DNS is configured (%s) — containers use that",
					d.DNSTrapServer, strings.Join(d.DaemonDNSServers, ", ")),
				nil,
			))
		} else {
			out = append(out, insight("WARN", "Docker",
				fmt.Sprintf("host resolv.conf uses %s (loopback) — containers cannot reach it and fall back to 8.8.8.8", d.DNSTrapServer),
				[]string{
					"note: if 8.8.8.8 is blocked by corporate firewall, container DNS fails silently",
					"to fix: add to /etc/docker/daemon.json: {\"dns\": [\"1.1.1.1\", \"8.8.8.8\"]}",
					"to fix: systemctl restart docker",
				},
			))
		}
	}
	return out
}

func checkDockerSecurity(d models.DockerInfo) []models.Insight {
	var out []models.Insight

	// Docker socket mounted — CRIT: root-equivalent host access
	if d.SocketMountedCount > 0 {
		var names []string
		for _, c := range d.Containers {
			if c.DockerSocketMounted {
				names = append(names, c.Name)
			}
		}
		out = append(out, insight("CRIT", "Docker",
			fmt.Sprintf("%d container(s) have docker.sock mounted — grants root-equivalent host access: %s",
				d.SocketMountedCount, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: docker inspect <name> | grep docker.sock",
				"to fix: remove HostConfig.Binds entry for docker.sock",
				"note: any process inside can escape to host via Docker API",
			},
		))
	}

	// Running as root
	if d.RunningAsRootCount > 0 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d running container(s) using root user — reduces container isolation", d.RunningAsRootCount),
			[]string{
				"to fix: add 'USER <non-root>' directive to Dockerfile",
				"to fix: use --user flag: docker run --user 1000:1000 ...",
			},
		))
	}

	// Plaintext secrets
	if d.ContainersWithSecrets > 0 {
		var names []string
		for _, c := range d.Containers {
			if len(c.PlaintextSecrets) > 0 {
				names = append(names, c.Name)
			}
		}
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d container(s) have plaintext secrets in env vars: %s",
				d.ContainersWithSecrets, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: docker inspect <name> | grep -i 'env\\|secret\\|password'",
				"to fix: use Docker secrets, a vault, or environment variable files",
				"note: env vars are visible in docker inspect and container logs",
			},
		))
	}

	return out
}

func checkK8s(k models.K8sInfo) []models.Insight {
	var out []models.Insight

	if !k.Detected {
		return out
	}

	// kubectl/k3s is present but no cluster query succeeded — the API server is
	// down, the kubeconfig is wrong, or RBAC forbids it. Every count is zero
	// because we never reached the cluster, which would read as a healthy cluster.
	// Surface it as INFO ("health not verified"), not a silent green OK. INFO does
	// not raise the verdict (a kubectl-on-a-workstation pointing at a remote
	// cluster shouldn't WARN).
	if !k.APIReachable {
		return []models.Insight{insight("INFO", "K8s",
			"kubectl/k3s present but the cluster API was unreachable — cluster health NOT verified",
			[]string{
				"to inspect: kubectl get nodes",
				"check: API server up? kubeconfig valid (KUBECONFIG / ~/.kube/config)? RBAC sufficient?",
			},
		)}
	}

	out = append(out, checkK8sNodes(k)...)
	out = append(out, checkK8sPodHealth(k)...)
	out = append(out, checkK8sWorkloadsAndEvents(k)...)

	if k.OSLayer != nil {
		out = append(out, CheckK8sOSLayer(*k.OSLayer)...)
	}

	return out
}

func checkK8sNodes(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.NodesNotReady > 0 {
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("%d node(s) not Ready — cluster may be degraded", k.NodesNotReady),
			[]string{
				"to inspect: kubectl get nodes -o wide",
				"to inspect: kubectl describe node <name>",
			},
		))
	}
	for _, node := range k.Nodes {
		for cond, status := range node.Conditions {
			// Only the standard node-pressure/unavailable conditions are faults when
			// True. Distros add conditions with the OPPOSITE polarity — RKE2/k3s set
			// "EtcdIsVoter"=True to mean the node is a HEALTHY etcd voter — so blanket-
			// CRITing any True condition false-CRIT'd every RKE2 etcd node (found live
			// 2026-07-01). Never raise on a condition whose meaning we don't know.
			if status != "True" || !nodeProblemConditions[cond] {
				continue
			}
			out = append(out, insight("CRIT", "K8s",
				fmt.Sprintf("node %s: %s condition True — workloads may be evicted", node.Name, cond),
				[]string{
					fmt.Sprintf("to inspect: kubectl describe node %s | grep -A5 Conditions", node.Name),
				},
			))
		}
	}
	return out
}

// nodeProblemConditions are the standard Kubernetes node conditions that signal a
// fault when their status is True (eviction pressure or an unconfigured network).
// Conditions outside this set — distro/vendor additions such as RKE2/k3s's
// "EtcdIsVoter" (confirmed live: True means the node IS a healthy etcd voting
// member, the opposite of the standard problem-condition convention) — carry
// their own polarity, so dsd does not assume True means broken for them. Any
// other vendor condition not in this set is likewise left unscored rather than
// guessed at; add it here only once its real polarity is confirmed against a
// live cluster, not inferred from its name.
var nodeProblemConditions = map[string]bool{
	"MemoryPressure":     true,
	"DiskPressure":       true,
	"PIDPressure":        true,
	"NetworkUnavailable": true,
}

func checkK8sPodHealth(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.CrashLooping > 0 {
		hints := []string{"to inspect: kubectl get pods -A | grep -v Running"}
		for _, p := range k.Pods {
			if strings.Contains(p.Status, "CrashLoop") && p.PreviousLogs != "" {
				hints = append(hints, fmt.Sprintf("  %s/%s last log: %s",
					p.Namespace, p.Name, k8sFirstLine(p.PreviousLogs)))
			}
			if p.TerminationMsg != "" {
				hints = append(hints, fmt.Sprintf("  %s/%s exit msg: %s",
					p.Namespace, p.Name, k8sFirstLine(p.TerminationMsg)))
			}
		}
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("%d pod(s) crash looping", k.CrashLooping), hints))
	}
	// Pods stuck in init errors — a failing init container blocks the pod from
	// ever starting. InitError was parsed but never surfaced; Init:CrashLoopBackOff
	// is already counted above (it contains "CrashLoop"), so only the distinct
	// Init:Error case is reported here to avoid double-warning.
	var initErr []string
	for _, p := range k.Pods {
		if p.InitError != "" && !strings.Contains(p.Status, "CrashLoop") {
			initErr = append(initErr, fmt.Sprintf("%s/%s (%s)", p.Namespace, p.Name, p.InitError))
		}
	}
	if len(initErr) > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) stuck in init errors — workload cannot start: %s",
				len(initErr), strings.Join(firstN(initErr, 3), ", ")),
			[]string{
				"to inspect: kubectl describe pod <name> -n <ns>",
				"to inspect: kubectl logs <name> -n <ns> -c <init-container>",
				"note: common causes — missing ConfigMap/Secret, failing migration/init job",
			},
		))
	}
	if k.PodsNotReady > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) running but containers not ready", k.PodsNotReady),
			[]string{
				"to inspect: kubectl get pods -A | grep '0/'",
				"to inspect: kubectl describe pod <name> -n <ns>",
			},
		))
	}
	if k.Pending > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) stuck in Pending — check node resources or PVC availability",
				k.Pending),
			[]string{
				"to inspect: kubectl get pods -A | grep Pending",
				"to inspect: kubectl describe pod <name> -n <ns> | grep -A5 Events",
			},
		))
	}
	if k.HighRestarts > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) with ≥10 restarts — instability detected", k.HighRestarts),
			[]string{
				"to inspect: kubectl get pods -A --sort-by='.status.containerStatuses[0].restartCount'",
				"to inspect: kubectl logs <pod> -n <ns> --previous",
			},
		))
	}
	if k.Terminating > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) stuck Terminating — finalizer or webhook blocking deletion",
				k.Terminating),
			[]string{
				"to inspect: kubectl get pods -A | grep Terminating",
				"to force: kubectl delete pod <name> -n <ns> --grace-period=0 --force",
			},
		))
	}
	return out
}

func checkK8sWorkloadsAndEvents(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.PVCsNotBound > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d PVC(s) not Bound — pods waiting for storage may stay Pending",
				k.PVCsNotBound),
			[]string{
				"to inspect: kubectl get pvc -A | grep -v Bound",
				"to inspect: kubectl describe pvc <name> -n <ns>",
			},
		))
	}
	if k.WorkloadsDown > 0 {
		var names []string
		for _, w := range k.Workloads {
			if w.Ready < w.Desired {
				names = append(names, fmt.Sprintf("%s/%s (%d/%d)",
					w.Namespace, w.Name, w.Ready, w.Desired))
			}
		}
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d workload(s) degraded: %s",
				k.WorkloadsDown, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: kubectl get deploy,statefulset -A | grep -v '1/1'",
				"to inspect: kubectl rollout status deployment/<name> -n <ns>",
			},
		))
	}
	out = append(out, k8sWarningEventInsight(k.Events)...)
	return out
}

// k8sEventRecentWindowSec gates Warning events on recency. k8s retains events in
// etcd for ~1h by default, so a Warning whose last-seen age exceeds this window has
// not recurred and is treated as quiesced rather than live.
const k8sEventRecentWindowSec = 5 * 60

// k8sWarningEventInsight turns retained Warning events into an insight, gated on
// recency. Transient startup warnings (flannel subnet.env not yet written,
// readiness probes failing during boot, helm-install backoff) linger in etcd long
// after they self-heal; surfacing every retained event flipped a now-healthy
// cluster to WARN purely on stale boot noise (seen live on a fresh k3s-on-VMware
// node: 8 events all 5-6 min old, every involved pod since Running/Completed).
// Events still seen within the recency window drive the WARN; once they have all
// quiesced they are reported as INFO ("no recent recurrence — likely transient").
func k8sWarningEventInsight(events []models.K8sEvent) []models.Insight {
	if len(events) == 0 {
		return nil
	}
	var recent []models.K8sEvent
	for _, e := range events {
		// Unparseable / "<unknown>" age → treat as recent, never hide a possibly-live event.
		if sec, ok := parseK8sEventAgeSeconds(e.Age); !ok || sec <= k8sEventRecentWindowSec {
			recent = append(recent, e)
		}
	}
	if len(recent) > 0 {
		return []models.Insight{k8sEventInsight("WARN", recent)}
	}
	return []models.Insight{k8sEventInsight("INFO", events)}
}

// k8sEventInsight builds the Warning-event insight at the given level. The reason
// summary is sorted (count desc, then name) so the output is deterministic across
// replay — the old map-iteration order was non-deterministic.
func k8sEventInsight(level string, events []models.K8sEvent) models.Insight {
	reasons := map[string]int{}
	for _, e := range events {
		reasons[e.Reason]++
	}
	type rc struct {
		reason string
		count  int
	}
	ordered := make([]rc, 0, len(reasons))
	for reason, count := range reasons {
		ordered = append(ordered, rc{reason, count})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].reason < ordered[j].reason
	})
	var summary []string
	for i, r := range ordered {
		if i >= 4 {
			break
		}
		summary = append(summary, fmt.Sprintf("%s×%d", r.reason, r.count))
	}

	hints := []string{"to inspect: kubectl get events -A --field-selector type=Warning"}
	for _, e := range events {
		if strings.Contains(e.Message, "subnet.env") {
			hints = append(hints,
				"flannel subnet.env missing — CNI network plugin not ready",
				"to fix: sudo systemctl restart k3s  (regenerates subnet.env)")
			break
		}
	}

	msg := fmt.Sprintf("%d Warning event(s): %s", len(events), strings.Join(summary, ", "))
	if level == "INFO" {
		msg = fmt.Sprintf("%d Warning event(s), all quiesced (none seen in last %dm): %s",
			len(events), k8sEventRecentWindowSec/60, strings.Join(summary, ", "))
	}
	return insight(level, "K8s", msg, hints)
}

// parseK8sEventAgeSeconds parses kubectl's compact age format ("47s", "6m5s",
// "92m", "2d3h", "5h") into seconds. Returns ok=false for empty / "<unknown>" /
// unparseable input so the caller can decide. The value is relative ("ago") as of
// collection time, so the comparison stays deterministic across replay.
func parseK8sEventAgeSeconds(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "<") {
		return 0, false
	}
	total, num := 0, 0
	sawUnit, sawDigit := false, false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			num = num*10 + int(r-'0')
			sawDigit = true
		case r == 'd' || r == 'h' || r == 'm' || r == 's':
			if !sawDigit {
				return 0, false
			}
			switch r {
			case 'd':
				total += num * 86400
			case 'h':
				total += num * 3600
			case 'm':
				total += num * 60
			case 's':
				total += num
			}
			num, sawDigit, sawUnit = 0, false, true
		default:
			return 0, false
		}
	}
	if !sawUnit || sawDigit { // trailing digits without a unit, or no units at all
		return 0, false
	}
	return total, true
}

// checkK8sNodeDaemons emits insights for the node's local kubelet/containerd/firewalld
// state — split out from checkK8sOSLayer to keep it under the funlen limit.
func checkK8sNodeDaemons(l models.K8sOSLayer) []models.Insight {
	var out []models.Insight

	// Gate on KubeletChecked/ContainerdChecked: these are only set when an on-disk
	// node marker was found (rke2/k3s/k0s/microk8s/kubeadm). A kubectl-only client host
	// (e.g. a laptop pointed at a remote cluster) never has kubelet/containerd
	// installed at all — that must NOT read as "kubelet down".
	if l.KubeletChecked && !l.KubeletActive {
		out = append(out, insight("CRIT", "K8s",
			"kubelet is not running on this node — pods cannot be scheduled or managed here",
			[]string{
				"to inspect: sudo systemctl status kubelet k3s k3s-agent rke2-server rke2-agent k0scontroller k0sworker",
				"to inspect: sudo journalctl -u kubelet -u k3s -n 50 --no-pager",
			},
		))
	}

	if l.ContainerdChecked && !l.ContainerdActive {
		out = append(out, insight("CRIT", "K8s",
			"container runtime is not active on this node — no containers can be started here",
			[]string{
				"to inspect: sudo systemctl status containerd",
				"to fix (k3s/RKE2/k0s/MicroK8s): the runtime is bundled — restart the node service instead",
			},
		))
	}

	// Firewalld masquerade only matters when flannel is the configured CNI (its
	// requirement); FirewalldChecked is only true when firewalld.service itself is
	// active, so a host without firewalld (the k3s/RKE2 default) never false-fires.
	if l.FirewalldChecked && l.FlannelInUse && !l.FirewalldMasquOK {
		out = append(out, insight("WARN", "K8s",
			"firewalld is active without masquerade enabled — flannel pod networking across nodes will fail",
			[]string{
				"to fix: sudo firewall-cmd --add-masquerade --permanent && sudo firewall-cmd --reload",
			},
		))
	}

	return out
}

// CheckK8sOSLayer emits insights for OS-level k8s node health. Exported so
// cmd/k8s.go can share this exact logic for the standalone `dsd k8s --deep`
// verdict/rendering instead of re-deriving the OS-layer concern conditions by
// hand — the single-source-of-truth fix for the cmd↔health tally-drift class
// (#275): a hand-duplicated set of conditions in cmd/ silently rots out of sync
// with the heuristic `dsd health` actually uses on the same data.
func CheckK8sOSLayer(l models.K8sOSLayer) []models.Insight {
	out := checkK8sNodeDaemons(l)

	// Gate on IPForwardChecked: an unreadable /proc path leaves IPForwardEnabled
	// at its false zero value, which must not be reported as a real "disabled".
	if l.IPForwardChecked && !l.IPForwardEnabled {
		out = append(out, insight("CRIT", "K8s",
			"IP forwarding disabled — pod-to-pod networking will fail",
			[]string{
				"to fix (persistent): echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/99-k8s.conf && sysctl -p",
				"to fix (immediate): sysctl -w net.ipv4.ip_forward=1",
			},
		))
	}

	if l.FlannelInUse && !l.FlannelSubnetOK {
		out = append(out, insight("CRIT", "K8s",
			"/run/flannel/subnet.env missing — CNI network plugin cannot configure pod networking",
			[]string{
				"to fix (k3s): sudo systemctl restart k3s",
				"to inspect: sudo journalctl -u k3s -n 50 | grep -i flannel",
			},
		))
	}

	if l.CNIChecked && !l.CNIBinsOK {
		out = append(out, insight("CRIT", "K8s",
			"/opt/cni/bin/ is empty — CNI plugins not installed, networking will fail",
			[]string{
				"to fix (k3s): sudo systemctl restart k3s",
				"to fix (kubeadm): reinstall kubeadm network plugin",
			},
		))
	}

	if l.KubeForwardChecked && !l.KubeForwardChain {
		out = append(out, insight("WARN", "K8s",
			"KUBE-FORWARD chain not found in iptables/nftables — kube-proxy may not be running",
			[]string{
				"to inspect: sudo iptables -L KUBE-FORWARD -n 2>/dev/null || sudo nft list tables",
				"to inspect: kubectl get pods -n kube-system | grep kube-proxy",
			},
		))
	}

	if len(l.CertExpiredNames) > 0 {
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("k8s certificate(s) EXPIRED: %s — API server will reject requests",
				strings.Join(l.CertExpiredNames, ", ")),
			[]string{
				"to fix (kubeadm): kubeadm certs renew all",
				"to fix (k3s): sudo systemctl restart k3s  (auto-renews certs)",
			},
		))
	} else if l.CertExpirySoon {
		// Flag-gated (not days>0): a cert expiring today is 0 days, which must still
		// surface — the old days>0 test let it read as the zero-value OK (false-OK).
		when := fmt.Sprintf("in %d day(s)", l.CertExpirySoonDays)
		if l.CertExpirySoonDays == 0 {
			when = "in less than a day"
		}
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("k8s certificate(s) expire %s — renew before expiry", when),
			[]string{
				"to fix (kubeadm): kubeadm certs renew all",
				"to fix (k3s): sudo systemctl restart k3s",
			},
		))
	}

	if len(l.KubeletErrors) > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("kubelet errors in journal: %s", l.KubeletErrors[0]),
			append([]string{"to inspect: journalctl -u kubelet -u k3s -n 50 --no-pager"},
				l.KubeletErrors[1:]...),
		))
	}

	return out
}

// k8sFirstLine returns the first non-empty line of a multi-line string.
func k8sFirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}

// checkRancher flags a degraded Rancher management plane: the rancher server or its
// admission webhook with fewer ready replicas than desired. Silent when Rancher is
// absent or fully ready. Downstream-cluster management and the UI ride on these, so a
// not-ready Rancher server is a real (if not always urgent) operational gap.
func checkRancher(d models.RancherInfo) []models.Insight {
	if !d.Available {
		return nil
	}
	var out []models.Insight
	if d.ServerDesired > 0 && d.ServerReady < d.ServerDesired {
		out = append(out, insight("WARN", "Rancher",
			fmt.Sprintf("Rancher server has %d/%d replicas ready — the management plane is degraded; downstream cluster management and the UI may be unavailable", d.ServerReady, d.ServerDesired),
			[]string{
				"to inspect: kubectl -n cattle-system get pods -l app=rancher",
				"to inspect: kubectl -n cattle-system logs deploy/rancher",
			}))
	}
	if d.WebhookDesired > 0 && d.WebhookReady < d.WebhookDesired {
		out = append(out, insight("WARN", "Rancher",
			fmt.Sprintf("rancher-webhook has %d/%d replicas ready — admission webhooks may reject or stall cluster changes", d.WebhookReady, d.WebhookDesired),
			[]string{"to inspect: kubectl -n cattle-system get pods -l app=rancher-webhook"}))
	}
	return out
}

func checkNspawn(n models.NspawnInfo) []models.Insight {
	if !n.Available || len(n.Containers) == 0 {
		return nil
	}
	if n.FailedCount == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "Nspawn",
		fmt.Sprintf("%d systemd-nspawn container(s) in failed/degraded state", n.FailedCount),
		[]string{
			"to inspect: machinectl list",
			"to inspect: machinectl status <name>",
		})}
}
