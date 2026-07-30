# Cyclomatic Complexity Refactor Candidates

**Read this as a worklist, not a mandate.** High CCN correlates with
more test paths and higher change risk, but the shape matters more than
the number: a long sequential migration chain or a field-by-field
`normalize()`/mapper function can have a very high CCN while being
low-risk (each branch is independent, not nested, and rarely touched
together). Prioritize functions that *mix unrelated concerns* in one
place over ones that are just long dispatch/mapping tables — and
refactor opportunistically, when you are already touching the function
for a feature or bugfix, rather than as a dedicated sweep.

Scanned with `lizard -C 15` (Go, `cmd/` + `internal/`, excluding test files, testdata, fixtures, captures). 124 functions exceed CCN 15.

| CCN | Function | Location | NLOC | Params |
|---:|---|---|---:|---:|
| 78 | `buildHealthCollectors` | `cmd/health.go:667` | 264 | 3 |
| 49 | `inlineData` | `internal/render/health.go:433` | 101 | 1 |
| 43 | `checkNetwork` | `internal/analysis/heuristics_network.go:336` | 170 | 1 |
| 42 | `printNetReport` | `cmd/net.go:255` | 133 | 4 |
| 42 | `parseSSHFileContent` | `internal/collectors/security_linux.go:187` | 90 | 2 |
| 40 | `prescanContext` | `internal/analysis/heuristics.go:196` | 63 | 2 |
| 39 | `checkNVMe` | `internal/analysis/heuristics_storage.go:127` | 207 | 1 |
| 34 | `printCPUReport` | `cmd/cpu.go:95` | 96 | 7 |
| 30 | `checkHardware` | `internal/analysis/heuristics_hardware.go:353` | 132 | 1 |
| 30 | `Evaluate` | `internal/cis/rules.go:5776` | 67 | 5 |
| 29 | `printCron` | `cmd/cron.go:57` | 80 | 2 |
| 29 | `collectPhysicalDrives` | `internal/collectors/disk_linux.go:26` | 89 | 0 |
| 29 | `checkSysctl` | `internal/analysis/heuristics_system.go:144` | 99 | 1 |
| 28 | `collectOneDrive` | `internal/collectors/hardware_linux.go:112` | 69 | 2 |
| 28 | `parseKmsg` | `internal/collectors/logs_linux.go:199` | 81 | 3 |
| 28 | `checkDockerResources` | `internal/analysis/heuristics_virt.go:407` | 126 | 1 |
| 27 | `printDiskLVM` | `cmd/disk.go:416` | 73 | 2 |
| 27 | `countPVEIssues` | `cmd/pve.go:510` | 41 | 1 |
| 26 | `applyOne` | `internal/analysis/heuristics.go:742` | 54 | 3 |
| 25 | `printSystemdHealth` | `cmd/services.go:216` | 80 | 2 |
| 25 | `steamOSConcernCount` | `cmd/steamos.go:288` | 48 | 1 |
| 25 | `parseCrontabFile` | `internal/collectors/cron_linux.go:186` | 67 | 2 |
| 25 | `collectDarwinDriveInfo` | `internal/collectors/disk_darwin.go:84` | 64 | 2 |
| 24 | `parseBondFileContent` | `internal/collectors/bonding_linux.go:84` | 81 | 2 |
| 24 | `parseSMARTAttributes` | `internal/collectors/disk_linux.go:250` | 58 | 2 |
| 24 | `buildMarkdown` | `internal/render/report.go:35` | 108 | 4 |
| 24 | `verrevcmp` | `internal/cvedata/version_dpkg.go:90` | 43 | 2 |
| 23 | `printHardwareDrivesSection` | `cmd/hardware.go:155` | 71 | 2 |
| 23 | `printCVEResult` | `cmd/cve.go:173` | 78 | 1 |
| 23 | `parseCgroupPath` | `internal/collectors/health_deep_linux.go:981` | 56 | 1 |
| 23 | `collectRAM` | `internal/collectors/hardware_linux.go:345` | 58 | 2 |
| 23 | `ApplyPolicy` | `internal/analysis/policy.go:82` | 69 | 2 |
| 23 | `checkKernelSecurity` | `internal/analysis/heuristics_system.go:427` | 90 | 2 |
| 23 | `detectCloudEnvironmentFromPaths` | `internal/platform/cloud.go:41` | 52 | 4 |
| 22 | `gpuConcerns` | `cmd/gpu.go:325` | 16 | 1 |
| 22 | `dispatchLive` | `internal/drilldown/drilldown.go:85` | 53 | 3 |
| 22 | `collectWiFiIwconfig` | `internal/collectors/network_quick.go:809` | 60 | 2 |
| 22 | `parseProcCPUInfo` | `internal/collectors/cpuinfo.go:28` | 55 | 1 |
| 22 | `parseSudoersFile` | `internal/collectors/security_linux.go:613` | 57 | 2 |
| 22 | `renderStoryFromHistory` | `internal/render/story.go:45` | 82 | 1 |
| 22 | `renderDetails` | `internal/render/health.go:1428` | 57 | 1 |
| 21 | `runCIS` | `cmd/cis.go:69` | 82 | 2 |
| 21 | `checkCVEDNF` | `internal/collectors/cve_linux.go:250` | 60 | 2 |
| 21 | `Collect` | `internal/collectors/gpu_linux.go:42` | 74 | 1 |
| 21 | `detectWorkload` | `internal/collectors/sysctl.go:119` | 25 | 0 |
| 21 | `checkGPUDevice` | `internal/analysis/heuristics_hardware.go:238` | 86 | 3 |
| 21 | `ParseRHELOVAL` | `internal/cvedata/oval_rhel.go:72` | 76 | 1 |
| 20 | `countDiskIssues` | `cmd/disk.go:253` | 38 | 2 |
| 20 | `parseProcNetTCP` | `internal/collectors/security_linux.go:467` | 65 | 2 |
| 20 | `parseSupportconfig` | `internal/collectors/security_linux.go:1825` | 56 | 1 |
| 20 | `checkDisk` | `internal/analysis/heuristics_storage.go:992` | 82 | 2 |
| 20 | `checkCPU` | `internal/analysis/heuristics_resources.go:18` | 69 | 3 |
| 20 | `Check closure (CIS rule 3.5.1.6)` | `internal/cis/rules.go:2169` | 63 | 2 |
| 20 | `Check closure (CIS rule 5.5.3)` | `internal/cis/rules.go:3681` | 54 | 2 |
| 20 | `Check closure (CIS rule 6.2.13)` | `internal/cis/rules.go:4690` | 55 | 2 |
| 19 | `Collect` | `internal/collectors/auth_linux.go:22` | 74 | 1 |
| 19 | `parseSessions` | `internal/collectors/sessions.go:54` | 62 | 1 |
| 19 | `parseNFTInputAccept` | `internal/collectors/firewall_linux.go:177` | 48 | 1 |
| 19 | `scanAllZypper` | `internal/collectors/cve_linux.go:556` | 71 | 1 |
| 19 | `collectNICs` | `internal/collectors/hardware_linux.go:409` | 59 | 2 |
| 19 | `parseMultipathL` | `internal/collectors/multipath_linux.go:163` | 59 | 1 |
| 19 | `RenderPostMortem` | `internal/render/postmortem.go:14` | 78 | 4 |
| 19 | `Check closure (CIS rule 3.5.1.4)` | `internal/cis/rules.go:2075` | 51 | 2 |
| 19 | `ParseUbuntuOVAL` | `internal/cvedata/oval_debian.go:223` | 68 | 1 |
| 18 | `printDNS` | `cmd/net.go:721` | 65 | 2 |
| 18 | `printGPUPerformance` | `cmd/gpu.go:171` | 61 | 2 |
| 18 | `parseSsOutput` | `internal/drilldown/network.go:52` | 74 | 2 |
| 18 | `parseDarwinSSHFile` | `internal/collectors/security_darwin.go:85` | 42 | 2 |
| 18 | `collectZypper` | `internal/collectors/packages_linux.go:686` | 76 | 1 |
| 18 | `armImplementerName` | `internal/collectors/cpuinfo.go:147` | 40 | 1 |
| 18 | `parseSnapperPlain` | `internal/collectors/snapper_linux.go:71` | 43 | 2 |
| 18 | `Collect` | `internal/collectors/docker.go:55` | 57 | 1 |
| 18 | `suggestSELinuxFix` | `internal/collectors/security_linux.go:2294` | 45 | 5 |
| 18 | `enrichDNFAdvisoryWithCVEs` | `internal/collectors/cve_linux.go:739` | 50 | 2 |
| 18 | `mergeZpoolStatus` | `internal/collectors/zfs.go:107` | 51 | 2 |
| 18 | `bindParseZoneFile` | `internal/collectors/bind_linux.go:270` | 56 | 2 |
| 18 | `parseTCPCounters` | `internal/collectors/network_deep.go:125` | 54 | 1 |
| 18 | `Collect` | `internal/collectors/ipmi_linux.go:37` | 38 | 1 |
| 18 | `parseMDStat` | `internal/collectors/raid_linux.go:54` | 45 | 1 |
| 18 | `Correlate` | `internal/analysis/correlate.go:43` | 56 | 1 |
| 18 | `checkSSHHardening` | `internal/analysis/heuristics_security.go:124` | 114 | 1 |
| 18 | `StatusIcon` | `internal/output/tty.go:34` | 49 | 2 |
| 18 | `PrintAllLayered` | `internal/render/health.go:301` | 55 | 2 |
| 18 | `networkInline` | `internal/render/health.go:1281` | 54 | 1 |
| 18 | `buildOutput` | `internal/render/json.go:64` | 69 | 2 |
| 17 | `printSELinuxSection` | `cmd/security.go:489` | 61 | 2 |
| 17 | `printBINDReport` | `cmd/net.go:872` | 57 | 1 |
| 17 | `printCompare` | `cmd/compare.go:152` | 69 | 3 |
| 17 | `Collect` | `internal/collectors/firmware.go:24` | 74 | 1 |
| 17 | `collectDNF` | `internal/collectors/packages_linux.go:289` | 67 | 1 |
| 17 | `analyzeDNSQuality` | `internal/collectors/dns_linux.go:179` | 48 | 1 |
| 17 | `Collect` | `internal/collectors/swap.go:87` | 64 | 1 |
| 17 | `parseK8sEventAgeSeconds` | `internal/analysis/heuristics_virt.go:927` | 36 | 1 |
| 17 | `azureRecognitionLine` | `internal/analysis/heuristics_azure.go:148` | 43 | 1 |
| 17 | `checkPVEBackups` | `internal/analysis/heuristics_pve.go:242` | 78 | 1 |
| 17 | `Save` | `internal/source/persist.go:52` | 60 | 1 |
| 17 | `Check closure (CIS rule 4.2.3)` | `internal/cis/rules.go:2759` | 38 | 2 |
| 17 | `compareSegment` | `internal/cvedata/version.go:176` | 44 | 4 |
| 17 | `Prune` | `internal/store/prune.go:14` | 62 | 3 |
| 16 | `printDockerContainers` | `cmd/docker.go:228` | 51 | 2 |
| 16 | `printCISReport` | `cmd/cis.go:158` | 56 | 4 |
| 16 | `printRHELSecuritySection` | `cmd/security.go:386` | 36 | 2 |
| 16 | `printNFSReport` | `cmd/net.go:806` | 57 | 2 |
| 16 | `runHealth` | `cmd/health.go:104` | 88 | 2 |
| 16 | `printPVENode` | `cmd/pve.go:146` | 53 | 2 |
| 16 | `printPVEGuests` | `cmd/pve.go:207` | 58 | 2 |
| 16 | `runCVEInfo` | `cmd/cve.go:390` | 81 | 0 |
| 16 | `parseNFTRuleset` | `internal/collectors/firewall_linux.go:302` | 39 | 2 |
| 16 | `parseFailedLogins` | `internal/collectors/security_linux.go:338` | 46 | 2 |
| 16 | `parsePasswordAging` | `internal/collectors/security_linux.go:2028` | 42 | 1 |
| 16 | `scanAllPacman` | `internal/collectors/cve_linux.go:1141` | 67 | 1 |
| 16 | `topMemoryProcs` | `internal/collectors/health_deep_linux.go:233` | 60 | 1 |
| 16 | `parseDmesgLine` | `internal/collectors/timeline_linux.go:365` | 53 | 2 |
| 16 | `checkZFSPool` | `internal/analysis/heuristics_storage.go:468` | 107 | 1 |
| 16 | `checkDNS` | `internal/analysis/heuristics_dns.go:12` | 74 | 1 |
| 16 | `checkNetworkExposure` | `internal/analysis/heuristics_security.go:305` | 105 | 1 |
| 16 | `untarGz` | `internal/source/tarball.go:98` | 53 | 2 |
| 16 | `Check closure (CIS rule 6.2.11)` | `internal/cis/rules.go:4598` | 45 | 2 |
| 16 | `Check closure (CIS rule 6.2.14)` | `internal/cis/rules.go:4748` | 45 | 2 |
| 16 | `Check closure (CIS rule 6.2.15)` | `internal/cis/rules.go:4796` | 45 | 2 |
| 16 | `Check closure (CIS rule 6.2.16)` | `internal/cis/rules.go:4844` | 45 | 2 |
| 16 | `checkAuditRule` | `internal/cis/rules.go:5702` | 42 | 3 |
| 16 | `EnrichFromRHAPI` | `internal/cvedata/rh_api.go:47` | 53 | 3 |
| 16 | `scanSUSEPatchClass` | `internal/cvedata/oval.go:336` | 61 | 2 |
