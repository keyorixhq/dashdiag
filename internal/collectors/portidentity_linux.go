//go:build linux

package collectors

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// tcpListenerPID finds the PID of the process listening on 127.0.0.1:port
// (or any address) per `ss -tlnp`, if attributable. checked is false when ss
// itself failed or is unavailable — callers must not treat that as "no
// listener". A zero pid with checked=true means ss ran but couldn't attribute
// an owner: either the non-root ownership blind spot (ss -p can only resolve
// socket owners for the invoking UID without CAP_SYS_PTRACE) or genuinely
// nothing listening on the port.
func tcpListenerPID(ctx context.Context, port string) (pid int, checked bool) {
	out, err := runCmd(ctx, "ss", "-tlnp")
	if err != nil {
		return 0, false
	}
	checked = true
	portSuffix := ":" + port
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, portSuffix+" ") && !strings.Contains(line, portSuffix+"\t") {
			continue
		}
		if m := ssPIDRe.FindStringSubmatch(line); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				return p, true
			}
		}
	}
	return 0, checked
}

var ssPIDRe = regexp.MustCompile(`pid=(\d+)`)

// pidCmdlineContains reports whether /proc/<pid>/cmdline contains substr
// (case-insensitive). Used as a lightweight identity check for a process
// discovered via a port scan, stronger than trusting an unauthenticated
// network response alone: cmdline is populated by the kernel at exec() time
// from the process's own argv, not from anything the network protocol
// controls. Not a full authentication mechanism — a determined local attacker
// with the same access already implied by "can bind this port before the
// real service starts" can still shape argv[0]/args to match — but it raises
// the bar past a bare protocol-response shape match, matching the "confirm
// via process identity, else disclose unverified" pattern already used for
// BIND (bind_linux.go's isBindProcess/PortsOwnershipUnverified).
func pidCmdlineContains(pid int, substr string) bool {
	data, err := readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	cmdline := strings.ToLower(strings.ReplaceAll(string(data), "\x00", " "))
	return strings.Contains(cmdline, strings.ToLower(substr))
}
