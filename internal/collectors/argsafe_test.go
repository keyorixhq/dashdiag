package collectors

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// argvSpy records every command the collectors try to run.
type argvSpy struct {
	mu    sync.Mutex
	calls [][]string
}

func (s *argvSpy) source() source.Live {
	return mockExec(func(name string, args []string) (source.Result, error) {
		s.mu.Lock()
		s.calls = append(s.calls, append([]string{name}, args...))
		s.mu.Unlock()
		return source.Result{ExitCode: 1}, nil
	})
}

func (s *argvSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// optionShaped values that must never reach a tool as an operand.
var optionShaped = []string{"--version", "-h", "--help", "-", "--output=x", "-x"}

func TestValidUnitName(t *testing.T) {
	good := []string{"sshd.service", "sshd@10.0.0.1:22-1.2.3.4:5.service", "systemd-resolved", `getty@tty1.service`, `dev-disk-by\x2duuid.device`, "a", "NetworkManager"}
	bad := []string{"", "--version", "-h", "-.mount", "a b", "a;b", "a/b", "$(id)", "a\nb", "a`b`", "é.service", strings.Repeat("a", 257)}
	for _, s := range good {
		if !validUnitName(s) {
			t.Errorf("validUnitName(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validUnitName(s) {
			t.Errorf("validUnitName(%q) = true, want false", s)
		}
	}
}

func TestValidIfaceAndOperand(t *testing.T) {
	for _, s := range []string{"eth0", "ens5", "br-1a2b", "bond0.100", "wlan0", "docker0", "veth12@if3"} {
		if !validIfaceName(s) {
			t.Errorf("validIfaceName(%q) = false", s)
		}
	}
	for _, s := range append([]string{"", "a b", "a\n", strings.Repeat("a", 65)}, optionShaped...) {
		if validIfaceName(s) {
			t.Errorf("validIfaceName(%q) = true", s)
		}
	}
	for _, s := range []string{"/dev/nvme0n1", "nvme0", "my vm", "tank/data", "/mnt/-x"} {
		if !validOperand(s) {
			t.Errorf("validOperand(%q) = false", s)
		}
	}
	for _, s := range append([]string{"", "a\x00b", "a\nb"}, optionShaped...) {
		if validOperand(s) {
			t.Errorf("validOperand(%q) = true", s)
		}
	}
}

func TestRunSystemctl_Argv(t *testing.T) {
	tests := []struct {
		name  string
		opts  []string
		units []string
		want  []string // nil = must not execute
	}{
		{"is-active", []string{"is-active"}, []string{"sshd.service"}, []string{"systemctl", "is-active", "--", "sshd.service"}},
		{"show props", []string{"show", "--property=ActiveState"}, []string{"cron.service"}, []string{"systemctl", "show", "--property=ActiveState", "--", "cron.service"}},
		{"batch", []string{"show"}, []string{"a.service", "b.service"}, []string{"systemctl", "show", "--", "a.service", "b.service"}},
		{"leading dash --version", []string{"is-active"}, []string{"--version"}, nil},
		{"leading dash -h", []string{"show"}, []string{"-h"}, nil},
		{"dash among valid", []string{"show"}, []string{"a.service", "--user"}, nil},
		{"shell metachar", []string{"show"}, []string{"a;reboot"}, nil},
		{"empty", []string{"show"}, []string{""}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spy := &argvSpy{}
			defer SetSource(SetSource(spy.source()))
			_, err := runSystemctl(context.Background(), runCmd, tc.opts, tc.units...)
			if tc.want == nil {
				var ua *unsafeArgError
				if !errors.As(err, &ua) {
					t.Fatalf("err = %v, want *unsafeArgError", err)
				}
				if spy.count() != 0 {
					t.Fatalf("executed %v, want no exec", spy.calls)
				}
				return
			}
			_ = err // the spy exits 1; only argv matters
			if len(spy.calls) != 1 || !reflect.DeepEqual(spy.calls[0], tc.want) {
				t.Fatalf("argv = %v, want %v", spy.calls, tc.want)
			}
		})
	}
}

func TestGuarded(t *testing.T) {
	ran := 0
	fn := func() (string, error) { ran++; return "ok", nil }
	for _, v := range optionShaped {
		if _, err := guarded(validOperand, "operand", v, fn); err == nil {
			t.Errorf("guarded accepted %q", v)
		}
	}
	if ran != 0 {
		t.Fatalf("fn ran %d times for option-shaped values", ran)
	}
	if out, err := guarded(validOperand, "operand", "/dev/sda", fn); err != nil || out != "ok" || ran != 1 {
		t.Fatalf("guarded rejected a normal value: %q %v ran=%d", out, err, ran)
	}
}

// Caller-level checks that do not depend on the OS (docker.go, k8s.go, ...).
func TestHostUnitCallers_NoOptionInjection(t *testing.T) {
	for _, bad := range optionShaped {
		spy := &argvSpy{}
		prev := SetSource(spy.source())
		quadletUnitState(context.Background(), bad)
		k8sUnitActive(context.Background(), bad)
		SetSource(prev)
		if spy.count() != 0 {
			t.Errorf("unit %q reached exec: %v", bad, spy.calls)
		}
	}
	// A normal unit still goes through with "--" before the operand.
	spy := &argvSpy{}
	defer SetSource(SetSource(spy.source()))
	k8sUnitActive(context.Background(), "kubelet")
	want := []string{"systemctl", "is-active", "--", "kubelet"}
	if len(spy.calls) != 1 || !reflect.DeepEqual(spy.calls[0], want) {
		t.Fatalf("argv = %v, want %v", spy.calls, want)
	}
}
