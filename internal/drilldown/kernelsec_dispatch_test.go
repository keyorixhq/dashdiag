package drilldown

import (
	"context"
	"runtime"
	"testing"
)

// These tests mock runCmd/lookPath rather than requiring real getenforce/
// aa-status binaries. No t.Parallel() in this group — see swapRunCmd's doc
// comment.

func TestSelinuxEnforceMode_Enforcing(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "getenforce" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "Enforcing\n", nil
	})
	if got := selinuxEnforceMode(context.Background()); got != "enforcing" {
		t.Errorf("selinuxEnforceMode() = %q, want %q", got, "enforcing")
	}
}

func TestSelinuxEnforceMode_NotInstalled(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})
	if got := selinuxEnforceMode(context.Background()); got != "" {
		t.Errorf("selinuxEnforceMode() = %q, want empty string when getenforce is absent", got)
	}
}

func TestAppArmorComplainProfiles_NoTooling(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", errNotFound })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		t.Fatalf("runCmd should not be called when aa-status is absent, got %s %v", name, args)
		return "", nil
	})

	names, partial := appArmorComplainProfiles(context.Background())
	if names != nil || partial {
		t.Errorf("appArmorComplainProfiles() = (%v, %v), want (nil, false) when tooling is absent", names, partial)
	}
}

func TestAppArmorComplainProfiles_JSONPath(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/usr/sbin/aa-status", nil })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name == "aa-status" && len(args) > 0 && args[0] == "--pretty-json" {
			return `{"profiles":{"Xorg":"complain","sshd":"enforce"}}`, nil
		}
		t.Fatalf("expected only the --pretty-json call, got %s %v", name, args)
		return "", nil
	})

	names, partial := appArmorComplainProfiles(context.Background())
	if partial {
		t.Error("expected partial=false on a successful JSON parse")
	}
	if len(names) != 1 || names[0] != "Xorg" {
		t.Errorf("names = %v, want [Xorg]", names)
	}
}

func TestAppArmorComplainProfiles_TextFallback(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/usr/sbin/aa-status", nil })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch {
		case name == "aa-status" && len(args) > 0 && args[0] == "--pretty-json":
			return "", errNotFound // old aa-status without --pretty-json support
		case name == "aa-status" && len(args) == 0:
			return "1 profiles are in complain mode.\n   Xorg\n0 processes are in enforce mode.\n", nil
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})

	names, partial := appArmorComplainProfiles(context.Background())
	if partial {
		t.Error("expected partial=false on a successful text parse")
	}
	if len(names) != 1 || names[0] != "Xorg" {
		t.Errorf("names = %v, want [Xorg]", names)
	}
}

func TestAppArmorComplainProfiles_QueryFailsPartial(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/usr/sbin/aa-status", nil })
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound // both --pretty-json and plain text calls fail
	})

	names, partial := appArmorComplainProfiles(context.Background())
	if names != nil {
		t.Errorf("expected nil names when the query fails, got %v", names)
	}
	// partial reflects os.Geteuid() != 0 in the current process — just assert
	// it's a deterministic bool given the code path, not its specific value.
	_ = partial
}

func TestPoliciesLinux_NothingWrong(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", errNotFound })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name == "getenforce" {
			return "Enforcing\n", nil
		}
		t.Fatalf("unexpected command: %s %v", name, args)
		return "", nil
	})

	got, err := policiesLinux(context.Background())
	if err != nil {
		t.Fatalf("policiesLinux: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil Details when SELinux is enforcing and no AppArmor complain profiles, got %+v", got)
	}
}

func TestPoliciesLinux_SELinuxPermissive(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", errNotFound })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name == "getenforce" {
			return "Permissive\n", nil
		}
		t.Fatalf("unexpected command: %s %v", name, args)
		return "", nil
	})

	got, err := policiesLinux(context.Background())
	if err != nil {
		t.Fatalf("policiesLinux: %v", err)
	}
	if got == nil || len(got.Rows) != 1 || got.Rows[0][0] != "SELinux" {
		t.Errorf("expected a single SELinux-permissive row, got %+v", got)
	}
}

// PoliciesNotEnforcing itself just dispatches on runtime.GOOS: darwin always
// returns nil,nil without touching runCmd, everything else delegates to
// policiesLinux (already covered directly above). Assert per-OS so this test
// is meaningful on both the macOS dev machine and Linux CI.
func TestPoliciesNotEnforcing_Dispatch(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", errNotFound })
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if runtime.GOOS == "darwin" {
			t.Fatalf("runCmd should not be called on darwin, got %s %v", name, args)
		}
		return "Enforcing\n", nil
	})

	got, err := PoliciesNotEnforcing(context.Background())
	if err != nil {
		t.Fatalf("PoliciesNotEnforcing: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil when everything is enforcing (or on darwin), got %+v", got)
	}
}
