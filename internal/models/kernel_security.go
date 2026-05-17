package models

type KernelSecurityInfo struct {
	SELinuxPresent    bool     `json:"se_linux_present"`
	SELinuxMode       string   `json:"se_linux_mode"`
	SELinuxDenials    int      `json:"se_linux_denials"`
	SELinuxAVCSamples []string `json:"se_linux_avc_samples,omitempty"` // up to 3 recent AVC lines

	// SELinux policy type validation — the Red Hat boot failure case.
	// SELINUXTYPE= in /etc/selinux/config must name an installed policy package.
	// When it references a non-existent policy (e.g. "permissive" instead of "targeted"),
	// dbus-daemon fails to load its contexts file and cascades to all dependent services.
	SELinuxType         string `json:"se_linux_type,omitempty"`          // value of SELINUXTYPE= (e.g. "targeted")
	SELinuxTypeValid    bool   `json:"se_linux_type_valid,omitempty"`    // true when type is targeted/minimum/mls
	SELinuxPolicyDirOK  bool   `json:"se_linux_policy_dir_ok,omitempty"` // true when /etc/selinux/<type>/ exists
	SELinuxPolicyPkgOK  bool   `json:"se_linux_policy_pkg_ok,omitempty"` // true when selinux-policy-<type> is installed
	SELinuxRelabelPending bool  `json:"se_linux_relabel_pending,omitempty"` // true when /.autorelabel exists

	AppArmorPresent bool `json:"app_armor_present"`
	AppArmorMode    string `json:"app_armor_mode"`
	// AppArmor detail (SLES/Ubuntu/Debian)
	AppArmorProfiles int `json:"app_armor_profiles"` // total loaded profiles
	AppArmorEnforce  int `json:"app_armor_enforce"`  // profiles in enforce mode
	AppArmorComplain int `json:"app_armor_complain"` // profiles in complain mode (should be 0)
	AppArmorDenials  int `json:"app_armor_denials"`  // denials in last hour (-1 = unavailable)
}
