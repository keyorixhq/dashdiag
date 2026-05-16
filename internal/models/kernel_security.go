package models

type KernelSecurityInfo struct {
	SELinuxPresent    bool     `json:"se_linux_present"`
	SELinuxMode       string   `json:"se_linux_mode"`
	SELinuxDenials    int      `json:"se_linux_denials"`
	SELinuxAVCSamples []string `json:"se_linux_avc_samples,omitempty"` // up to 3 recent AVC lines
	AppArmorPresent   bool     `json:"app_armor_present"`
	AppArmorMode      string   `json:"app_armor_mode"`
	// AppArmor detail (SLES/Ubuntu/Debian)
	AppArmorProfiles int `json:"app_armor_profiles"` // total loaded profiles
	AppArmorEnforce  int `json:"app_armor_enforce"`  // profiles in enforce mode
	AppArmorComplain int `json:"app_armor_complain"` // profiles in complain mode (should be 0)
	AppArmorDenials  int `json:"app_armor_denials"`  // denials in last hour (-1 = unavailable)
}
