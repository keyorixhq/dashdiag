package models

type KernelSecurityInfo struct {
	SELinuxPresent  bool   `json:"se_linux_present"`
	SELinuxMode     string `json:"se_linux_mode"`
	SELinuxDenials  int    `json:"se_linux_denials"`
	AppArmorPresent bool   `json:"app_armor_present"`
	AppArmorMode    string `json:"app_armor_mode"`
	Status          string `json:"status"`
	StatusReason    string `json:"status_reason"`
}
