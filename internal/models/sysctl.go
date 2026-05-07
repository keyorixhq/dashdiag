package models

type SysctlInfo struct {
	VMSwappiness int    `json:"vm_swappiness"`
	NetSomaxconn int    `json:"net_somaxconn"`
	FSFileMax    int    `json:"fs_file_max"`
	KernelPIDMax int    `json:"kernel_pid_max"`
	PIDCount     int    `json:"pid_count"`
	Status       string `json:"status"`
	StatusReason string `json:"status_reason"`
}
