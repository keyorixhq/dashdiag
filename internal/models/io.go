package models

type IODeviceInfo struct {
	Name         string  `json:"name"`
	IsSSD        bool    `json:"is_ssd"`
	DriveType    string  `json:"drive_type"` // "nvme", "ssd", "hdd"
	UtilPct      float64 `json:"util_pct"`
	AwaitMs      float64 `json:"await_ms"`
	ReadMBps     float64 `json:"read_mbps"`
	WriteMBps    float64 `json:"write_mbps"`
	QueueDepth   float64 `json:"queue_depth"`
	Status       string  `json:"status"`
	StatusReason string  `json:"status_reason"`
}

type IOInfo struct {
	Devices      []IODeviceInfo `json:"devices"`
	Status       string         `json:"status"`
	StatusReason string         `json:"status_reason"`
}
