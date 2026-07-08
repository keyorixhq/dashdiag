package models

import "time"

// MTEFaultEvent is one ARM Memory Tagging Extension tag-check-fault crash
// parsed from the kernel journal/dmesg.
type MTEFaultEvent struct {
	Process   string    `json:"process"`
	PID       int       `json:"pid,omitempty"`
	FaultType string    `json:"fault_type"`         // "synchronous" or "asynchronous"
	Timestamp time.Time `json:"timestamp,omitzero"` // omitempty is a no-op on struct-typed fields — use omitzero
}

// MTEInfo holds ARM Memory Tagging Extension support and fault-visibility
// posture: whether the hardware/kernel support the feature, whether the
// kernel is configured to actually log a tag-check-fault crash, and any
// recent faults found in the kernel log.
type MTEInfo struct {
	Available             bool            `json:"available"`               // arm64 + "mte" in /proc/cpuinfo Features
	ExceptionTraceEnabled bool            `json:"exception_trace_enabled"` // debug.exception-trace sysctl == 1
	RecentFaults          []MTEFaultEvent `json:"recent_faults,omitempty"`
	StatusReason          string          `json:"status_reason,omitempty"` // set when the kernel log couldn't be read
}
