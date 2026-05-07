package models

import "time"

type LogError struct {
	Message   string    `json:"message"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source"`
}

type LogsInfo struct {
	ErrorCount    int        `json:"error_count"`
	WarnCount     int        `json:"warn_count"`
	TopErrors     []LogError `json:"top_errors"`
	Sources       []string   `json:"sources"`
	SinceMinutes  int        `json:"since_minutes"`
	JournalSizeGB float64    `json:"journal_size_gb"`
	Status        string     `json:"status"`
	StatusReason  string     `json:"status_reason"`
}
