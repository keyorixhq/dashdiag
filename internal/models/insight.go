package models

type Insight struct {
	Level   string   `json:"level"`
	Check   string   `json:"check"`
	Message string   `json:"message"`
	Hints   []string `json:"hints"`
}
