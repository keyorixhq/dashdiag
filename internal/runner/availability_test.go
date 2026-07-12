package runner

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// alwaysPresentResult is a stand-in for a collector result type that does not
// implement the availabler contract (e.g. CPU, Memory) — IsAvailable must
// treat it as always present.
type alwaysPresentResult struct {
	Value int
}

func TestIsAvailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data any
		want bool
	}{
		{
			name: "nil data is not available",
			data: nil,
			want: false,
		},
		{
			name: "type without availabler contract is always available",
			data: alwaysPresentResult{Value: 42},
			want: true,
		},
		{
			name: "availabler type with Available=true",
			data: models.DockerInfo{Available: true, Runtime: "docker"},
			want: true,
		},
		{
			name: "availabler type with Available=false",
			data: models.DockerInfo{Available: false},
			want: false,
		},
		{
			name: "pointer to availabler type with Available=true",
			data: &models.DockerInfo{Available: true},
			want: true,
		},
		{
			name: "pointer to availabler type with Available=false",
			data: &models.DockerInfo{Available: false},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsAvailable(tt.data)
			if got != tt.want {
				t.Errorf("IsAvailable(%#v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
