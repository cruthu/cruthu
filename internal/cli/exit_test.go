package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	t.Parallel()

	drift := &DriftError{Summary: "1 critical finding"}

	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "nil is clean",
			err:  nil,
			want: ExitClean,
		},
		{
			name: "drift error is a finding, not a failure",
			err:  drift,
			want: ExitDrift,
		},
		{
			name: "wrapped drift error is still a finding",
			err:  fmt.Errorf("check: %w", drift),
			want: ExitDrift,
		},
		{
			name: "plain error is a tool failure",
			err:  errors.New("cannot read index"),
			want: ExitError,
		},
		{
			name: "wrapped plain error is a tool failure",
			err:  fmt.Errorf("open index: %w", errors.New("permission denied")),
			want: ExitError,
		},
		{
			// An error that merely mentions drift in its text must not be
			// promoted to ExitDrift. Only the typed sentinel counts.
			name: "error whose message resembles drift is still a failure",
			err:  errors.New("drift detected"),
			want: ExitError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := exitCodeFor(tt.err); got != tt.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestExitCodesAreStable(t *testing.T) {
	t.Parallel()

	// These values are documented in README.md and gated on by CI pipelines.
	// Changing one is a breaking change to the tool's contract, so it should
	// require deliberately editing this test.
	if ExitClean != 0 || ExitDrift != 1 || ExitError != 2 {
		t.Fatalf("exit codes changed: clean=%d drift=%d error=%d; these are a public contract",
			ExitClean, ExitDrift, ExitError)
	}
}

func TestDriftErrorMessage(t *testing.T) {
	t.Parallel()

	err := &DriftError{Summary: "2 critical, 1 high"}
	if got := err.Error(); got != "2 critical, 1 high" {
		t.Errorf("Error() = %q, want %q", got, "2 critical, 1 high")
	}
}
