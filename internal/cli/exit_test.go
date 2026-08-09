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
		{
			// The case this function's doc comment always described and the
			// code did not implement. A run that found drift and then broke
			// must not report as a completed run that found drift: the
			// findings it never got to are indistinguishable from findings
			// that do not exist, so ExitDrift would tell a pipeline the image
			// had been fully checked when it had not.
			name: "drift joined with a real failure is a failure",
			err:  errors.Join(drift, errors.New("truncated event stream")),
			want: ExitError,
		},
		{
			name: "real failure joined ahead of drift is a failure",
			err:  errors.Join(errors.New("unreadable index"), drift),
			want: ExitError,
		},
		{
			// Wrapping the join must not launder it either.
			name: "wrapped join of drift and failure is a failure",
			err:  fmt.Errorf("check: %w", errors.Join(drift, errors.New("boom"))),
			want: ExitError,
		},
		{
			// Drift found by two independent checks is still only drift.
			name: "join of drift errors is a finding",
			err:  errors.Join(drift, &DriftError{Summary: "2 high findings"}),
			want: ExitDrift,
		},
		{
			// Nothing in the tree is a finding, so there is nothing to report
			// as one. errors.Join() itself returns nil, which is genuinely
			// clean, so reaching this branch takes a hand-built joiner.
			name: "error joining nothing is a failure",
			err:  emptyJoin{},
			want: ExitError,
		},
		{
			// A chain longer than the walk will follow is unrecognizable, and
			// an unrecognizable error is a failure rather than a finding.
			name: "drift buried deeper than the walk goes is a failure",
			err:  wrapTimes(drift, maxErrorDepth+2),
			want: ExitError,
		},
		{
			name: "drift just inside the depth limit is still a finding",
			err:  wrapTimes(drift, maxErrorDepth-1),
			want: ExitDrift,
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

// emptyJoin is an error that reports a join of nothing, which errors.Join
// itself will not produce because it returns nil instead.
type emptyJoin struct{}

func (emptyJoin) Error() string   { return "joins nothing" }
func (emptyJoin) Unwrap() []error { return nil }

// wrapTimes nests err inside n layers of wrapping.
func wrapTimes(err error, n int) error {
	for range n {
		err = fmt.Errorf("layer: %w", err)
	}
	return err
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
