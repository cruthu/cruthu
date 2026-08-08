package cli

import "errors"

// Exit codes are part of the tool's public contract: CI pipelines branch on
// them, so they are defined once here and never invented at a call site.
//
// The distinction that matters is between ExitDrift and ExitError. A pipeline
// that treats "the tool broke" as "the image is clean" fails open, which for a
// drift detector is the worst possible failure mode. Any error that is not
// explicitly a drift finding must therefore surface as ExitError.
const (
	// ExitClean means the run completed and found nothing at or above the
	// configured severity threshold.
	ExitClean = 0

	// ExitDrift means the run completed successfully and found drift at or
	// above the configured severity threshold. It is a result, not a failure.
	ExitDrift = 1

	// ExitError means the tool could not complete the run: bad flags,
	// unreadable input, malformed data. It says nothing about drift.
	ExitError = 2
)

// DriftError signals that a command completed normally but observed drift at
// or above its threshold. It is the only way to reach ExitDrift, so a plain
// error can never be mistaken for a clean-but-drifted result.
type DriftError struct {
	// Summary is a short human-readable statement of what was found, used as
	// the process's final stderr line.
	Summary string
}

func (e *DriftError) Error() string {
	return e.Summary
}

// exitCodeFor maps a command's returned error onto the process exit code.
// A nil error is clean; a *DriftError is a finding; everything else, including
// an error that merely wraps a *DriftError alongside a real failure, is an
// error. Failing closed here is deliberate.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitClean
	}

	var drift *DriftError
	if errors.As(err, &drift) {
		return ExitDrift
	}

	return ExitError
}
