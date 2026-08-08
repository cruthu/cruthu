package cli

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

// maxErrorDepth bounds the walk over an error tree. Errors are built in this
// process rather than read from input, so exceeding this means a construction
// bug — and an unrecognizable error is a failure, not a finding.
const maxErrorDepth = 32

// exitCodeFor maps a command's returned error onto the process exit code.
// A nil error is clean; a *DriftError is a finding; everything else, including
// an error that merely wraps a *DriftError alongside a real failure, is an
// error. Failing closed here is deliberate.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitClean
	}

	// errors.As is deliberately not used here. It reports whether a
	// *DriftError is present anywhere in the tree, and "present" is the wrong
	// question: errors.Join(drift, errNoSuchIndex) contains one, but the run
	// both found drift and broke, and reporting ExitDrift would tell a pipeline
	// the tool completed. Every leaf must be a finding before the run counts as
	// one.
	if onlyDrift(err, 0) {
		return ExitDrift
	}

	return ExitError
}

// onlyDrift reports whether every leaf of err's tree is a *DriftError.
func onlyDrift(err error, depth int) bool {
	if err == nil || depth > maxErrorDepth {
		return false
	}

	// errorlint is disabled for the two checks below, and the reason is the
	// reason this function exists. Its advice — reach for errors.Is/As instead
	// of inspecting a concrete type — is right nearly everywhere and wrong
	// here: errors.As searches the whole tree and answers "is a *DriftError in
	// there somewhere", which is the question that produced the bug this
	// function fixes. Deciding whether *every* leaf is a finding means looking
	// at each node as itself, one at a time, which is a type inspection by
	// definition. Following the linter here would restore the fail-open.

	// A DriftError ends the walk. Whatever it wraps is its own business, and
	// the finding it represents is not made less of a finding by it.
	if _, ok := err.(*DriftError); ok { //nolint:errorlint // see above
		return true
	}

	switch x := err.(type) { //nolint:errorlint // see above
	case interface{ Unwrap() error }:
		return onlyDrift(x.Unwrap(), depth+1)

	case interface{ Unwrap() []error }:
		joined := x.Unwrap()
		// An empty join carries no finding, so it cannot be one.
		if len(joined) == 0 {
			return false
		}
		for _, e := range joined {
			if !onlyDrift(e, depth+1) {
				return false
			}
		}
		return true
	}

	// A leaf that is not a DriftError. This is the branch that makes a real
	// failure outrank a finding.
	return false
}
