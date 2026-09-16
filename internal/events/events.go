// Package events reads runtime observations and normalizes them into the
// shape the reconciler compares against a file-to-package index.
//
// Every source in this package is untrusted input, exactly like an SBOM or a
// package database: it is a recorded export written by a sensor, read off
// disk long after the container it describes has exited. See
// docs/decisions/0006-event-adapter-path-contract.md for the path contract
// this package exists to enforce, and internal/index's cleanAbs/Owner for the
// other half of it: an index built after branch B returns unowned for any
// path that is not rooted and cleaned, so an adapter that hands it anything
// else has silently created a blind spot rather than a match.
package events

import (
	"context"
	"time"
)

// Kind identifies what an Event observed. Only KindProcessExec exists in this
// branch; shared-object loads need a different Tetragon event
// (process_loader) and land in a follow-up branch, per
// docs/decisions/0006-event-adapter-path-contract.md.
type Kind string

// KindProcessExec is an observed exec: a binary the kernel actually ran.
const KindProcessExec Kind = "process-exec"

// Event is one runtime observation, normalized for the reconciler.
//
// Path is always rooted and already clean: path.Clean(Path) == Path and
// strings.HasPrefix(Path, "/"). A Source that cannot produce a path meeting
// that guarantee must drop the observation instead of emitting it — see
// Counts.Unplaceable. This is not a convenience; internal/index.Owner returns
// unowned for anything that fails the same check, so an Event that violated
// it would silently fail to match the very package it should have matched,
// which is a false negative rather than a formatting bug.
type Event struct {
	// ContainerID identifies the container the observation came from: a
	// runtime-prefixed ID (e.g. "containerd://...") when the sensor reports
	// one, otherwise the shorter docker-style prefix. Never empty — an
	// observation with no container identity is a host process and a Source
	// must skip it rather than emit it, because cruthu has no index to check
	// a host process against.
	ContainerID string

	// ImageDigest is "sha256:" plus 64 lowercase hex when the source reports
	// one, and "" otherwise. It is provenance for the attestation, never a
	// match key: the index in force is chosen by the caller, not by this
	// field.
	ImageDigest string

	Path string
	Kind Kind
	Time time.Time
}

// SkipReason explains why an observation was never in scope for this tool. A
// skipped observation is not a coverage gap: it is a kind of event this tool
// does not check, or an event outside any container, and F must not count it
// toward a blind spot.
type SkipReason string

const (
	// SkipOtherKind is a recognized non-exec event: process exit, a kprobe
	// hit, a tracepoint, and so on. 0.1 checks execs only.
	SkipOtherKind SkipReason = "other-kind"

	// SkipHost is a process with no container identity at all.
	SkipHost SkipReason = "host"

	// SkipBlank is a blank line in the export file. Real exports do not
	// contain them; a hand-edited or concatenated file might.
	SkipBlank SkipReason = "blank"
)

// DropReason explains why an observation was in scope but this adapter could
// not place it. Unlike a SkipReason, a drop is a coverage gap: the exec
// happened and was not checked. F must treat a nonzero Unplaceable count as
// evidence the run did not see everything, per
// docs/decisions/0006-event-adapter-path-contract.md.
type DropReason string

const (
	// DropUnreliable is set when the sensor's own debug flags say the binary
	// path is truncated, unreadable, or the process was never resolved
	// (Tetragon's truncFilename, errorFilename, and unknown flags). Trusting
	// a path the sensor itself flagged as unreliable is exactly the kind of
	// silent narrowing CLAUDE.md's suppression rule exists to prevent.
	DropUnreliable DropReason = "unreliable"

	// DropEmptyBinary is an exec with no binary path at all.
	DropEmptyBinary DropReason = "empty-binary"

	// DropControlBytes is a binary or cwd containing a NUL or other control
	// byte, which cannot be a real kernel path.
	DropControlBytes DropReason = "control-bytes"

	// DropRelativeNoCWD is a relative binary path with no usable cwd to
	// resolve it against: the cwd is missing, unrooted, or the sensor's own
	// flags say it could not be resolved (needsCWD, noCWDSupport, errorCWD).
	// Guessing a cwd here is the mistake branch B removed from the index
	// side; the adapter must not reintroduce it on the event side.
	DropRelativeNoCWD DropReason = "relative-no-cwd"

	// DropNotClean is a candidate path that does not already equal its own
	// path.Clean form. Cleaning it here rather than refusing it would let a
	// binary or cwd containing ".." resolve through a symlinked directory the
	// kernel actually walked but this code never did — see
	// docs/decisions/0006-event-adapter-path-contract.md for the worked
	// example.
	DropNotClean DropReason = "not-clean"

	// DropBadTime is an event with a missing or unparseable timestamp. 0.3's
	// observation windows and gap tracking depend on knowing when an
	// observation happened, so an event this adapter cannot place in time is
	// as uncheckable as one it cannot place on the filesystem.
	DropBadTime DropReason = "bad-time"
)

// Counts summarizes what a Source did with everything it read.
//
// Skipped and Unplaceable are kept apart deliberately. A skipped event was
// never in this tool's scope; an unplaceable one was in scope and could not
// be checked. Collapsing the two into one "ignored" number would let a run
// full of unplaceable execs — the exact blind spot an attacker who can
// influence the sensor's flags or working directory would want — report
// identically to a quiet run that only ever saw process exits.
type Counts struct {
	Emitted     int
	Skipped     map[SkipReason]int
	Unplaceable map[DropReason]int
}

// Source yields normalized events in stream order.
//
// Next returns io.EOF once the stream is exhausted cleanly; any other error
// means the stream could not be fully read, and per CLAUDE.md's fail-closed
// rule that must surface as cli.ExitError, never as a run that quietly
// checked less than it claimed to.
type Source interface {
	Next(ctx context.Context) (Event, error)

	// Counts reports running totals. It is safe to call at any point, and it
	// is authoritative only after Next has returned io.EOF or a terminal
	// error: a caller that stops early has not seen the whole story.
	Counts() Counts
}
