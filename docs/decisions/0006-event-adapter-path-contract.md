# 0006 — The event adapter must emit rooted, already-clean paths, or drop the event

**Status:** accepted
**Date:** 2026-09-16

## Context

`docs/decisions/0002-path-aliasing.md`'s amendment removed `cleanAbs`'s habit of anchoring an
unrooted path at the root: `index.Owner` now returns unowned for anything that is not already rooted
and cleaned, rather than guessing a working directory it cannot know. That amendment named the
consequence explicitly — "this moves a requirement onto the event adapters" — but `internal/events`
did not exist yet to carry it. This ADR is where that requirement gets a concrete answer, for the
first `events.Source`: a reader over a recorded Tetragon export (`tetragon --export-file`).

Two properties of the real format bear directly on the contract:

- **`process.binary` is not reliably rooted.** Tetragon's own field comment calls it "absolute path of
  the executed binary," but a relative exec (a shell script run as `./app`, a binary run via a relative
  `argv[0]`) still reaches the sensor, and the proto's own debug flags (`needsCWD`, `noCWDSupport`,
  `errorCWD`, `rootcwd`) exist specifically because resolving the working directory is not
  unconditional.
- **`process.flags` is documented as unreliable.** The proto says outright that flags "are for
  debugging purposes only and should not be considered a reliable source of information." Treating
  them as authoritative when they say a path is fine, while still trusting them when they say a path is
  broken, is the asymmetry a false negative lives in.

## Decision

`internal/events`'s `Source.Next` returns an `Event` whose `Path` already satisfies
`strings.HasPrefix(Path, "/") && path.Clean(Path) == Path`, or it does not return that event at all.

**Skipped vs. unplaceable are two different outcomes, not one.** `Counts.Skipped` is for observations
never in this tool's scope: a non-exec event kind, a process with no container identity. Those are not
a coverage gap. `Counts.Unplaceable` is for an exec this adapter could not place — a relative binary
with no usable cwd, a path the sensor's own flags say is truncated or unreliable, a candidate that is
not already clean. Every one of those is a real exec this run did not check, and collapsing the two
counts into one "ignored" number would make an attacker-influenced run of all-unplaceable execs
indistinguishable from a quiet one. Branch F (the reconciler) must treat a nonzero `Unplaceable` count
as evidence the run did not see everything.

**Placement never calls `path.Join` or `path.Clean` to accept an input, only to check one.** A
candidate path is built by plain string concatenation — `cwd + "/" + binary` — and then checked against
its own `path.Clean` form. If they differ, the event is dropped, not cleaned and accepted.

**Flags are read pessimistically.** `truncFilename`, `errorFilename`, and `unknown` mark the binary
field as unreliable and drop the event, because trusting a path the sensor itself flagged as unreliable
is a policy of trusting a suppression signal without a test proving what it suppresses. Flags are
compared case-insensitively, because a field the proto says it will not stabilize the format of not
being pinned to today's exact casing is a smaller assumption than pinning it.

## The false-negative question

*Construct an event that represents real drift but that this code would classify as clean.*

There is one, and it is the reason `path.Clean` is only ever used to check a candidate and never to
build one. An attacker execs a relative binary `x/../../usr/bin/ls` from `cwd=/tmp`, where `/tmp/x` is
a symlink the kernel resolves somewhere else entirely — say into a writable directory the attacker
controls. The kernel does not run `/usr/bin/ls`; it runs whatever `/tmp/x` actually points at. But the
naive candidate this adapter could have built, `path.Join("/tmp", "x/../../usr/bin/ls")` or an
equivalent lexical clean, collapses to `/usr/bin/ls` — a real, package-owned path — and reports **clean**
for an exec that never touched coreutils. This is the same lexical/physical resolution differential
`docs/decisions/0002-path-aliasing.md`'s second amendment closed for alias targets, reappearing on the
event side of the same seam.

Refusing any candidate that does not already equal its own cleaned form closes it: the candidate above
is `/tmp/x/../../usr/bin/ls`, which is not equal to `path.Clean` of itself, so it is dropped into
`Unplaceable` rather than resolved. `FuzzTetragonExport` asserts this as an invariant on every emitted
event, not just on this one worked example.

What remains, and is not fixed by this ADR:

1. **An unplaceable exec is unchecked, not merely unreported.** It is counted, and branch F must treat
   the count as a reason the run is not clean — but the exec happened. This is a coverage gap this
   adapter can name and cannot close; closing it further would mean guessing a cwd, which is the exact
   mistake branch B removed from the index side.
2. **An attacker who can edit the export file itself can simply delete the line.** File integrity for
   a recorded export is a signing problem, and belongs to 0.2's attestation work, not to this reader.
3. **`memfd:`-style and `/dev/fd/N` binaries are emitted as ordinary unowned paths, not specially
   flagged.** They are real execs of content with no package identity, and reporting them as drift —
   rather than silently dropping them as "not a real path" — is the intended behavior, not a gap.
4. **The flags string's reliability is bounded only by Tetragon's own guarantee about it.** If a
   future sensor version stops setting `truncFilename` on a case it used to, a truncated path could
   pass through unflagged. Nothing in this reader can detect that independently; it is a reason to
   pin the sensor version this adapter is validated against once branch G's demo exists.

## Consequences

- Every future `events.Source` (Tracee, live gRPC streaming in 0.3) inherits this same contract:
  produce a rooted, already-clean `Path`, or drop the observation and count why.
- `internal/index` and `internal/events` now jointly enforce the path contract from opposite ends —
  the index refuses to match anything unrooted or uncleaned, and the adapter refuses to emit anything
  that would fail that match for the wrong reason. Weakening either side without the other reopens the
  gap ADR 0002's amendment closed.
- `Kind` covers only `process-exec` in this branch. Shared-object loads need Tetragon's
  `process_loader` event or a kprobe policy, which is enough of a different decoding path to be its own
  branch before branch F's HIGH tier can be meaningful.
