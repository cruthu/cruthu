package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// Bounds on reading a recorded Tetragon export. An export file is
// attacker-controlled input like everything else cruthu reads: it is a CI
// artifact or a file handed over for a `cruthu check` run, not something this
// tool produced.
const (
	// maxLineBytes bounds one export line. A real exec line with a long
	// argument string still fits in low kilobytes; 1 MiB is far above any
	// real event and far below exhausting memory on a line this reader must
	// buffer whole before it can be parsed as JSON.
	maxLineBytes = 1 << 20

	// maxExportBytes bounds the total size this reader will consume from one
	// export. The 0.1 demo's recorded trace is a few hundred lines, a few
	// hundred KB; live streaming (0.3) does not go through this reader at
	// all. 64 MiB is several orders of magnitude above any file this offline
	// reader is expected to see, matching the reasoning behind
	// index/json.go's maxIndexBytes, and kept well short of a size that would
	// make the test proving this cap fires take real wall-clock time.
	maxExportBytes = 64 << 20

	// maxLines bounds the line count independently of maxExportBytes, so a
	// file made entirely of maximally short lines cannot force an unbounded
	// number of loop iterations and map updates while staying under the byte
	// cap. This reader is offline-only, scoped to a recorded, single-container
	// export for a CI run or the 0.1 demo (personal_notes/0.1-revision.md
	// §E) — not the long-running capture 0.3's live streaming source will
	// read, which will define its own bound when it exists. 200,000 lines is
	// several orders of magnitude past either use case.
	maxLines = 200_000
)

// Tetragon's own debug flags, lowercased. Tetragon documents flags as "for
// debugging purposes only and should not be considered a reliable source of
// information" and does not commit to their casing across releases, so this
// reader lowercases every token it reads before comparing rather than pinning
// one spelling.
const (
	flagTruncFilename = "truncfilename"
	flagErrorFilename = "errorfilename"
	flagUnknown       = "unknown"
	flagNeedsCWD      = "needscwd"
	flagNoCWDSupport  = "nocwdsupport"
	flagErrorCWD      = "errorcwd"
	flagRootCWD       = "rootcwd"
)

// tetragonLine is the outer envelope of one exported event: a oneof over
// event kinds, plus the fields Tetragon attaches to every kind. The oneof
// members this reader does not otherwise decode are declared as
// json.RawMessage purely so their presence can be tested — this reader must
// tell "an exec" apart from "some other, currently uninteresting event kind"
// without decoding a kind it has no use for, per the events.proto
// GetEventsResponse oneof (process_exec, process_exit, process_kprobe,
// process_tracepoint, process_loader, process_uprobe, process_throttle,
// process_lsm, process_usdt, test, rate_limit_info).
//
// Unknown top-level fields are not rejected: Tetragon adds fields across
// releases (the roadmap's own risk register names this API churn), and a
// strict decoder here would break on every upstream release rather than only
// when a line is actually malformed.
type tetragonLine struct {
	ProcessExec       json.RawMessage `json:"process_exec"`
	ProcessExit       json.RawMessage `json:"process_exit"`
	ProcessKprobe     json.RawMessage `json:"process_kprobe"`
	ProcessTracepoint json.RawMessage `json:"process_tracepoint"`
	ProcessLoader     json.RawMessage `json:"process_loader"`
	ProcessUprobe     json.RawMessage `json:"process_uprobe"`
	ProcessThrottle   json.RawMessage `json:"process_throttle"`
	ProcessLsm        json.RawMessage `json:"process_lsm"`
	ProcessUsdt       json.RawMessage `json:"process_usdt"`
	Test              json.RawMessage `json:"test"`
	RateLimitInfo     json.RawMessage `json:"rate_limit_info"`

	// Time is when the sensor observed the event, RFC 3339 with a fractional
	// second of varying length (protobuf Timestamp's JSON mapping). It sits
	// on the envelope, not on Process, because it is the sensor's observation
	// time rather than the process's start time.
	Time string `json:"time"`
}

// tetragonProcessExec is the part of a ProcessExec event this reader uses.
type tetragonProcessExec struct {
	Process *tetragonProcess `json:"process"`
}

// tetragonProcess is the part of a Process message this reader uses. Every
// field not read here is dropped, the same discipline internal/dpkg applies
// to a Deb822 stanza: nothing reaches an Event unless it was asked for by
// name.
type tetragonProcess struct {
	Cwd    string       `json:"cwd"`
	Binary string       `json:"binary"`
	Flags  string       `json:"flags"`
	Pod    *tetragonPod `json:"pod"`

	// Docker is the runtime-agnostic fallback container identity: the first
	// 15 hex digits of the container ID, present even when there is no pod.
	Docker string `json:"docker"`
}

type tetragonPod struct {
	Container *tetragonContainer `json:"container"`
}

type tetragonContainer struct {
	ID    string         `json:"id"`
	Image *tetragonImage `json:"image"`
}

type tetragonImage struct {
	// ID is "registry/path@sha256:<hex>". Only the digest half is ever used.
	ID string `json:"id"`
}

// tetragonSource is a Source reading a recorded Tetragon export: one JSON
// object per line, as `tetragon --export-file` writes it.
type tetragonSource struct {
	sc      *bufio.Scanner
	lineNum int
	read    int64
	counts  Counts

	// err is sticky once set, including io.EOF: a Source whose stream broke
	// or ended must report the same outcome on every subsequent call rather
	// than resuming a read that already failed.
	err error
}

// NewTetragonExport builds a Source over a recorded Tetragon export.
//
// It is offline only, per the 0.1 scope in personal_notes/0.1-revision.md
// §E: r is a complete file, not a live stream, and this function returns
// once construction succeeds — all reading happens through Next.
func NewTetragonExport(r io.Reader) Source {
	sc := bufio.NewScanner(io.LimitReader(r, maxExportBytes+1))
	sc.Buffer(nil, maxLineBytes+1)

	return &tetragonSource{
		sc: sc,
		counts: Counts{
			Skipped:     map[SkipReason]int{},
			Unplaceable: map[DropReason]int{},
		},
	}
}

// Next returns the next process-exec observation, skipping and counting
// everything this adapter does not check or cannot place along the way.
func (s *tetragonSource) Next(ctx context.Context) (Event, error) {
	if s.err != nil {
		return Event{}, s.err
	}

	for {
		if err := ctx.Err(); err != nil {
			s.err = err
			return Event{}, err
		}

		if !s.sc.Scan() {
			if err := s.sc.Err(); err != nil {
				s.err = s.wrapScanErr(err)
				return Event{}, s.err
			}
			s.err = io.EOF
			return Event{}, io.EOF
		}
		s.lineNum++

		if s.lineNum > maxLines {
			s.err = fmt.Errorf("events: tetragon: more than %d lines", maxLines)
			return Event{}, s.err
		}

		line := s.sc.Bytes()
		s.read += int64(len(line)) + 1
		// Compared with >, not >=, so an export of exactly maxExportBytes is
		// distinguishable from one that overflowed it by even one byte.
		if s.read > maxExportBytes {
			s.err = fmt.Errorf("events: tetragon: export exceeds %d bytes", maxExportBytes)
			return Event{}, s.err
		}

		if len(bytes.TrimSpace(line)) == 0 {
			s.counts.Skipped[SkipBlank]++
			continue
		}

		ev, outcome, err := parseLine(line)
		if err != nil {
			s.err = fmt.Errorf("events: tetragon: line %d: %w", s.lineNum, err)
			return Event{}, s.err
		}

		switch {
		case outcome.skip != "":
			s.counts.Skipped[outcome.skip]++
		case outcome.drop != "":
			s.counts.Unplaceable[outcome.drop]++
		default:
			s.counts.Emitted++
			return ev, nil
		}
	}
}

func (s *tetragonSource) wrapScanErr(err error) error {
	if errors.Is(err, bufio.ErrTooLong) {
		return fmt.Errorf("events: tetragon: line %d exceeds %d bytes", s.lineNum+1, maxLineBytes)
	}
	return fmt.Errorf("events: tetragon: read: %w", err)
}

func (s *tetragonSource) Counts() Counts {
	return s.counts
}

// lineOutcome is what parseLine decided about one line: emit ev, or skip it
// as out of scope, or drop it as an unplaceable observation. At most one of
// skip and drop is ever set, and neither is set when the line should be
// emitted.
type lineOutcome struct {
	skip SkipReason
	drop DropReason
}

// parseLine decodes one export line and normalizes it, or reports why it
// could not be turned into an Event.
//
// An error here means the line itself is malformed — not JSON, or JSON that
// names no event kind this reader recognizes at all — and per CLAUDE.md that
// must fail the whole run rather than being silently skipped: a torn line in
// the middle of a file is evidence the rest of the file may be torn too.
func parseLine(line []byte) (Event, lineOutcome, error) {
	var tl tetragonLine
	if err := json.Unmarshal(line, &tl); err != nil {
		return Event{}, lineOutcome{}, fmt.Errorf("not a valid event: %w", err)
	}

	if present(tl.ProcessExec) {
		return parseProcessExec(tl)
	}

	for _, other := range []json.RawMessage{
		tl.ProcessExit, tl.ProcessKprobe, tl.ProcessTracepoint, tl.ProcessLoader,
		tl.ProcessUprobe, tl.ProcessThrottle, tl.ProcessLsm, tl.ProcessUsdt,
		tl.Test, tl.RateLimitInfo,
	} {
		if present(other) {
			return Event{}, lineOutcome{skip: SkipOtherKind}, nil
		}
	}

	return Event{}, lineOutcome{}, errors.New("no recognized event kind")
}

// present reports whether a oneof member was actually set. A field the
// encoder omits decodes to a nil RawMessage; a field explicitly serialized as
// JSON null decodes to the four bytes "null" and means the same thing here —
// the oneof did not choose this member.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// parseProcessExec turns a ProcessExec event into an Event, or reports why it
// cannot be checked.
func parseProcessExec(tl tetragonLine) (Event, lineOutcome, error) {
	var exec tetragonProcessExec
	if err := json.Unmarshal(tl.ProcessExec, &exec); err != nil {
		return Event{}, lineOutcome{}, fmt.Errorf("malformed process_exec: %w", err)
	}
	if exec.Process == nil {
		return Event{}, lineOutcome{}, errors.New("process_exec has no process")
	}
	p := exec.Process

	id := containerID(p)
	if id == "" {
		return Event{}, lineOutcome{skip: SkipHost}, nil
	}

	candidate, dropped := placePath(p.Binary, p.Cwd, p.Flags)
	if dropped != "" {
		return Event{}, lineOutcome{drop: dropped}, nil
	}

	when, ok := parseEventTime(tl.Time)
	if !ok {
		return Event{}, lineOutcome{drop: DropBadTime}, nil
	}

	return Event{
		ContainerID: id,
		ImageDigest: imageDigest(p),
		Path:        candidate,
		Kind:        KindProcessExec,
		Time:        when,
	}, lineOutcome{}, nil
}

// containerID reports the container a process belongs to, preferring the
// runtime-prefixed pod identity and falling back to the docker-style short
// ID a non-Kubernetes deployment reports instead. "" means the process is not
// containerized at all.
func containerID(p *tetragonProcess) string {
	if p.Pod != nil && p.Pod.Container != nil && p.Pod.Container.ID != "" {
		return p.Pod.Container.ID
	}
	return p.Docker
}

// imageDigest extracts the sha256 digest from a container image reference,
// or "" when none is present or it is not well formed. It is provenance
// only; nothing compares paths against it.
func imageDigest(p *tetragonProcess) string {
	if p.Pod == nil || p.Pod.Container == nil || p.Pod.Container.Image == nil {
		return ""
	}
	_, digest, ok := strings.Cut(p.Pod.Container.Image.ID, "@")
	if !ok || !isSHA256Digest(digest) {
		return ""
	}
	return digest
}

// isSHA256Digest reports whether d is "sha256:" plus 64 lowercase hex
// characters.
//
// This duplicates index's validDigest rather than importing it: the two
// packages check the same shape for unrelated reasons (one validates a
// stored index field, this one screens provenance pulled out of a sensor
// event), and internal/index does not export the check. Small and duplicated
// beats a shared helper that would make this package depend on index's
// internals for four lines of logic.
func isSHA256Digest(d string) bool {
	const prefix = "sha256:"
	hex, ok := strings.CutPrefix(d, prefix)
	if !ok || len(hex) != 64 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseEventTime parses the sensor's observation timestamp.
func parseEventTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// flagSet splits a Tetragon debug-flags string into a lowercased token set.
func flagSet(flags string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, f := range strings.Fields(flags) {
		set[strings.ToLower(f)] = struct{}{}
	}
	return set
}

// placePath decides the rooted, cleaned path an exec observation reports, or
// why it cannot be placed.
//
// This is the adapter half of the contract
// docs/decisions/0002-path-aliasing.md's amendment created and
// docs/decisions/0006-event-adapter-path-contract.md states in full: an
// index built after that amendment returns unowned for anything that is not
// already rooted and clean, so this function's job is to either produce
// exactly that or refuse to emit an Event at all. It never calls path.Join or
// path.Clean to accept an input — only to check one, after building the
// candidate by plain concatenation. Cleaning here would let a syntactically
// present ".." resolve through a directory the kernel walked but this
// function never did.
//
// Construct an event that represents real drift but that this code would
// classify as clean, per CLAUDE.md: an attacker execs a relative binary
// "x/../../usr/bin/ls" from cwd "/tmp", where "/tmp/x" is a symlink the
// kernel resolves elsewhere. The kernel does not run /usr/bin/ls; this
// function's candidate is "/tmp/x/../../usr/bin/ls", whose cleaned form IS
// "/usr/bin/ls" — so accepting it would silently attribute the real exec to
// coreutils. Refusing any candidate that is not already clean, rather than
// cleaning and accepting it, is what keeps that case in Unplaceable instead
// of in a false negative.
func placePath(binary, cwd, flags string) (string, DropReason) {
	tokens := flagSet(flags)
	if _, unreliable := tokens[flagTruncFilename]; unreliable {
		return "", DropUnreliable
	}
	if _, unreliable := tokens[flagErrorFilename]; unreliable {
		return "", DropUnreliable
	}
	if _, unreliable := tokens[flagUnknown]; unreliable {
		return "", DropUnreliable
	}

	if binary == "" {
		return "", DropEmptyBinary
	}
	if hasControlBytes(binary) {
		return "", DropControlBytes
	}

	var candidate string
	if strings.HasPrefix(binary, "/") {
		candidate = binary
	} else {
		root := false
		if _, ok := tokens[flagRootCWD]; ok {
			root = true
		} else {
			for _, blocking := range []string{flagNeedsCWD, flagNoCWDSupport, flagErrorCWD} {
				if _, blocked := tokens[blocking]; blocked {
					return "", DropRelativeNoCWD
				}
			}
			if !strings.HasPrefix(cwd, "/") {
				return "", DropRelativeNoCWD
			}
			if hasControlBytes(cwd) {
				return "", DropControlBytes
			}
		}

		switch {
		case root || cwd == "/":
			candidate = "/" + binary
		default:
			candidate = cwd + "/" + binary
		}
	}

	if candidate != path.Clean(candidate) {
		return "", DropNotClean
	}
	return candidate, ""
}

// hasControlBytes reports whether s contains a C0 control byte or DEL. Per
// byte rather than per rune deliberately, matching internal/index and
// internal/dpkg: every byte of a multi-byte UTF-8 sequence is >= 0x80, so no
// continuation byte is mistaken for a control character.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
