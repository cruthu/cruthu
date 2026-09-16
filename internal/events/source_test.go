package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestTetragonSourceEmitsAndCounts(t *testing.T) {
	t.Parallel()

	relativeNoCWD := baseProcess()
	relativeNoCWD.Flags = "execve"
	relativeNoCWD.Cwd = ""
	relativeNoCWD.Binary = "app"

	body := join(
		execLine(t, baseProcess(), testTime),
		[]byte(""), // blank line
		otherKindLine(t, "process_exit"),
		func() []byte {
			p := baseProcess()
			p.Pod = nil
			p.Docker = ""
			return execLine(t, p, testTime)
		}(),
		execLine(t, relativeNoCWD, testTime),
		execLine(t, baseProcess(), testTime),
	)

	src := NewTetragonExport(bytes.NewReader(body))
	got := drainEvents(t, src)

	if len(got) != 2 {
		t.Fatalf("emitted %d events, want 2: %+v", len(got), got)
	}
	for _, ev := range got {
		if ev.Path != "/usr/bin/ls" {
			t.Errorf("emitted event has Path = %q, want /usr/bin/ls", ev.Path)
		}
	}

	counts := src.Counts()
	if counts.Emitted != 2 {
		t.Errorf("Emitted = %d, want 2", counts.Emitted)
	}
	if counts.Skipped[SkipBlank] != 1 {
		t.Errorf("Skipped[blank] = %d, want 1", counts.Skipped[SkipBlank])
	}
	if counts.Skipped[SkipOtherKind] != 1 {
		t.Errorf("Skipped[other-kind] = %d, want 1", counts.Skipped[SkipOtherKind])
	}
	if counts.Skipped[SkipHost] != 1 {
		t.Errorf("Skipped[host] = %d, want 1", counts.Skipped[SkipHost])
	}
	if counts.Unplaceable[DropRelativeNoCWD] != 1 {
		t.Errorf("Unplaceable[relative-no-cwd] = %d, want 1", counts.Unplaceable[DropRelativeNoCWD])
	}
}

func TestTetragonSourceEmptyInputIsImmediateEOF(t *testing.T) {
	t.Parallel()

	src := NewTetragonExport(strings.NewReader(""))

	// F must treat a zero-event run as non-clean rather than as "checked and
	// found nothing": an empty export is indistinguishable, from here, from a
	// sensor that was never actually attached.
	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("Next on empty input = %v, want io.EOF", err)
	}

	counts := src.Counts()
	if counts.Emitted != 0 || len(counts.Skipped) != 0 || len(counts.Unplaceable) != 0 {
		t.Errorf("Counts() = %+v, want all zero", counts)
	}
}

func TestTetragonSourceRejectsMalformedLineMidStream(t *testing.T) {
	t.Parallel()

	body := string(execLine(t, baseProcess(), testTime)) + "\n" +
		"{this is not json" + "\n" +
		string(execLine(t, baseProcess(), testTime)) + "\n"

	src := NewTetragonExport(strings.NewReader(body))

	if _, err := src.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}

	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("second Next: want an error for the malformed line")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error = %v, want it to name line 2", err)
	}

	// A stream that broke must report the same failure on every subsequent
	// call rather than resuming past the malformed line and checking less
	// than it claims to.
	if _, err2 := src.Next(context.Background()); !errors.Is(err2, err) {
		t.Errorf("third Next = %v, want the same terminal error %v", err2, err)
	}
}

func TestTetragonSourceAcceptsFinalLineWithoutNewline(t *testing.T) {
	t.Parallel()

	// No trailing newline: a complete final line is not distinguishable from
	// a file simply cut at a line boundary, so it is accepted.
	body := execLine(t, baseProcess(), testTime)

	src := NewTetragonExport(bytes.NewReader(body))

	if _, err := src.Next(context.Background()); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("second Next = %v, want io.EOF", err)
	}
}

func TestTetragonSourceRejectsTornFinalLine(t *testing.T) {
	t.Parallel()

	full := execLine(t, baseProcess(), testTime)
	torn := full[:len(full)-8] // cut mid-object, no closing braces

	src := NewTetragonExport(bytes.NewReader(torn))

	if _, err := src.Next(context.Background()); err == nil {
		t.Fatal("Next on a torn final line: want an error")
	}
}

func TestTetragonSourceRejectsOverLongLine(t *testing.T) {
	t.Parallel()

	line := strings.Repeat(" ", maxLineBytes+1)
	src := NewTetragonExport(strings.NewReader(line))

	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("want an error for a line over the byte cap")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d bytes", maxLineBytes)) {
		t.Errorf("error = %v, want the line cap named", err)
	}
}

func TestTetragonSourceAcceptsLineAtCap(t *testing.T) {
	t.Parallel()

	// A blank line of exactly maxLineBytes, immediately followed by a real
	// event: the boundary case must not be refused, and the blank line must
	// not itself surface to the caller.
	body := strings.Repeat(" ", maxLineBytes) + "\n" + string(execLine(t, baseProcess(), testTime)) + "\n"

	src := NewTetragonExport(strings.NewReader(body))

	ev, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.Path != "/usr/bin/ls" {
		t.Errorf("Path = %q, want /usr/bin/ls", ev.Path)
	}
	if src.Counts().Skipped[SkipBlank] != 1 {
		t.Errorf("Skipped[blank] = %d, want 1", src.Counts().Skipped[SkipBlank])
	}
}

func TestTetragonSourceRejectsTooManyLines(t *testing.T) {
	t.Parallel()

	// maxLines is 200,000, which no test should materialize as a real
	// buffer, so the input is a reader that manufactures blank lines forever
	// without allocating them.
	src := NewTetragonExport(blankLineReader{})

	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("want an error once the line cap is exceeded")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d lines", maxLines)) {
		t.Errorf("error = %v, want the line cap named", err)
	}
}

func TestTetragonSourceRejectsOversizedExport(t *testing.T) {
	t.Parallel()

	// maxExportBytes is 1 GiB; a synthetic reader emitting long blank lines
	// crosses it in about a thousand lines instead of a thousand megabytes of
	// materialized test data.
	src := NewTetragonExport(newRepeatingBlankLines(maxLineBytes - 1024))

	_, err := src.Next(context.Background())
	if err == nil {
		t.Fatal("want an error once the export size cap is exceeded")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d bytes", maxExportBytes)) {
		t.Errorf("error = %v, want the export size cap named", err)
	}
}

func TestTetragonSourceHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	src := NewTetragonExport(blankLineReader{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := src.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next with a canceled context = %v, want context.Canceled", err)
	}
}

// blankLineReader manufactures an endless stream of one-byte blank lines
// without allocating them, the same trick internal/index's endlessDirFS uses
// to exercise a cap that no test should build for real.
type blankLineReader struct{}

func (blankLineReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '\n'
	}
	return len(p), nil
}

// repeatingBlankLines manufactures an endless stream of blank lines of a
// fixed length, cycling a small pattern rather than materializing gigabytes
// of test data.
type repeatingBlankLines struct {
	pattern []byte
	pos     int
}

func newRepeatingBlankLines(lineLen int) *repeatingBlankLines {
	pattern := make([]byte, lineLen+1)
	for i := 0; i < lineLen; i++ {
		pattern[i] = ' '
	}
	pattern[lineLen] = '\n'
	return &repeatingBlankLines{pattern: pattern}
}

func (r *repeatingBlankLines) Read(p []byte) (int, error) {
	// Filled with copy() in pattern-sized chunks rather than byte by byte:
	// this reader has to produce on the order of a gigabyte to cross
	// maxExportBytes, and a per-byte assignment loop over that much data
	// makes the test itself the slow part of the suite, especially under the
	// race detector.
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.pattern[r.pos:])
		n += c
		r.pos += c
		if r.pos == len(r.pattern) {
			r.pos = 0
		}
	}
	return n, nil
}
