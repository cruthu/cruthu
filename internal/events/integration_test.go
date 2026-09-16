package events

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"cruthu.dev/core/internal/index"
)

// TestReconciliationAgainstAMergedUsrIndex is the success gate
// personal_notes/0.1-revision.md §"Revised success gates" adds: a dropped
// binary named after a real package file must be caught, and it is tested
// here rather than in the reconciler (branch F, not yet written) because the
// property under test — that this package and internal/index agree on what
// "the same path" means — belongs to the seam between them, not to either
// package alone.
func TestReconciliationAgainstAMergedUsrIndex(t *testing.T) {
	t.Parallel()

	idx := &index.Index{
		Aliases: []index.Alias{{From: "/bin", To: "/usr/bin"}},
		Packages: []index.Package{
			{ID: "deb:coreutils@1", Name: "coreutils", Version: "1", Type: "deb", Files: []string{"/usr/bin/ls"}},
		},
	}
	lookup, err := index.NewLookup(idx)
	if err != nil {
		t.Fatalf("NewLookup: %v", err)
	}

	// The compatibility-symlink spelling: ADR 0005 records that a sensor may
	// report either this or the merged spelling depending on resolution
	// behavior, and the alias table must make both queries land in the same
	// place.
	legit := baseProcess()
	legit.Binary = "/bin/ls"

	// Named after a real package file rather than an obviously fake name —
	// the case personal_notes/0.1-revision.md calls out because "the
	// obvious-name case passes today for the wrong reason".
	planted := baseProcess()
	planted.Binary = "/tmp/ls"
	planted.Flags = "execve"
	planted.Cwd = "/tmp"

	events := drainEvents(t, NewTetragonExport(bytes.NewReader(join(
		execLine(t, legit, testTime),
		execLine(t, planted, testTime),
	))))
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}

	if _, ok := lookup.Owner(events[0].Path); !ok {
		t.Errorf("Owner(%q) = not found, want /bin to alias to the coreutils-owned /usr/bin/ls", events[0].Path)
	}
	if owner, ok := lookup.Owner(events[1].Path); ok {
		t.Errorf("Owner(%q) = %q, want the planted binary unowned", events[1].Path, owner.ID)
	}
}

// TestTetragonSourceReadsRecordedFixture exercises the reader against a file
// on disk rather than an in-memory buffer, and against hand-written JSON
// rather than this package's own marshaling — so a decode bug tied to
// exactly how the test fixtures were constructed cannot hide.
func TestTetragonSourceReadsRecordedFixture(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/tetragon/sample.jsonl")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	})

	src := NewTetragonExport(f)
	events := drainEvents(t, src)

	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
	if events[0].Path != "/bin/ls" {
		t.Errorf("events[0].Path = %q, want /bin/ls", events[0].Path)
	}
	if events[1].Path != "/tmp/ls" {
		t.Errorf("events[1].Path = %q, want /tmp/ls", events[1].Path)
	}

	counts := src.Counts()
	if counts.Skipped[SkipOtherKind] != 1 {
		t.Errorf("Skipped[other-kind] = %d, want 1 (the process_exit line)", counts.Skipped[SkipOtherKind])
	}
	if counts.Skipped[SkipBlank] != 1 {
		t.Errorf("Skipped[blank] = %d, want 1", counts.Skipped[SkipBlank])
	}
}

// drainEvents reads every event from src until a clean end, failing the test
// on any other error.
func drainEvents(t *testing.T, src Source) []Event {
	t.Helper()

	var out []Event
	for {
		ev, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, ev)
	}
}
