package events

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"
	"testing"
)

// FuzzTetragonExport drives the reader over arbitrary bytes.
//
// A recorded export is attacker-controlled input parsed by hand-written code,
// which is what CLAUDE.md requires a fuzz target for. The assertion is the
// contract this package exists to uphold rather than merely "it doesn't
// panic": every Event this reader ever emits has a Path that is already
// rooted and clean. Anything else is the false-negative class
// docs/decisions/0006-event-adapter-path-contract.md exists to name — a path
// internal/index's Owner would silently fail to match the very file it
// should have matched.
func FuzzTetragonExport(f *testing.F) {
	f.Add(join(mustExecLine(baseProcess(), testTime)))
	f.Add(join(
		mustExecLine(baseProcess(), testTime),
		mustOtherKindLine("process_exit"),
		[]byte(""),
	))
	// Every drop and skip case from TestParseLineDropsUnplaceableExecs and
	// TestParseLineSkipsHostProcesses, so the fuzzer starts from a corpus
	// that already reaches every branch rather than rediscovering them.
	for _, mutate := range []func(*tetragonProcess){
		func(p *tetragonProcess) { p.Flags = "execve"; p.Cwd = ""; p.Binary = "app" },
		func(p *tetragonProcess) { p.Flags = "execve needsCWD"; p.Cwd = ""; p.Binary = "app" },
		func(p *tetragonProcess) { p.Flags = "execve truncFilename" },
		func(p *tetragonProcess) { p.Flags = "execve"; p.Cwd = "/tmp"; p.Binary = "x/../../usr/bin/ls" },
		func(p *tetragonProcess) { p.Binary = "/usr/bin/../../etc/passwd" },
		func(p *tetragonProcess) { p.Binary = "/usr//bin/ls" },
		func(p *tetragonProcess) { p.Binary = "/usr/bin/ls/" },
		func(p *tetragonProcess) { p.Binary = "/usr/bin/ls\x00etc" },
		func(p *tetragonProcess) { p.Binary = "" },
		func(p *tetragonProcess) { p.Pod = nil; p.Docker = "" },
	} {
		p := baseProcess()
		mutate(&p)
		f.Add(join(mustExecLine(p, testTime)))
	}
	f.Add([]byte("{this is not json\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add(join([]byte(`{"process_exec":{},"node_name":"n","time":"` + testTime + `"}`)))

	f.Fuzz(func(t *testing.T, body []byte) {
		src := NewTetragonExport(strings.NewReader(string(body)))

		for {
			ev, err := src.Next(context.Background())
			if err != nil {
				if !errors.Is(err, io.EOF) {
					// Any other error is a refused input, which is exactly
					// what CLAUDE.md's fail-closed rule asks for. Refused,
					// not panicked, is the property under test here; the
					// error's content is unconstrained.
					return
				}
				break
			}

			if !strings.HasPrefix(ev.Path, "/") {
				t.Fatalf("emitted Path %q is not rooted", ev.Path)
			}
			if path.Clean(ev.Path) != ev.Path {
				t.Fatalf("emitted Path %q is not already clean (path.Clean gives %q)", ev.Path, path.Clean(ev.Path))
			}
			if ev.ContainerID == "" {
				t.Fatalf("emitted event has no container identity: %+v", ev)
			}
			if ev.Kind != KindProcessExec {
				t.Fatalf("emitted event has Kind %q, want %q", ev.Kind, KindProcessExec)
			}
		}

		counts := src.Counts()
		if counts.Emitted < 0 {
			t.Fatalf("negative Emitted count: %d", counts.Emitted)
		}
	})
}
