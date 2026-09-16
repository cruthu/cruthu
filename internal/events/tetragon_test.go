package events

import (
	"strings"
	"testing"
	"time"
)

func TestParseLineEmitsExecEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    tetragonProcess

		wantPath        string
		wantContainerID string
		wantDigest      string
	}{
		{
			name:            "absolute binary, rootcwd",
			p:               baseProcess(),
			wantPath:        "/usr/bin/ls",
			wantContainerID: "containerd://abc123",
			wantDigest:      validDigestHex,
		},
		{
			name: "relative binary under rootcwd",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "usr/bin/ls"
				return p
			}(),
			wantPath:        "/usr/bin/ls",
			wantContainerID: "containerd://abc123",
			wantDigest:      validDigestHex,
		},
		{
			name: "relative binary resolved against a rooted cwd",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve"
				p.Cwd = "/home/user"
				p.Binary = "app"
				return p
			}(),
			wantPath:        "/home/user/app",
			wantContainerID: "containerd://abc123",
			wantDigest:      validDigestHex,
		},
		{
			name: "docker-only container, no pod",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Pod = nil
				p.Docker = "1234567890abcde"
				return p
			}(),
			wantPath:        "/usr/bin/ls",
			wantContainerID: "1234567890abcde",
			wantDigest:      "",
		},
		{
			name: "malformed image digest is dropped, not matched",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Pod.Container.Image.ID = "registry.example/app@notadigest"
				return p
			}(),
			wantPath:        "/usr/bin/ls",
			wantContainerID: "containerd://abc123",
			wantDigest:      "",
		},
		{
			name: "no image at all",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Pod.Container.Image = nil
				return p
			}(),
			wantPath:        "/usr/bin/ls",
			wantContainerID: "containerd://abc123",
			wantDigest:      "",
		},
		{
			name: "memfd binary carries no leading slash worth resolving, is emitted as-is",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "memfd:evil (deleted)"
				return p
			}(),
			wantPath:        "/memfd:evil (deleted)",
			wantContainerID: "containerd://abc123",
			wantDigest:      validDigestHex,
		},
		{
			name: "dev fd binary is emitted unchanged",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "/dev/fd/3"
				return p
			}(),
			wantPath:        "/dev/fd/3",
			wantContainerID: "containerd://abc123",
			wantDigest:      validDigestHex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ev, outcome, err := parseLine(execLine(t, tt.p, testTime))
			if err != nil {
				t.Fatalf("parseLine: %v", err)
			}
			if outcome.skip != "" || outcome.drop != "" {
				t.Fatalf("outcome = %+v, want the event emitted", outcome)
			}
			if ev.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", ev.Path, tt.wantPath)
			}
			if ev.ContainerID != tt.wantContainerID {
				t.Errorf("ContainerID = %q, want %q", ev.ContainerID, tt.wantContainerID)
			}
			if ev.ImageDigest != tt.wantDigest {
				t.Errorf("ImageDigest = %q, want %q", ev.ImageDigest, tt.wantDigest)
			}
			if ev.Kind != KindProcessExec {
				t.Errorf("Kind = %q, want %q", ev.Kind, KindProcessExec)
			}
			wantTime, err := time.Parse(time.RFC3339Nano, testTime)
			if err != nil {
				t.Fatalf("parse testTime: %v", err)
			}
			if !ev.Time.Equal(wantTime) {
				t.Errorf("Time = %v, want %v", ev.Time, wantTime)
			}
		})
	}
}

func TestParseLineDropsUnplaceableExecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    tetragonProcess
		when string
		want DropReason
	}{
		{
			name: "relative binary, no cwd, no rootcwd flag",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve"
				p.Cwd = ""
				p.Binary = "app"
				return p
			}(),
			when: testTime,
			want: DropRelativeNoCWD,
		},
		{
			name: "needsCWD flag blocks resolution",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve needsCWD"
				p.Cwd = ""
				p.Binary = "app"
				return p
			}(),
			when: testTime,
			want: DropRelativeNoCWD,
		},
		{
			name: "noCWDSupport flag blocks resolution",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve noCWDSupport"
				p.Cwd = "/home/user"
				p.Binary = "app"
				return p
			}(),
			when: testTime,
			want: DropRelativeNoCWD,
		},
		{
			name: "errorCWD flag blocks resolution",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve errorCWD"
				p.Cwd = "/home/user"
				p.Binary = "app"
				return p
			}(),
			when: testTime,
			want: DropRelativeNoCWD,
		},
		{
			name: "truncFilename flag makes the binary unreliable",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve truncFilename"
				return p
			}(),
			when: testTime,
			want: DropUnreliable,
		},
		{
			name: "errorFilename flag makes the binary unreliable",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve errorFilename"
				return p
			}(),
			when: testTime,
			want: DropUnreliable,
		},
		{
			name: "unknown flag means the process was never resolved",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "unknown"
				return p
			}(),
			when: testTime,
			want: DropUnreliable,
		},
		{
			name: "lexical cleanup of a relative binary would cross a symlinked directory",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve"
				p.Cwd = "/tmp"
				p.Binary = "x/../../usr/bin/ls"
				return p
			}(),
			when: testTime,
			want: DropNotClean,
			// This is the false-negative case docs/decisions/0006 exists to
			// name: path.Clean("/tmp/x/../../usr/bin/ls") is "/usr/bin/ls",
			// which is package-owned. Accepting the cleaned form would
			// attribute a real drift event to coreutils.
		},
		{
			name: "absolute binary containing dot-dot",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "/usr/bin/../../etc/passwd"
				return p
			}(),
			when: testTime,
			want: DropNotClean,
		},
		{
			name: "doubled separator",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "/usr//bin/ls"
				return p
			}(),
			when: testTime,
			want: DropNotClean,
		},
		{
			name: "trailing separator",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "/usr/bin/ls/"
				return p
			}(),
			when: testTime,
			want: DropNotClean,
		},
		{
			name: "NUL byte in binary",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = "/usr/bin/ls\x00etc"
				return p
			}(),
			when: testTime,
			want: DropControlBytes,
		},
		{
			name: "control byte in cwd",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Flags = "execve"
				p.Cwd = "/tmp\x01"
				p.Binary = "app"
				return p
			}(),
			when: testTime,
			want: DropControlBytes,
		},
		{
			name: "empty binary",
			p: func() tetragonProcess {
				p := baseProcess()
				p.Binary = ""
				return p
			}(),
			when: testTime,
			want: DropEmptyBinary,
		},
		{
			name: "missing timestamp",
			p:    baseProcess(),
			when: "",
			want: DropBadTime,
		},
		{
			name: "unparseable timestamp",
			p:    baseProcess(),
			when: "not-a-time",
			want: DropBadTime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ev, outcome, err := parseLine(execLine(t, tt.p, tt.when))
			if err != nil {
				t.Fatalf("parseLine: %v", err)
			}
			if outcome.drop != tt.want {
				t.Fatalf("outcome = %+v (event %+v), want drop reason %q", outcome, ev, tt.want)
			}
			if outcome.skip != "" {
				t.Errorf("outcome also set skip = %q", outcome.skip)
			}
		})
	}
}

func TestParseLineSkipsHostProcesses(t *testing.T) {
	t.Parallel()

	p := baseProcess()
	p.Pod = nil
	p.Docker = ""

	_, outcome, err := parseLine(execLine(t, p, testTime))
	if err != nil {
		t.Fatalf("parseLine: %v", err)
	}
	if outcome.skip != SkipHost {
		t.Errorf("outcome = %+v, want skip reason %q", outcome, SkipHost)
	}
}

func TestParseLineSkipsOtherEventKinds(t *testing.T) {
	t.Parallel()

	// Every member of the GetEventsResponse oneof besides process_exec, per
	// api/v1/tetragon/events.proto.
	kinds := []string{
		"process_exit", "process_kprobe", "process_tracepoint",
		"process_loader", "process_uprobe", "process_throttle",
		"process_lsm", "process_usdt", "test", "rate_limit_info",
	}

	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			_, outcome, err := parseLine(otherKindLine(t, kind))
			if err != nil {
				t.Fatalf("parseLine: %v", err)
			}
			if outcome.skip != SkipOtherKind {
				t.Errorf("outcome = %+v, want skip reason %q", outcome, SkipOtherKind)
			}
		})
	}
}

func TestParseLineRejectsLinesItCannotClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line []byte
	}{
		{"not JSON at all", []byte("{this is not json")},
		{"no recognized oneof member", noKindLine(t)},
		{"process_exec is not an object", []byte(`{"process_exec":"oops","node_name":"n","time":"` + testTime + `"}`)},
		{"process_exec has no process field", []byte(`{"process_exec":{},"node_name":"n","time":"` + testTime + `"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseLine(tt.line); err == nil {
				t.Fatal("parseLine: want an error, got none")
			}
		})
	}
}

func TestFlagSetIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	// Tetragon documents flags as debug-only and does not commit to their
	// casing across releases, so this reader compares them lowercased. Mixed
	// case here stands in for a future release changing it.
	set := flagSet("ExecVE RootCWD")
	if _, ok := set[flagRootCWD]; !ok {
		t.Errorf("flagSet(%q) missing %q", "ExecVE RootCWD", flagRootCWD)
	}
	if !strings.Contains(strings.Join(keys(set), " "), "execve") {
		t.Errorf("flagSet did not lowercase execve: %v", set)
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
