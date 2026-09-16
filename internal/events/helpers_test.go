package events

import (
	"encoding/json"
	"strings"
	"testing"
)

// validDigestHex is a syntactically valid sha256 hex digest for fixtures that
// need one. Its value carries no meaning; only its shape does.
const validDigestHex = "sha256:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"

// testTime is an RFC 3339 timestamp usable anywhere a fixture needs one.
const testTime = "2026-01-01T00:00:01Z"

// baseProcess returns a well-formed process from which every parseLine test
// case derives its own case by overriding exactly the fields it is testing.
func baseProcess() tetragonProcess {
	return tetragonProcess{
		Cwd:    "/",
		Binary: "/usr/bin/ls",
		Flags:  "execve rootcwd",
		Pod: &tetragonPod{
			Container: &tetragonContainer{
				ID: "containerd://abc123",
				Image: &tetragonImage{
					ID: "registry.example/app@" + validDigestHex,
				},
			},
		},
	}
}

// execLine marshals p into a complete process_exec export line, using the
// same types the reader decodes with so a fixture can never drift from the
// shape the reader actually parses.
func execLine(t *testing.T, p tetragonProcess, when string) []byte {
	t.Helper()
	return mustExecLine(p, when)
}

// mustExecLine is execLine without a *testing.T, for building fuzz seed
// corpus entries at FuzzTetragonExport registration time, when only a
// *testing.F is in scope. Marshaling a struct this package built cannot fail;
// panicking rather than swallowing the impossible error keeps that fact
// visible if it is ever wrong.
func mustExecLine(p tetragonProcess, when string) []byte {
	envelope := struct {
		ProcessExec tetragonProcessExec `json:"process_exec"`
		NodeName    string              `json:"node_name"`
		Time        string              `json:"time"`
	}{
		ProcessExec: tetragonProcessExec{Process: &p},
		NodeName:    "test-node",
		Time:        when,
	}

	b, err := json.Marshal(envelope)
	if err != nil {
		panic("events: marshal fixture: " + err.Error())
	}
	return b
}

// otherKindLine builds a line whose oneof member is key, with an empty body.
// The body's content never matters: this reader skips every non-exec kind
// without decoding it.
func otherKindLine(t *testing.T, key string) []byte {
	t.Helper()
	return mustOtherKindLine(key)
}

// mustOtherKindLine is otherKindLine without a *testing.T; see mustExecLine.
func mustOtherKindLine(key string) []byte {
	b, err := json.Marshal(map[string]any{
		key:         map[string]any{},
		"node_name": "test-node",
		"time":      testTime,
	})
	if err != nil {
		panic("events: marshal fixture: " + err.Error())
	}
	return b
}

// noKindLine builds a line naming no recognized oneof member at all — a
// malformed line this reader must refuse rather than silently ignore.
func noKindLine(t *testing.T) []byte {
	t.Helper()

	b, err := json.Marshal(map[string]any{
		"cluster_name": "test-cluster",
		"node_name":    "test-node",
		"time":         testTime,
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// join builds a multi-line export body from individual lines, exactly as a
// recorded export file would be laid out: one JSON object per line.
func join(lines ...[]byte) []byte {
	return []byte(strings.Join(toStrings(lines), "\n") + "\n")
}

func toStrings(lines [][]byte) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = string(l)
	}
	return out
}
