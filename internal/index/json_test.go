package index

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func sampleIndex() *Index {
	return &Index{
		SchemaVersion: SchemaVersion,
		Source: Source{
			Kind:      "rootfs",
			Reference: "./testdata/rootfs",
			BuiltAt:   time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
		},
		Aliases: []Alias{{From: "/bin", To: "/usr/bin"}},
		Packages: []Package{
			{
				ID:      "deb:coreutils@9.1-1",
				Name:    "coreutils",
				Version: "9.1-1",
				Type:    "deb",
				Files:   []string{"/usr/bin/ls", "/usr/bin/cat"},
			},
		},
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleIndex()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	got, err := ReadJSON(&buf)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}

	want := sampleIndex()
	if got.SchemaVersion != want.SchemaVersion {
		t.Errorf("schema version = %q, want %q", got.SchemaVersion, want.SchemaVersion)
	}
	if len(got.Packages) != 1 || got.Packages[0].ID != want.Packages[0].ID {
		t.Fatalf("packages = %+v, want %+v", got.Packages, want.Packages)
	}
	if len(got.Aliases) != 1 || got.Aliases[0].To != "/usr/bin" {
		t.Errorf("aliases = %+v, want the /bin -> /usr/bin entry", got.Aliases)
	}
	if !got.Source.BuiltAt.Equal(want.Source.BuiltAt) {
		t.Errorf("builtAt = %v, want %v", got.Source.BuiltAt, want.Source.BuiltAt)
	}
}

func TestWriteJSONStampsSchemaVersion(t *testing.T) {
	t.Parallel()

	idx := sampleIndex()
	idx.SchemaVersion = "cruthu.dev/index/v99"

	var buf bytes.Buffer
	if err := WriteJSON(&buf, idx); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), SchemaVersion) {
		t.Errorf("output does not carry %q: %s", SchemaVersion, buf.String())
	}
}

func TestWriteJSONNil(t *testing.T) {
	t.Parallel()

	if err := WriteJSON(io.Discard, nil); err == nil {
		t.Fatal("WriteJSON(nil) returned no error")
	}
}

func TestReadJSONRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "truncated object",
			input: `{"schemaVersion":"cruthu.dev/index/v0","packages":[`,
		},
		{
			name:  "not json at all",
			input: "\x00\x00\x00\x00",
		},
		{
			// The version gate is the whole point of stamping one. A future
			// v1 index must not be silently read as if it were v0.
			name:  "unknown schema version",
			input: `{"schemaVersion":"cruthu.dev/index/v1","packages":[]}`,
		},
		{
			name:  "missing schema version",
			input: `{"packages":[]}`,
		},
		{
			name:  "package with no id",
			input: `{"schemaVersion":"cruthu.dev/index/v0","packages":[{"name":"x","files":["/usr/bin/x"]}]}`,
		},
		{
			name:  "wrong type for packages",
			input: `{"schemaVersion":"cruthu.dev/index/v0","packages":"lots"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ReadJSON(strings.NewReader(tt.input)); err == nil {
				t.Fatalf("ReadJSON(%q) returned no error", tt.input)
			}
		})
	}
}

func TestReadJSONRejectsOversizeInput(t *testing.T) {
	t.Parallel()

	// A reader that never ends. Without the byte cap, ReadJSON would consume
	// memory until the process died — a denial of service driven purely by the
	// size of an input file.
	endless := io.MultiReader(
		strings.NewReader(`{"schemaVersion":"cruthu.dev/index/v0","packages":[`),
		infiniteReader{},
	)

	_, err := ReadJSON(endless)
	if err == nil {
		t.Fatal("ReadJSON on an endless reader returned no error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want the size cap to be the reason", err)
	}
}

func TestReadJSONRejectsTooManyFiles(t *testing.T) {
	t.Parallel()

	// Built as a stream rather than a literal so the test does not itself
	// allocate the thing it is checking is refused.
	var buf bytes.Buffer
	buf.WriteString(`{"schemaVersion":"cruthu.dev/index/v0","packages":[`)
	const packages = 6
	perPackage := maxIndexFiles/packages + 1
	for p := range packages {
		if p > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"id":"deb:p%d@1","files":[`, p)
		for f := range perPackage {
			if f > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`"/usr/bin/x"`)
		}
		buf.WriteString(`]}`)
	}
	buf.WriteString(`]}`)

	_, err := ReadJSON(&buf)
	if err == nil {
		t.Fatal("ReadJSON accepted an index over the file cap")
	}
	if !strings.Contains(err.Error(), "declared files") {
		t.Errorf("error = %v, want the file cap to be the reason", err)
	}
}

type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// FuzzReadJSON exercises the index parser against arbitrary bytes. An index
// file is untrusted input: it arrives as a CI artifact or a cached blob and
// nothing verifies it before it is parsed. The contract is narrow and absolute
// — return an index or return an error, never panic.
func FuzzReadJSON(f *testing.F) {
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/bin","to":"/usr/bin"}],"packages":[{"id":"deb:a@1","files":["/usr/bin/a"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[{"id":"","files":null}]}`)
	f.Add(`{"schemaVersion":"","packages":null}`)
	f.Add("")
	f.Add("{")
	f.Add("\x00")

	f.Fuzz(func(t *testing.T, in string) {
		idx, err := ReadJSON(strings.NewReader(in))
		if err != nil {
			if idx != nil {
				t.Fatalf("ReadJSON returned both an index and an error %v", err)
			}
			return
		}

		if idx.SchemaVersion != SchemaVersion {
			t.Fatalf("accepted schema version %q", idx.SchemaVersion)
		}

		// Anything that parses must survive being queried, including through
		// whatever alias set the input described.
		// The contract here is only that a query cannot panic, whatever alias
		// set and paths the input described. A declared path may normalize onto
		// another package's entry, so a miss is legal; a crash is not.
		lookup := NewLookup(idx)
		for _, p := range idx.Packages {
			for _, file := range p.Files {
				lookup.Owner(file)
			}
		}
		lookup.Owner("/tmp/kdevtmpfsi")

		// A written index must read back, or WriteJSON and ReadJSON disagree
		// about the schema they share.
		var buf bytes.Buffer
		if err := WriteJSON(&buf, idx); err != nil {
			t.Fatalf("WriteJSON on a parsed index: %v", err)
		}
		if _, err := ReadJSON(&buf); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}
