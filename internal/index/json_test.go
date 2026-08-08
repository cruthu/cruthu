package index

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
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

	// Seeds carrying the exact schema version are the only ones that reach
	// validate, NewLookup, and the round trip; everything else stops at the
	// version check. Random mutation does not reinvent that string, so the
	// depth this target reaches is bounded by how many valid seeds it starts
	// from, and each one below opens a lineage into a different behavior.
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/lib","to":"/usr/lib"},{"from":"/usr/lib","to":"/usr/lib64"}],"packages":[{"id":"deb:a@1","files":["/usr/lib64/x.so"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/a","to":"/b"},{"from":"/b","to":"/a"}],"packages":[{"id":"deb:a@1","files":["/a/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[{"id":"deb:a@1","files":["/usr/bin/../../etc/shadow","/usr/bin/./ls","usr/bin/relative"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/bin","to":"/usr/bin"}],"packages":[{"id":"deb:a@1","files":["/binary/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[{"id":"deb:a@1","files":["/usr/bin/x"]},{"id":"deb:a@1","files":["/usr/bin/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/","to":"/usr"},{"from":"","to":""},{"from":"/x","to":"/x"}],"packages":[{"id":"deb:a@1","files":["/usr/bin/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/bin","to":"../../etc"}],"packages":[{"id":"deb:a@1","files":["/bin/sh"]}]}`)
	f.Add("{\"schemaVersion\":\"cruthu.dev/index/v0\",\"packages\":[{\"id\":\"deb:a@1\",\"files\":[\"/usr/bin/\xff\"]}]}")
	// Timestamp spellings that survive the round trip as a different *Location
	// for the same instant. Seeded because the round-trip comparison below has
	// to treat them as equal, and a regression there would look like a data
	// loss finding rather than the formatting artifact it is.
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","source":{"kind":"rootfs","reference":"x","builtAt":"2026-08-08T12:00:00+00:00"},"packages":[]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","source":{"kind":"rootfs","reference":"x","builtAt":"2026-08-08T12:00:00-05:30"},"packages":[]}`)

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

		// A written index must read back unchanged, or WriteJSON and ReadJSON
		// disagree about the schema they share.
		//
		// The comparison is the point, not just the absence of an error. An
		// index that survives the round trip having quietly lost a package or
		// dropped a declared path still parses cleanly, and every path it lost
		// becomes a file no package claims — drift reported as legitimate, or
		// legitimate files reported as drift. A crash here would be visible;
		// this is the failure that would not be.
		var buf bytes.Buffer
		if err := WriteJSON(&buf, idx); err != nil {
			t.Fatalf("WriteJSON on a parsed index: %v", err)
		}
		again, rereadErr := ReadJSON(&buf)
		if rereadErr != nil && !errors.Is(rereadErr, io.EOF) {
			t.Fatalf("round trip failed: %v", rereadErr)
		}
		if rereadErr != nil {
			return
		}

		// BuiltAt is compared as an instant, not structurally. A time.Time
		// carries a *Location, and "+00:00" parses to a fixed zone that
		// marshals back as "Z" and re-parses as time.UTC — the same instant
		// behind a different pointer. Comparing it structurally would fail on
		// that spelling alone, and a fuzz target that cries wolf is worse than
		// one that does not exist, because it teaches people to skip the
		// output. Nothing about drift turns on which spelling of UTC was used.
		if !idx.Source.BuiltAt.Equal(again.Source.BuiltAt) {
			t.Fatalf("round trip moved builtAt: %v then %v", idx.Source.BuiltAt, again.Source.BuiltAt)
		}
		before, after := *idx, *again
		before.Source.BuiltAt, after.Source.BuiltAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("round trip changed the index:\n before: %+v\n after:  %+v", before, after)
		}
	})
}
