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

// doc wraps body in a minimal valid index document, so that a test case shows
// only the part it is about.
func doc(body string) string {
	return `{"schemaVersion":"cruthu.dev/index/v0",` + body + `}`
}

func TestWriteReadRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleIndex()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	got, err := LoadVerified(buf.Bytes())
	if err != nil {
		t.Fatalf("LoadVerified: %v", err)
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

// TestLoadVerifiedRejectsInjectedAliases is the reason validateAliases exists,
// so it is separated from the general rejection table rather than buried in it.
//
// Every case here is a syntactically perfect index that no well-formedness check
// would object to. Each one makes a file that no package declares resolve onto a
// path that some package does declare, which is a drift finding turned into a
// clean report by editing a file that nothing verifies.
func TestLoadVerifiedRejectsInjectedAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		aliases string
		attack  string
	}{
		{
			name:    "alias onto an owned directory hides a dropped binary",
			aliases: `{"from":"/tmp","to":"/usr/bin"}`,
			attack:  "an exec of /tmp/ls normalizes onto the package-owned /usr/bin/ls",
		},
		{
			name:    "alias off an owned directory relocates the owned set",
			aliases: `{"from":"/bin","to":"/tmp"}`,
			attack:  "every declared path under /bin moves to /tmp, so anything dropped there is owned",
		},
		{
			name:    "alias onto the root owns everything",
			aliases: `{"from":"/tmp","to":"/"}`,
			attack:  "/tmp/miner normalizes to /miner and can collide with any declared path",
		},
		{
			name:    "deep alias is not a merged-/usr rewrite",
			aliases: `{"from":"/usr/share/doc/x","to":"/usr/bin"}`,
			attack:  "the same substitution one level down, which the shape rule must also refuse",
		},
		{
			name:    "aliasing /usr rewrites every declared path",
			aliases: `{"from":"/usr","to":"/usr/usr"}`,
			attack:  "satisfies the twin rule textually while making the whole table meaningless",
		},
		{
			name:    "relative from is not a top-level directory",
			aliases: `{"from":"bin","to":"/usr/bin"}`,
			attack:  "an unrooted key that cleanAbs would have silently anchored",
		},
		{
			name:    "traversal in from",
			aliases: `{"from":"/..","to":"/usr/.."}`,
			attack:  "a pair that survives a naive prefix comparison and means nothing after cleaning",
		},
		{
			name:    "duplicate from makes file order significant",
			aliases: `{"from":"/bin","to":"/usr/bin"},{"from":"/bin","to":"/usr/bin"}`,
			attack:  "two entries for one key let line order decide which rewrite applies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := doc(`"aliases":[` + tt.aliases + `],"packages":[{"id":"deb:coreutils@9.1-1","files":["/usr/bin/ls"]}]`)
			if _, err := LoadVerified([]byte(in)); err == nil {
				t.Fatalf("accepted %s\nattack: %s", tt.aliases, tt.attack)
			}
		})
	}
}

func TestLoadVerifiedAcceptsMergedUsrAliases(t *testing.T) {
	t.Parallel()

	// The four entries measured on debian:bookworm and python:3.12-bookworm.
	// If this fails, the rule is too narrow to index a real image and the tool
	// reports every binary on it as drift.
	in := doc(`"aliases":[
		{"from":"/bin","to":"/usr/bin"},
		{"from":"/sbin","to":"/usr/sbin"},
		{"from":"/lib","to":"/usr/lib"},
		{"from":"/lib64","to":"/usr/lib64"}
	],"packages":[{"id":"deb:dash@0.5.12","files":["/usr/bin/sh"]}]`)

	idx, err := LoadVerified([]byte(in))
	if err != nil {
		t.Fatalf("LoadVerified: %v", err)
	}
	if len(idx.Aliases) != 4 {
		t.Fatalf("aliases = %+v, want all four", idx.Aliases)
	}

	// The point of keeping them: the sensor's spelling still resolves.
	if _, ok := NewLookup(idx).Owner("/bin/sh"); !ok {
		t.Error("/bin/sh is unowned; the alias table no longer does its job")
	}
}

func TestLoadVerifiedRejects(t *testing.T) {
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
			input: doc(`"packages":[{"name":"x","files":["/usr/bin/x"]}]`),
		},
		{
			name:  "wrong type for packages",
			input: doc(`"packages":"lots"`),
		},
		{
			// encoding/json takes the last duplicate and discards the rest, so
			// a reviewer reading top to bottom sees the empty table and the
			// tool uses the injected one.
			name:  "duplicate key",
			input: `{"schemaVersion":"cruthu.dev/index/v0","aliases":[],"aliases":[{"from":"/tmp","to":"/usr/bin"}],"packages":[]}`,
		},
		{
			// Field matching is case-insensitive, so this populates
			// SchemaVersion in Go and reads as an unset field to anything else.
			name:  "case-variant field name",
			input: `{"SCHEMAVERSION":"cruthu.dev/index/v0","packages":[]}`,
		},
		{
			name:  "unknown field",
			input: doc(`"packages":[],"suppress":["/tmp"]`),
		},
		{
			name:  "known field in the wrong position",
			input: doc(`"packages":[{"id":"deb:a@1","aliases":[]}]`),
		},
		{
			name:  "trailing second document",
			input: doc(`"packages":[]`) + doc(`"packages":[]`),
		},
		{
			name:  "control byte in package name forges a report line",
			input: doc(`"packages":[{"id":"deb:a@1","name":"coreutils\n[INFO] no drift detected","files":[]}]`),
		},
		{
			name:  "control byte in package id",
			input: doc(`"packages":[{"id":"deb:a@1\r","files":[]}]`),
		},
		{
			name:  "control byte in package version",
			input: doc(`"packages":[{"id":"deb:a@1","version":"1.0\u0000","files":[]}]`),
		},
		{
			name:  "control byte in a declared path",
			input: doc(`"packages":[{"id":"deb:a@1","files":["/usr/bin/\u0000ls"]}]`),
		},
		{
			// An owned "" is matched by any observed path that normalizes away
			// to nothing, which is what a truncated event field looks like.
			name:  "empty declared path",
			input: doc(`"packages":[{"id":"deb:a@1","files":[""]}]`),
		},
		{
			name:  "digest with no algorithm prefix",
			input: doc(`"source":{"digest":"` + strings.Repeat("a", 64) + `"},"packages":[]`),
		},
		{
			name:  "digest of the wrong length",
			input: doc(`"source":{"digest":"sha256:abc"},"packages":[]`),
		},
		{
			name:  "digest in uppercase hex",
			input: doc(`"source":{"digest":"sha256:` + strings.Repeat("A", 64) + `"},"packages":[]`),
		},
		{
			name:  "digest with a non-hex character",
			input: doc(`"source":{"digest":"sha256:` + strings.Repeat("g", 64) + `"},"packages":[]`),
		},
		{
			name:  "nested past the depth cap",
			input: strings.Repeat(`{"packages":`, maxJSONDepth+2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := LoadVerified([]byte(tt.input)); err == nil {
				t.Fatalf("LoadVerified(%q) returned no error", tt.input)
			}
		})
	}
}

func TestLoadVerifiedAcceptsWellFormedOptionalFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "absent digest",
			input: doc(`"source":{"kind":"rootfs","reference":"x"},"packages":[]`),
		},
		{
			name:  "lowercase sha256 digest",
			input: doc(`"source":{"digest":"sha256:` + strings.Repeat("0f", 32) + `"},"packages":[]`),
		},
		{
			name:  "no aliases at all",
			input: doc(`"packages":[{"id":"deb:a@1","files":["/usr/bin/a"]}]`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := LoadVerified([]byte(tt.input)); err != nil {
				t.Fatalf("LoadVerified(%q): %v", tt.input, err)
			}
		})
	}
}

func TestLoadVerifiedRejectsOversizeInput(t *testing.T) {
	t.Parallel()

	if _, err := LoadVerified(make([]byte, maxIndexBytes+1)); err == nil {
		t.Fatal("LoadVerified accepted input over the byte cap")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want the size cap to be the reason", err)
	}
}

func TestReadBoundedStopsAtTheCap(t *testing.T) {
	t.Parallel()

	// A reader that never ends. Without the byte cap, reading an index would
	// consume memory until the process died — a denial of service driven purely
	// by the size of an input file.
	endless := io.MultiReader(
		strings.NewReader(`{"schemaVersion":"cruthu.dev/index/v0","packages":[`),
		infiniteReader{},
	)

	_, err := ReadBounded(endless)
	if err == nil {
		t.Fatal("ReadBounded on an endless reader returned no error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want the size cap to be the reason", err)
	}
}

func TestReadBoundedReturnsShortInput(t *testing.T) {
	t.Parallel()

	const in = `{"schemaVersion":"cruthu.dev/index/v0","packages":[]}`

	data, err := ReadBounded(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ReadBounded: %v", err)
	}
	if string(data) != in {
		t.Errorf("ReadBounded returned %q, want %q", data, in)
	}
}

func TestLoadVerifiedRejectsTooManyFiles(t *testing.T) {
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

	_, err := LoadVerified(buf.Bytes())
	if err == nil {
		t.Fatal("LoadVerified accepted an index over the file cap")
	}
	if !strings.Contains(err.Error(), "declared files") {
		t.Errorf("error = %v, want the file cap to be the reason", err)
	}
}

func TestLoadVerifiedRejectsTooManyAliases(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	buf.WriteString(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[`)
	for i := range maxAliases + 1 {
		if i > 0 {
			buf.WriteByte(',')
		}
		// Shape-valid entries, so the cap is what refuses them rather than the
		// merged-/usr rule reaching them first.
		fmt.Fprintf(&buf, `{"from":"/d%d","to":"/usr/d%d"}`, i, i)
	}
	buf.WriteString(`],"packages":[]}`)

	_, err := LoadVerified(buf.Bytes())
	if err == nil {
		t.Fatal("LoadVerified accepted an index over the alias cap")
	}
	if !errors.Is(err, errTooManyAliases) {
		t.Errorf("error = %v, want errTooManyAliases", err)
	}
}

type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// FuzzLoadVerified exercises the index parser against arbitrary bytes. An index
// file is untrusted input: it arrives as a CI artifact or a cached blob and
// nothing verifies it before it is parsed. The contract is narrow and absolute
// — return an index or return an error, never panic.
func FuzzLoadVerified(f *testing.F) {
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
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/lib","to":"/usr/lib"},{"from":"/lib64","to":"/usr/lib64"}],"packages":[{"id":"deb:a@1","files":["/usr/lib64/x.so"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[{"id":"deb:a@1","files":["/usr/bin/../../etc/shadow","/usr/bin/./ls","usr/bin/relative"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/bin","to":"/usr/bin"}],"packages":[{"id":"deb:a@1","files":["/binary/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","packages":[{"id":"deb:a@1","files":["/usr/bin/x"]},{"id":"deb:a@1","files":["/usr/bin/x"]}]}`)
	f.Add("{\"schemaVersion\":\"cruthu.dev/index/v0\",\"packages\":[{\"id\":\"deb:a@1\",\"files\":[\"/usr/bin/\xff\"]}]}")

	// Alias tables that must be refused. Mutation from a rejected seed reaches
	// validateAliases far more often than mutation from a valid one, and this
	// is the check whose failure is a silent false negative rather than a
	// crash.
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/tmp","to":"/usr/bin"}],"packages":[{"id":"deb:a@1","files":["/usr/bin/ls"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/","to":"/usr"},{"from":"","to":""},{"from":"/x","to":"/x"}],"packages":[{"id":"deb:a@1","files":["/usr/bin/x"]}]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","aliases":[{"from":"/bin","to":"../../etc"}],"packages":[{"id":"deb:a@1","files":["/bin/sh"]}]}`)

	// Timestamp spellings that survive the round trip as a different *Location
	// for the same instant. Seeded because the round-trip comparison below has
	// to treat them as equal, and a regression there would look like a data
	// loss finding rather than the formatting artifact it is.
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","source":{"kind":"rootfs","reference":"x","builtAt":"2026-08-08T12:00:00+00:00"},"packages":[]}`)
	f.Add(`{"schemaVersion":"cruthu.dev/index/v0","source":{"kind":"rootfs","reference":"x","builtAt":"2026-08-08T12:00:00-05:30"},"packages":[]}`)

	f.Fuzz(func(t *testing.T, in string) {
		idx, err := LoadVerified([]byte(in))
		if err != nil {
			if idx != nil {
				t.Fatalf("LoadVerified returned both an index and an error %v", err)
			}
			return
		}

		if idx.SchemaVersion != SchemaVersion {
			t.Fatalf("accepted schema version %q", idx.SchemaVersion)
		}

		// No accepted alias may be anything but a top-level directory and its
		// own /usr twin. This is the false-negative invariant: an alias outside
		// that shape is a path rewrite an attacker chose, and the fuzzer is
		// looking for a spelling that slips one past validateAliases.
		for _, a := range idx.Aliases {
			if !singleRootComponent(a.From) || a.To != "/usr"+a.From || a.From == "/usr" {
				t.Fatalf("accepted alias %q -> %q", a.From, a.To)
			}
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
		lookup.Owner("")

		// A written index must read back unchanged, or WriteJSON and
		// LoadVerified disagree about the schema they share.
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
		again, rereadErr := LoadVerified(buf.Bytes())
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
