package dpkg

import (
	"context"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"cruthu.dev/core/internal/index"
)

// FuzzBuild drives both parsers over arbitrary bytes.
//
// A package database is attacker-controlled input parsed by hand-written code,
// which is what CLAUDE.md requires a fuzz target for. Both halves are fuzzed
// together rather than separately because the status file chooses which list
// file is read, so the interesting inputs are the pairs that disagree.
//
// The assertions are the contract Build owes the index, checked on every
// accepted input rather than only on the ones a test author thought of. Each one
// is a property whose violation would be a false negative: a path that
// normalizes away to nothing becomes an owned "" key, and an event whose path
// field was truncated then matches it.
func FuzzBuild(f *testing.F) {
	f.Add(
		"Package: dash\nStatus: install ok installed\nVersion: 0.5.12-2\nArchitecture: amd64\n",
		"/.\n/bin/dash\n/bin/sh\n",
	)
	f.Add(
		"Package: libc6\nStatus: install ok installed\nVersion: 2.36\nArchitecture: amd64\nMulti-Arch: same\n",
		"/.\n/usr/lib/libc.so.6\n",
	)
	// Two stanzas, one of them not installed.
	f.Add(
		"Package: a\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n\nPackage: b\nStatus: deinstall ok config-files\nVersion: 2\nArchitecture: all\n",
		"/.\n/usr/bin/a\n",
	)
	// A continuation line that looks like a field.
	f.Add(
		"Package: a\nStatus: install ok installed\nVersion: 1\nArchitecture: all\nDescription: x\n Package: evil\n Status: install ok installed\n",
		"/.\n/usr/bin/a\n",
	)
	// Paths this parser must refuse.
	f.Add(
		"Package: a\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n",
		"/.\n/usr/bin/../../tmp/miner\nusr/bin/rel\n//doubled\n/trailing/\n\n",
	)

	f.Fuzz(func(t *testing.T, status, list string) {
		// Every list filename Build might construct is populated with the same
		// body, so that a fuzzed Package or Architecture still finds a list to
		// read and the path parser is reached. Without this, almost every input
		// would stop at the missing-list error.
		fsys := fstest.MapFS{statusPath: &fstest.MapFile{Data: []byte(status)}}
		for _, name := range candidateListNames(status) {
			// fstest.MapFS panics on a key that is not a valid fs path, so the
			// harness screens what it adds. Build does the same check on what
			// it opens, which is the property under test rather than an
			// assumption made here.
			if p := infoDir + "/" + name; fs.ValidPath(p) {
				fsys[p] = &fstest.MapFile{Data: []byte(list)}
			}
		}

		pkgs, err := Build(context.Background(), fsys)
		if err != nil {
			// A rejected database must yield nothing at all: a caller that
			// ignores the error must not be handed a partial package set it
			// could mistake for a complete one.
			if pkgs != nil {
				t.Fatalf("Build returned %d packages alongside error %v", len(pkgs), err)
			}
			return
		}

		ids := make(map[string]struct{}, len(pkgs))

		for _, p := range pkgs {
			if p.ID == "" {
				t.Fatalf("package with an empty ID: %+v", p)
			}
			if _, dup := ids[p.ID]; dup {
				t.Fatalf("duplicate package ID %q survived Build", p.ID)
			}
			ids[p.ID] = struct{}{}

			if p.Type != "deb" {
				t.Errorf("package %q has type %q, want \"deb\"", p.ID, p.Type)
			}
			if p.Name == "" || p.Version == "" {
				t.Errorf("package %q has an empty name or version", p.ID)
			}
			for _, f := range []struct{ what, value string }{
				{"id", p.ID}, {"name", p.Name}, {"version", p.Version},
			} {
				if hasControlBytes(f.value) {
					t.Errorf("package %q has a control byte in its %s", p.ID, f.what)
				}
			}

			if len(p.Files) > maxFilesPerPackage {
				t.Errorf("package %q declares %d files, over the cap", p.ID, len(p.Files))
			}
			if !sort.StringsAreSorted(p.Files) {
				t.Errorf("package %q declares unsorted files; the index would not be reproducible", p.ID)
			}

			for _, declared := range p.Files {
				assertUsableDeclaredPath(t, p.ID, declared)
			}
		}

		if !sort.SliceIsSorted(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID }) {
			t.Error("packages are not sorted by ID; the index would not be reproducible")
		}

		// The result must be loadable by the thing that consumes it. A Build
		// that produces an index the lookup rejects is a Build that produces
		// nothing usable, and the failure would surface far from here.
		lk, err := index.NewLookup(&index.Index{Packages: pkgs})
		if err != nil {
			t.Fatalf("NewLookup rejected a successfully built package set: %v", err)
		}

		// The two queries that must never resolve. An owned "" is what a
		// truncated event matches, and an owned "/" is what a path that
		// normalizes away to the root matches.
		for _, q := range []string{"", "/"} {
			if owner, ok := lk.Owner(q); ok {
				t.Errorf("Owner(%q) resolved to %q; a path that carries no information must be unowned", q, owner.ID)
			}
		}
	})
}

// assertUsableDeclaredPath checks the properties a declared path must have for
// the index to be able to compare it against an observed one.
func assertUsableDeclaredPath(t *testing.T, id, declared string) {
	t.Helper()

	switch {
	case declared == "":
		t.Errorf("package %q declares an empty path", id)
	case !strings.HasPrefix(declared, "/"):
		t.Errorf("package %q declares a relative path %q; the index cannot place it", id, declared)
	case declared == "/":
		t.Errorf("package %q declares the filesystem root", id)
	case len(declared) > maxPathBytes:
		t.Errorf("package %q declares a path of %d bytes, over the cap", id, len(declared))
	case hasControlBytes(declared):
		t.Errorf("package %q declares a path with a control byte", id)
	case path.Clean(declared) != declared:
		t.Errorf("package %q declares an uncleaned path %q; it and the string a reviewer reads differ", id, declared)
	}
}

// candidateListNames returns the info/ filenames Build could plausibly open for
// the packages named in status, so the fuzzer reaches the path parser.
//
// It deliberately re-derives the names from the raw text rather than calling
// into the parser: a helper that shared the parser's own idea of a package name
// would hide a disagreement between the two, and this is fuzzing.
func candidateListNames(status string) []string {
	var names []string

	for line := range strings.SplitSeq(status, "\n") {
		value, ok := strings.CutPrefix(line, fieldPackage+":")
		if !ok {
			continue
		}
		name := strings.TrimSpace(value)
		if name == "" || strings.ContainsAny(name, "/:") || name == "." || name == ".." {
			continue
		}
		names = append(names, name+".list")

		for line := range strings.SplitSeq(status, "\n") {
			arch, ok := strings.CutPrefix(line, fieldArchitecture+":")
			if !ok {
				continue
			}
			a := strings.TrimSpace(arch)
			if a == "" || strings.ContainsAny(a, "/:") || a == "." || a == ".." {
				continue
			}
			names = append(names, name+":"+a+".list")
		}
	}

	return names
}
