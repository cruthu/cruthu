package index

import "testing"

func TestLookupOwner(t *testing.T) {
	t.Parallel()

	idx := &Index{
		SchemaVersion: SchemaVersion,
		Aliases:       []Alias{{From: "/bin", To: "/usr/bin"}},
		Packages: []Package{
			{
				ID:    "deb:coreutils@9.1-1",
				Name:  "coreutils",
				Type:  "deb",
				Files: []string{"/usr/bin/ls"},
			},
			{
				ID:    "deb:dash@0.5.12-2",
				Name:  "dash",
				Type:  "deb",
				Files: []string{"/usr/bin/sh"},
			},
		},
	}
	lookup := NewLookup(idx)

	tests := []struct {
		name      string
		observed  string
		wantOwner string
	}{
		{
			// The finding this whole branch exists to prevent: dpkg declares
			// /usr/bin/sh, the sensor reports /bin/sh, and without the alias
			// every binary on a merged-/usr image reports as unowned.
			name:      "aliased sensor path resolves to the declaring package",
			observed:  "/bin/sh",
			wantOwner: "deb:dash@0.5.12-2",
		},
		{
			name:      "canonical path resolves",
			observed:  "/usr/bin/ls",
			wantOwner: "deb:coreutils@9.1-1",
		},
		{
			name:      "uncleaned path resolves",
			observed:  "/usr/bin/../bin/ls",
			wantOwner: "deb:coreutils@9.1-1",
		},
		{
			// The drift case. If this ever returns an owner, the tool has
			// stopped detecting the thing it exists to detect.
			name:      "dropped binary is owned by nothing",
			observed:  "/tmp/kdevtmpfsi",
			wantOwner: "",
		},
		{
			name:      "a path under an aliased directory that nothing declares",
			observed:  "/bin/nc",
			wantOwner: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkg, ok := lookup.Owner(tt.observed)
			if tt.wantOwner == "" {
				if ok {
					t.Fatalf("Owner(%q) = %q, want no owner", tt.observed, pkg.ID)
				}
				return
			}
			if !ok {
				t.Fatalf("Owner(%q) found no owner, want %q", tt.observed, tt.wantOwner)
			}
			if pkg.ID != tt.wantOwner {
				t.Errorf("Owner(%q) = %q, want %q", tt.observed, pkg.ID, tt.wantOwner)
			}
		})
	}
}

// TestLookupNormalizesDeclaredPathsToo guards the asymmetry that would break
// aliasing: normalizing the observed path but not the declared one.
func TestLookupNormalizesDeclaredPaths(t *testing.T) {
	t.Parallel()

	idx := &Index{
		SchemaVersion: SchemaVersion,
		Aliases:       []Alias{{From: "/bin", To: "/usr/bin"}},
		// A package database that records the aliased spelling rather than the
		// canonical one; both sides must still meet.
		Packages: []Package{{ID: "deb:dash@1", Files: []string{"/bin/sh"}}},
	}

	lookup := NewLookup(idx)
	for _, spelling := range []string{"/bin/sh", "/usr/bin/sh"} {
		if _, ok := lookup.Owner(spelling); !ok {
			t.Errorf("Owner(%q) found no owner", spelling)
		}
	}
}

func TestLookupFirstPackageWinsOnDuplicatePath(t *testing.T) {
	t.Parallel()

	idx := &Index{
		SchemaVersion: SchemaVersion,
		Packages: []Package{
			{ID: "deb:first@1", Files: []string{"/usr/bin/x"}},
			{ID: "deb:second@1", Files: []string{"/usr/bin/x"}},
		},
	}

	pkg, ok := NewLookup(idx).Owner("/usr/bin/x")
	if !ok {
		t.Fatal("Owner found no owner for a duplicated path")
	}
	if pkg.ID != "deb:first@1" {
		t.Errorf("Owner = %q, want the first declaring package", pkg.ID)
	}
}

func TestLookupEmptyIndex(t *testing.T) {
	t.Parallel()

	// An index with no packages must report everything as unowned rather than
	// failing open and reporting everything as fine.
	lookup := NewLookup(&Index{SchemaVersion: SchemaVersion})
	if _, ok := lookup.Owner("/usr/bin/ls"); ok {
		t.Error("Owner found an owner in an empty index")
	}
}

// FuzzLookupOwner exercises path matching directly, without going through the
// index parser.
//
// FuzzReadJSON reaches this code only by way of a JSON document carrying the
// exact schema version, which random mutation never reinvents, so in practice
// almost none of its budget lands here. Path normalization is detection logic:
// a change that makes an observed path stop meeting its declared spelling turns
// a real file into drift, and a change that makes unrelated paths collide turns
// real drift into a legitimate file. Building the Index in Go puts the whole
// budget on that question.
//
// Two aliases are fuzzed rather than one so that chains and cycles are reachable
// at all; maxAliasHops exists for the cyclic case and cannot be exercised by a
// single alias.
func FuzzLookupOwner(f *testing.F) {
	// The merged-/usr case this package exists for.
	f.Add("/bin", "/usr/bin", "", "", "/usr/bin/sh", "/bin/sh")
	// A chain, which normalization must follow to the end.
	f.Add("/lib", "/usr/lib", "/usr/lib", "/usr/lib64", "/usr/lib64/x.so", "/lib/x.so")
	// A cycle, which must terminate rather than spin.
	f.Add("/a", "/b", "/b", "/a", "/a/x", "/b/x")
	// The component-boundary case: an alias for /bin must not rewrite /binary.
	f.Add("/bin", "/usr/bin", "", "", "/binary/x", "/binary/x")
	// Traversal and relative spellings of one path.
	f.Add("/bin", "/usr/bin", "", "", "/usr/bin/../bin/ls", "usr/bin/./ls")
	// Degenerate aliases, all of which NewAliases is expected to drop.
	f.Add("/", "/usr", "", "", "/usr/bin/x", "/usr/bin/x")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, from1, to1, from2, to2, declared, observed string) {
		idx := &Index{
			SchemaVersion: SchemaVersion,
			Aliases:       []Alias{{From: from1, To: to1}, {From: from2, To: to2}},
			Packages:      []Package{{ID: "deb:a@1", Files: []string{declared}}},
		}
		lookup := NewLookup(idx)

		// The same alias set NewLookup builds internally, so the test can ask
		// what a path normalizes to without asserting a particular spelling.
		// The spelling is an implementation detail; that both sides agree on it
		// is the contract.
		aliases := NewAliases(idx.Aliases)

		// A declared path must always be found by its own spelling. This is the
		// floor: if it fails, the index cannot recognize the files it just
		// recorded, and everything in the image reports as drift.
		//
		// The empty path is excluded because it is not a path, and this
		// exclusion is a deliberate contract change rather than a test bent to
		// fit the code. Declaring "" used to make owners[""] a live key, so an
		// event whose path field had been truncated away matched it and
		// reported clean — "the sensor told us nothing" reading as "the sensor
		// told us it was fine". That is a false negative, and the assertion
		// below now pins the opposite.
		if aliases.Normalize(declared) != "" {
			if _, ok := lookup.Owner(declared); !ok {
				t.Fatalf("Owner(%q) found no owner for a path the index declares", declared)
			}
		}

		// An unnormalizable path is owned by nothing, whatever the index
		// declares and whatever the alias set does.
		if pkg, ok := lookup.Owner(""); ok {
			t.Fatalf(`Owner("") returned owner %q`, pkg.ID)
		}

		// Any observed path that normalizes to the declared path must resolve
		// to it. Normalizing only one side is the bug this design exists to
		// prevent, and it fails in the direction that hides nothing — it makes
		// legitimate files look like drift.
		// Empty excluded for the same reason as above: two paths that both
		// normalize to nothing have not met, they have both disappeared.
		if n := aliases.Normalize(observed); n != "" && n == aliases.Normalize(declared) {
			if _, ok := lookup.Owner(observed); !ok {
				t.Fatalf("Owner(%q) found no owner, but it normalizes to declared %q", observed, declared)
			}
		}

		// The dangerous direction. A path that normalizes to something the
		// index does not declare must not acquire an owner: over-matching
		// reports a planted binary as a legitimate file, which is a false
		// negative and worse for the product than a crash.
		const planted = "/tmp/kdevtmpfsi"
		if aliases.Normalize(planted) != aliases.Normalize(declared) {
			if pkg, ok := lookup.Owner(planted); ok {
				t.Fatalf("Owner(%q) returned owner %q for an undeclared path", planted, pkg.ID)
			}
		}
	})
}
