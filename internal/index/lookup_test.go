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
