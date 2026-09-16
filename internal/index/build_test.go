package index

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedSource is a Source with every field already set, the shape Build
// expects its caller to supply. BuiltAt is fixed rather than time.Now so tests
// can assert on byte-identical output.
func fixedSource() Source {
	return Source{
		Kind:      "rootfs",
		Reference: "/fixtures/bookworm",
		Digest:    "sha256:" + strings.Repeat("a", 64),
		BuiltAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// TestBuildRoundTrips pins the writer/reader symmetry the whole design rests
// on: an index Build produces must be exactly the index its own loader
// accepts back, with the alias table normalizing an owned path and refusing
// an unowned one on both sides of the write.
func TestBuildRoundTrips(t *testing.T) {
	t.Parallel()

	root := mergedUsrRootfs(t)
	fsys, closeFn, err := OpenRootfs(root)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	pkgs := []Package{
		{ID: "deb:sh@1.0", Name: "sh", Version: "1.0", Type: "deb", Files: []string{"/usr/bin/sh"}},
	}

	idx, err := Build(t.Context(), fsys, fixedSource(), pkgs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	var buf bytes.Buffer
	if writeErr := WriteJSON(&buf, idx); writeErr != nil {
		t.Fatalf("WriteJSON: %v", writeErr)
	}

	data, err := ReadBounded(&buf)
	if err != nil {
		t.Fatalf("ReadBounded: %v", err)
	}

	loaded, err := LoadVerified(data)
	if err != nil {
		t.Fatalf("LoadVerified: %v", err)
	}

	lk, err := NewLookup(loaded)
	if err != nil {
		t.Fatalf("NewLookup: %v", err)
	}

	if _, ok := lk.Owner("/usr/bin/sh"); !ok {
		t.Errorf("Owner(/usr/bin/sh) = not owned, want owned")
	}
	if _, ok := lk.Owner("/bin/sh"); !ok {
		t.Errorf("Owner(/bin/sh) = not owned, want owned via the /bin -> /usr/bin alias")
	}
	if _, ok := lk.Owner("/tmp/sh"); ok {
		t.Errorf("Owner(/tmp/sh) = owned, want not owned")
	}
}

// TestBuildIsDeterministic confirms that a fixed Source produces byte-identical
// output across two runs, even though BuiltAt is not recomputed. dpkg.Build
// already sorts packages and files; this pins that Build does not undo it by,
// say, reordering aliases non-deterministically.
func TestBuildIsDeterministic(t *testing.T) {
	t.Parallel()

	root := mergedUsrRootfs(t)
	fsys, closeFn, err := OpenRootfs(root)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	pkgs := []Package{
		{ID: "deb:sh@1.0", Name: "sh", Version: "1.0", Type: "deb", Files: []string{"/usr/bin/sh"}},
	}

	var outs [][]byte
	for i := 0; i < 2; i++ {
		idx, err := Build(t.Context(), fsys, fixedSource(), pkgs)
		if err != nil {
			t.Fatalf("Build run %d: %v", i, err)
		}
		var buf bytes.Buffer
		if writeErr := WriteJSON(&buf, idx); writeErr != nil {
			t.Fatalf("WriteJSON run %d: %v", i, writeErr)
		}
		outs = append(outs, buf.Bytes())
	}

	if !bytes.Equal(outs[0], outs[1]) {
		t.Errorf("Build output differs across runs with a fixed Source:\nrun 0: %s\nrun 1: %s", outs[0], outs[1])
	}
}

// TestBuildWithNoSymlinksYieldsEmptyAliasTable confirms a plain rootfs (no
// merged-/usr symlinks) builds successfully with an empty alias table rather
// than erroring, since most files.Files don't need any rewriting to be found.
func TestBuildWithNoSymlinksYieldsEmptyAliasTable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/sh"), []byte("elf"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	fsys, closeFn, err := OpenRootfs(root)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	pkgs := []Package{
		{ID: "deb:sh@1.0", Name: "sh", Version: "1.0", Type: "deb", Files: []string{"/bin/sh"}},
	}

	idx, err := Build(t.Context(), fsys, fixedSource(), pkgs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(idx.Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty", idx.Aliases)
	}
}

// TestBuildRejectsWhatItsOwnLoaderWouldReject is the load-bearing assertion
// behind Build's design: a caller cannot smuggle package data past Build that
// validate would refuse on the way back in, because Build runs validate
// itself before returning.
func TestBuildRejectsWhatItsOwnLoaderWouldReject(t *testing.T) {
	t.Parallel()

	root := mergedUsrRootfs(t)
	fsys, closeFn, err := OpenRootfs(root)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	tests := []struct {
		name string
		pkgs []Package
	}{
		{
			name: "empty package id",
			pkgs: []Package{{ID: "", Name: "sh", Version: "1.0", Type: "deb", Files: []string{"/usr/bin/sh"}}},
		},
		{
			name: "relative declared path",
			pkgs: []Package{{ID: "deb:sh@1.0", Name: "sh", Version: "1.0", Type: "deb", Files: []string{"usr/bin/sh"}}},
		},
		{
			name: "empty declared path",
			pkgs: []Package{{ID: "deb:sh@1.0", Name: "sh", Version: "1.0", Type: "deb", Files: []string{""}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Build(t.Context(), fsys, fixedSource(), tt.pkgs); err == nil {
				t.Fatalf("Build succeeded on input its own validate rejects")
			}
		})
	}
}
