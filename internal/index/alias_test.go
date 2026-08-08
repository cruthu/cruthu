package index

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// mergedUsrRootfs builds the filesystem shape this whole mechanism exists for:
// a merged-/usr image where /bin, /sbin, and /lib are symlinks into /usr.
func mergedUsrRootfs(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for _, dir := range []string{"usr/bin", "usr/sbin", "usr/lib", "etc", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/sh"), []byte("elf"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}

	links := map[string]string{
		"bin":  "usr/bin",   // relative target, the Debian shape
		"sbin": "/usr/sbin", // absolute target, also seen in the wild
		"lib":  "usr/lib",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	return root
}

func aliasFor(aliases []Alias, from string) (Alias, bool) {
	for _, a := range aliases {
		if a.From == from {
			return a, true
		}
	}
	return Alias{}, false
}

func TestBuildAliasesFindsDirectorySymlinks(t *testing.T) {
	t.Parallel()

	fsys, closeFn, err := OpenRootfs(mergedUsrRootfs(t))
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	aliases, err := BuildAliases(fsys)
	if err != nil {
		t.Fatalf("BuildAliases: %v", err)
	}

	// An absolute target and a relative target must produce the same alias.
	// Getting this wrong on one of the two forms is how half an image ends up
	// unnormalized.
	want := map[string]string{
		"/bin":  "/usr/bin",
		"/sbin": "/usr/sbin",
		"/lib":  "/usr/lib",
	}
	for from, to := range want {
		got, ok := aliasFor(aliases, from)
		if !ok {
			t.Errorf("no alias recorded for %s", from)
			continue
		}
		if got.To != to {
			t.Errorf("alias %s -> %s, want %s", from, got.To, to)
		}
	}
	if len(aliases) != len(want) {
		names := make([]string, 0, len(aliases))
		for _, a := range aliases {
			names = append(names, a.From)
		}
		sort.Strings(names)
		t.Errorf("recorded %d aliases %v, want %d", len(aliases), names, len(want))
	}
}

func TestBuildAliasesRejectsNonDirectoryAndEscapingLinks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/sh"), []byte("elf"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	outside := t.TempDir()

	links := map[string]string{
		"tofile":    "usr/bin/sh", // a file, not a directory
		"dangling":  "usr/bin/nonexistent",
		"escaping":  "../../../etc",
		"absescape": outside,
		"selfloop":  "selfloop",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
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

	aliases, err := BuildAliases(fsys)
	if err != nil {
		t.Fatalf("BuildAliases: %v", err)
	}

	// An alias to anything but a real directory inside the root would rewrite
	// observed paths toward somewhere the index does not describe.
	if len(aliases) != 0 {
		t.Errorf("recorded %v, want no aliases", aliases)
	}
}

// plainFS exposes only fs.FS. Embedding the interface promotes just its
// methods, so the result cannot read symlinks however capable the value inside
// it is.
type plainFS struct{ fs.FS }

func TestBuildAliasesRequiresReadLinkFS(t *testing.T) {
	t.Parallel()

	// Alias discovery is not optional: a filesystem it cannot inspect would
	// yield an empty alias set, which looks identical to an image that has no
	// directory symlinks. Erroring keeps those two cases distinguishable.
	if _, err := BuildAliases(plainFS{os.DirFS(t.TempDir())}); err == nil {
		t.Fatal("BuildAliases accepted a filesystem that cannot read symlinks")
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	aliases := NewAliases([]Alias{
		{From: "/bin", To: "/usr/bin"},
		{From: "/lib", To: "/usr/lib"},
		{From: "/usr/lib", To: "/usr/lib64"}, // chains with the previous entry
	})

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "sensor spelling rewrites to the dpkg spelling",
			in:   "/bin/sh",
			want: "/usr/bin/sh",
		},
		{
			name: "dpkg spelling is already canonical",
			in:   "/usr/bin/sh",
			want: "/usr/bin/sh",
		},
		{
			name: "the aliased directory itself rewrites",
			in:   "/bin",
			want: "/usr/bin",
		},
		{
			// The whole reason matching is component-aware: a raw string
			// prefix would turn /binary into /usr/binary and mis-attribute it.
			name: "a path merely starting with the alias name is untouched",
			in:   "/binary/thing",
			want: "/binary/thing",
		},
		{
			name: "chained aliases resolve transitively",
			in:   "/lib/libc.so.6",
			want: "/usr/lib64/libc.so.6",
		},
		{
			name: "unrelated paths are only cleaned",
			in:   "/tmp//kdevtmpfsi",
			want: "/tmp/kdevtmpfsi",
		},
		{
			name: "traversal inside a path is cleaned before matching",
			in:   "/usr/share/../bin/sh",
			want: "/usr/bin/sh",
		},
		{
			name: "a relative path is anchored at the root",
			in:   "bin/sh",
			want: "/usr/bin/sh",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := aliases.Normalize(tt.in); got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeLongestAliasWins(t *testing.T) {
	t.Parallel()

	// Declared in the order that would give the wrong answer if the alias set
	// were applied in input order rather than most-specific first.
	aliases := NewAliases([]Alias{
		{From: "/usr", To: "/opt"},
		{From: "/usr/bin", To: "/opt/sbin"},
	})

	if got := aliases.Normalize("/usr/bin/sh"); got != "/opt/sbin/sh" {
		t.Errorf("Normalize = %q, want %q", got, "/opt/sbin/sh")
	}
}

func TestNormalizeTerminatesOnCycle(t *testing.T) {
	t.Parallel()

	// A hostile or broken image can describe a cycle. Normalization must
	// terminate; the exact fixed point is unimportant because both the declared
	// and the observed side pass through the same function.
	aliases := NewAliases([]Alias{
		{From: "/a", To: "/b"},
		{From: "/b", To: "/a"},
	})

	// If the hop bound is ever removed this call does not return and the test
	// binary's own timeout reports it, which is the failure we want to see.
	got := aliases.Normalize("/a/thing")
	if got != "/a/thing" && got != "/b/thing" {
		t.Errorf("Normalize = %q, want one of the two cycle members", got)
	}
}

func TestNewAliasesDropsUnusableEntries(t *testing.T) {
	t.Parallel()

	aliases := NewAliases([]Alias{
		{From: "", To: "/usr/bin"},
		{From: "/bin", To: ""},
		{From: "/", To: "/usr"},          // aliasing the root rewrites everything
		{From: "/usr", To: "/"},          // and so does aliasing onto it
		{From: "/bin", To: "/bin"},       // self-referential
		{From: "/sbin", To: "/usr/sbin"}, // the only usable entry
	})

	if len(aliases.entries) != 1 {
		t.Fatalf("kept %v, want only the /sbin entry", aliases.entries)
	}
	if got := aliases.Normalize("/sbin/ip"); got != "/usr/sbin/ip" {
		t.Errorf("Normalize = %q, want %q", got, "/usr/sbin/ip")
	}
}

func TestNilAliasesNormalizes(t *testing.T) {
	t.Parallel()

	var aliases *Aliases
	if got := aliases.Normalize("/usr//bin/../bin/sh"); got != "/usr/bin/sh" {
		t.Errorf("Normalize = %q, want %q", got, "/usr/bin/sh")
	}
}
