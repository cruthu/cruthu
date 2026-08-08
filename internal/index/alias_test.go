package index

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	aliases := mustAliases(t, []Alias{
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
			// This case asserted the opposite until the contract was corrected,
			// and the reversal is the change rather than a side effect of it.
			// Anchoring "bin/sh" at the root made it the same query as
			// "/bin/sh", so a binary planted in a writable working directory
			// and run by relative path resolved through the alias table onto
			// the package-owned /usr/bin/sh and reported clean. An unrooted
			// path carries no information about where it is; resolving one
			// against the event's cwd belongs to the adapter that has the cwd.
			name: "an unrooted path is un-normalizable, not root-anchored",
			in:   "bin/sh",
			want: "",
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
	aliases := mustAliases(t, []Alias{
		{From: "/usr", To: "/opt"},
		{From: "/usr/bin", To: "/opt/sbin"},
	})

	if got := aliases.Normalize("/usr/bin/sh"); got != "/opt/sbin/sh" {
		t.Errorf("Normalize = %q, want %q", got, "/opt/sbin/sh")
	}
}

func TestNewAliasesRejectsNonConvergingSets(t *testing.T) {
	t.Parallel()

	// This used to be TestNormalizeTerminatesOnCycle, which asserted that
	// Normalize picked one of the two cycle members and moved on. Terminating
	// was the right requirement; being satisfied with a half-rewritten result
	// was not. Both sides of a comparison enter a chain at different points, so
	// a clamped result is not the shared spelling the whole design depends on,
	// and a set with no fixed point is refused at load instead.
	tests := []struct {
		name string
		in   []Alias
	}{
		{
			name: "two-element cycle",
			in:   []Alias{{From: "/a", To: "/b"}, {From: "/b", To: "/a"}},
		},
		{
			name: "self-cycle through a longer loop",
			in: []Alias{
				{From: "/a", To: "/b"},
				{From: "/b", To: "/c"},
				{From: "/c", To: "/a"},
			},
		},
		{
			name: "chain longer than the hop bound",
			in:   chainOf(maxAliasHops + 2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// If the hop bound is ever removed this call does not return and
			// the test binary's own timeout reports it, which is the failure we
			// want to see.
			if _, err := NewAliases(tt.in); err == nil {
				t.Fatalf("NewAliases(%v) returned no error", tt.in)
			}
		})
	}
}

// chainOf builds /a0 -> /a1 -> ... -> /aN, a set that converges only if n is
// within maxAliasHops.
func chainOf(n int) []Alias {
	out := make([]Alias, 0, n)
	for i := range n {
		out = append(out, Alias{
			From: fmt.Sprintf("/a%d", i),
			To:   fmt.Sprintf("/a%d", i+1),
		})
	}
	return out
}

func TestNewAliasesAcceptsChainWithinTheBound(t *testing.T) {
	t.Parallel()

	// The boundary on the accepting side, so the bound is pinned from both
	// directions rather than only where it rejects.
	aliases := mustAliases(t, chainOf(maxAliasHops-1))

	if got := aliases.Normalize("/a0/x"); got != fmt.Sprintf("/a%d/x", maxAliasHops-1) {
		t.Errorf("Normalize = %q, want the end of the chain", got)
	}
}

func TestNewAliasesDropsUnusableEntries(t *testing.T) {
	t.Parallel()

	aliases := mustAliases(t, []Alias{
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

// FuzzNormalize asserts that normalization has a fixed point.
//
// Normalize is the function both sides of every comparison pass through, and
// the whole design rests on them landing in the same spelling. Idempotence is
// the cheapest statement of that: if normalizing twice differs from normalizing
// once, then the spelling a path gets depends on how many times it has been
// through the function, and a declared path and an observed path that entered
// an alias chain at different points are compared in different alphabets.
//
// This target fails on the code that preceded it. Normalize clamped at
// maxAliasHops and returned the half-rewritten path, so a chain of nine links
// gave Normalize("/a0/x") = "/a8/x" and Normalize("/a8/x") = "/a9/x".
func FuzzNormalize(f *testing.F) {
	f.Add("/bin", "/usr/bin", "/lib", "/usr/lib", "/bin/sh")
	f.Add("/a", "/b", "/b", "/c", "/a/x")
	// A cycle and a self-reference, both of which NewAliases must refuse.
	f.Add("/a", "/b", "/b", "/a", "/a/x")
	f.Add("/a", "/a", "", "", "/a/x")
	// Unrooted and empty spellings, which normalize to nothing.
	f.Add("/bin", "/usr/bin", "", "", "bin/sh")
	f.Add("", "", "", "", "")
	// Traversal that cleaning has to resolve before any alias can match.
	f.Add("/bin", "/usr/bin", "", "", "/usr/../bin/./sh")
	// An alias whose To re-enters the other alias's From, the shape that makes
	// hop counting necessary at all.
	f.Add("/usr/lib", "/usr/lib64", "/lib", "/usr/lib", "/lib/libc.so.6")

	f.Fuzz(func(t *testing.T, from1, to1, from2, to2, in string) {
		aliases, err := NewAliases([]Alias{{From: from1, To: to1}, {From: from2, To: to2}})
		if err != nil {
			// A refused set has no normalization to be idempotent about.
			return
		}

		once := aliases.Normalize(in)
		twice := aliases.Normalize(once)
		if once != twice {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q", in, once, twice)
		}

		// An accepted set must never produce the un-normalizable result from a
		// rooted path: that outcome is reserved for input this package cannot
		// place, and a converging set can always place a rooted path.
		if strings.HasPrefix(in, "/") && once == "" {
			t.Fatalf("Normalize(%q) returned un-normalizable for a rooted path", in)
		}
	})
}
