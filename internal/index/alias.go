package index

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Bounds on alias discovery. Every one of these caps a quantity derived from
// an attacker-controlled filesystem, so each is a named constant with a test
// at its boundary rather than a literal at a call site.
const (
	// maxAliases bounds how many directory symlinks are recorded. Real images
	// have a handful (/bin, /sbin, /lib, /lib64); a filesystem with thousands
	// is hostile or broken, and either way the index is not trustworthy.
	maxAliases = 1024

	// maxWalkEntries bounds the scan itself, so a filesystem with an absurd
	// number of entries cannot make indexing run unbounded.
	maxWalkEntries = 5_000_000

	// maxAliasHops bounds chain resolution during normalization. Aliases can
	// legitimately chain (/lib -> /usr/lib while /usr/lib -> /usr/lib64), but a
	// cycle must terminate rather than spin.
	maxAliasHops = 8
)

var (
	errTooManyAliases = fmt.Errorf("index: more than %d directory symlinks", maxAliases)
	errTooManyEntries = fmt.Errorf("index: more than %d filesystem entries", maxWalkEntries)
)

// BuildAliases scans fsys for symlinks that point at directories and records
// each one as a path rewrite.
//
// This is what makes a merged-/usr image comparable. dpkg records
// /usr/bin/sh while a sensor reports the exec as /bin/sh; without the rewrite
// every binary on such an image reports as unowned. See
// docs/decisions/0002-path-aliasing.md.
//
// fsys must implement fs.ReadLinkFS; use OpenRootfs to obtain one. Targets are
// read and resolved here rather than traversed, because os.Root deliberately
// refuses to follow absolute or escaping symlinks, and an absolute
// `/bin -> /usr/bin` is still an alias worth recording even though following it
// is not allowed.
func BuildAliases(fsys fs.FS) ([]Alias, error) {
	linkFS, ok := fsys.(fs.ReadLinkFS)
	if !ok {
		return nil, errors.New("index: filesystem cannot read symlinks; open it with OpenRootfs")
	}

	var aliases []Alias
	entries := 0

	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// An unreadable subtree is skipped, not fatal. This is safe in the
			// one direction that matters: a missing alias can only stop an
			// observed path from matching, which over-reports drift. It cannot
			// hide drift. Failing the whole index here would let one odd
			// directory disable the tool entirely.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		entries++
		if entries > maxWalkEntries {
			return errTooManyEntries
		}

		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		resolved, ok := directoryLinkTarget(fsys, linkFS, name)
		if !ok {
			return nil
		}

		from, to := "/"+name, "/"+resolved
		if from == to {
			return nil
		}

		if len(aliases) >= maxAliases {
			return errTooManyAliases
		}
		aliases = append(aliases, Alias{From: from, To: to})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return aliases, nil
}

// directoryLinkTarget reports the root-relative path a symlink names, if and
// only if that path is a real directory inside the root.
//
// Every failure collapses to a single false rather than an error, because none
// of them is a failure of the index: a link to a file, a dangling link, a link
// out of the root, and an unreadable link are all simply "not an alias". The
// bool-returning shape keeps that judgment in one place instead of scattering
// error-swallowing through the walk, where returning nil after a non-nil error
// is exactly the fail-open pattern the linters watch for.
func directoryLinkTarget(fsys fs.FS, linkFS fs.ReadLinkFS, name string) (string, bool) {
	target, err := linkFS.ReadLink(name)
	if err != nil {
		return "", false
	}

	resolved, ok := resolveLinkTarget(name, target)
	if !ok {
		return "", false
	}

	// Stat follows the resolved path, so a link to a file, to a dangling path,
	// or to anything outside the root fails here. Only a symlink that genuinely
	// names a directory is allowed to rewrite paths.
	info, err := fs.Stat(fsys, resolved)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return resolved, true
}

// resolveLinkTarget converts a symlink target into a path relative to the
// filesystem root, reporting false when the target does not name something
// inside the root.
//
// Absolute targets are interpreted against the container root rather than the
// host root, which is what they mean inside an image. Relative targets resolve
// against the link's own directory. Either way the result is checked with
// fs.ValidPath, which rejects "..", absolute paths, and empty elements — so a
// target escaping the tree is dropped rather than recorded as an alias that
// would rewrite paths to somewhere outside the image.
func resolveLinkTarget(name, target string) (string, bool) {
	if target == "" {
		return "", false
	}

	var resolved string
	if rooted, absolute := strings.CutPrefix(target, "/"); absolute {
		resolved = path.Clean(rooted)
	} else {
		resolved = path.Join(path.Dir(name), target)
	}

	// "." is the root itself. Aliasing a directory onto the root would rewrite
	// unrelated paths wholesale, so it is never recorded.
	if resolved == "." || !fs.ValidPath(resolved) {
		return "", false
	}
	return resolved, true
}

// Aliases rewrites paths through a set of directory-symlink aliases so that the
// two sides of a comparison meet in one spelling.
//
// The zero value and a nil *Aliases both normalize paths without rewriting,
// which is the correct behavior for an image that has no directory symlinks.
type Aliases struct {
	// entries is sorted longest From first, so that the most specific alias
	// wins when several match. Without that ordering, /usr and /usr/bin
	// aliases would apply in map-iteration order and normalization would not
	// be deterministic.
	entries []Alias
}

// NewAliases prepares an alias set for normalization. Entries that cannot
// rewrite anything meaningfully — empty, rooted at "/", or self-referential —
// are dropped rather than stored, so Normalize never has to defend against
// them.
//
// It returns an error when the surviving entries do not converge: a cycle, or a
// chain longer than maxAliasHops. Refusing at load is the point. The bound used
// to be applied per query inside Normalize, which silently clamped a long chain
// rather than reporting it, and the two sides of a comparison enter a chain at
// different points — a declared /a/x and an observed /c/x walking the same
// nine-link chain stop at different links and stop being comparable. The old
// comment claimed a bounded result "is still consistent between them". It is
// not, and this is where that is fixed.
func NewAliases(in []Alias) (*Aliases, error) {
	// Grown rather than pre-sized: len(in) is an entry count taken straight
	// from the index file, and sizing an allocation from an attacker-supplied
	// number is what the house rules forbid. Real tables hold four entries.
	var entries []Alias
	for _, a := range in {
		from, to := cleanAbs(a.From), cleanAbs(a.To)
		if from == "" || to == "" || from == "/" || to == "/" || from == to {
			continue
		}
		entries = append(entries, Alias{From: from, To: to})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return len(entries[i].From) > len(entries[j].From)
	})

	a := &Aliases{entries: entries}
	if err := a.checkConverges(); err != nil {
		return nil, err
	}
	return a, nil
}

// checkConverges reports whether every alias resolves to a fixed point within
// maxAliasHops.
//
// Only the From of each entry needs walking. Any path the set rewrites at all
// matches some entry's From — as the whole path or as a leading component run —
// and it then follows that entry's chain, so the entries' own chains are the
// only ones there are.
func (a *Aliases) checkConverges() error {
	for _, e := range a.entries {
		p := e.From
		converged := false

		for range maxAliasHops {
			next, rewritten := a.rewriteOnce(p)
			if !rewritten {
				converged = true
				break
			}
			p = next
		}

		if !converged {
			return fmt.Errorf("index: alias %q does not resolve within %d hops; the set has a cycle or too long a chain", e.From, maxAliasHops)
		}
	}
	return nil
}

// Normalize rewrites p through the alias set until no alias applies, and
// returns the spelling both declared and observed paths are compared in.
//
// It returns "" for a path it cannot resolve: one that is not rooted, and one
// that is still being rewritten after maxAliasHops. NewAliases refuses a
// non-converging set outright, so the second case needs a set built by hand to
// reach — and "" is the fail-closed answer for it either way, because an
// unresolvable path is owned by nothing and is reported as drift. The previous
// behavior returned the half-rewritten path, which could collide with an
// unrelated declared path and report a planted binary as legitimate.
func (a *Aliases) Normalize(p string) string {
	p = cleanAbs(p)
	if a == nil || p == "" {
		return p
	}

	for range maxAliasHops {
		next, rewritten := a.rewriteOnce(p)
		if !rewritten {
			return p
		}
		p = next
	}

	// Still rewriting after the bound: no fixed point, so no comparable
	// spelling exists.
	if _, rewritten := a.rewriteOnce(p); rewritten {
		return ""
	}
	return p
}

// rewriteOnce applies the most specific matching alias, matching on whole path
// components. The component check is the point: a prefix match on raw strings
// would rewrite /binary using an alias for /bin.
func (a *Aliases) rewriteOnce(p string) (string, bool) {
	for _, e := range a.entries {
		if p == e.From {
			return e.To, true
		}
		if strings.HasPrefix(p, e.From+"/") {
			return e.To + p[len(e.From):], true
		}
	}
	return p, false
}
