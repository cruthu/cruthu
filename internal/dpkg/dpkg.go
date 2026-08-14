// Package dpkg builds the file-to-package half of a cruthu index from a Debian
// package database.
//
// The index, not the SBOM, is the authority on paths, and on a Debian image the
// authority behind the index is /var/lib/dpkg: the status file says which
// packages are installed and at what version, and info/<pkg>.list says which
// paths each one declares. See docs/decisions/0001-index-is-the-spine.md.
//
// Everything here reads attacker-controlled input. A package database is part
// of the image being indexed, so a compromised image supplies a compromised
// database, and every path it declares is a path that will not be reported as
// drift. That makes this package a suppression surface, and it is written like
// one: bounded, strict about spelling, and failing closed on anything it cannot
// interpret. See the false-negative note on Build.
package dpkg

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"cruthu.dev/core/internal/index"
)

// Locations inside the rootfs, as fs.FS paths: relative, slash-separated, no
// leading slash. These are the only paths this package opens.
const (
	statusPath = "var/lib/dpkg/status"
	infoDir    = "var/lib/dpkg/info"
)

// Bounds on reading a package database. Every one of these caps a quantity
// taken from an attacker-controlled filesystem, so each is a named constant
// with a boundary test rather than a literal at a call site.
//
// The calibrating measurement is debian:bookworm: 88 packages, a 77 KB status
// file whose longest line is 1,013 bytes, 8,029 declared paths across all
// lists, a largest list of 1,320 paths in 49 KB, and a longest declared path of
// 81 bytes. The caps below sit orders of magnitude above that, so they bound a
// hostile input without being reachable by a real one.
const (
	// maxStatusBytes bounds the status file. A developer workstation with ten
	// thousand packages installed carries roughly 10 MB here.
	maxStatusBytes = 64 << 20

	// maxListBytes bounds one info/<pkg>.list file.
	maxListBytes = 64 << 20

	// maxStatusLineBytes is the longest accepted line of the status file.
	// Depends and Description lines are the long ones; 1,013 bytes is the
	// measured maximum.
	maxStatusLineBytes = 64 << 10

	// maxPathBytes is the longest accepted line of a .list file, which is one
	// path. Linux PATH_MAX is 4096 *including* the terminating NUL, so 4095 is
	// the longest path string the kernel will open — and dpkg cannot install a
	// path the kernel cannot open.
	maxPathBytes = 4095

	// maxPackages bounds how many stanzas the status file may contain.
	maxPackages = 200_000

	// maxFilesPerPackage bounds one package's declared paths. texlive-full,
	// about the largest package in the archive, declares roughly 130,000.
	maxFilesPerPackage = 2_000_000

	// maxTotalFiles bounds declared paths across every package, matching the
	// cap the index applies when it reads the result back. Bounding here as
	// well means an oversized database is refused while it is being read
	// rather than after it has been fully materialized.
	maxTotalFiles = 5_000_000
)

// Build reads the dpkg database from fsys and returns one index.Package per
// installed package, with the paths that package declares.
//
// fsys must be confined to the image root; use index.OpenRootfs to obtain one.
// A package database is attacker-controlled, and a .list file naming a path
// outside the root is not a path this index can describe.
//
// Only packages whose status is "<want> ok installed" are returned. A package
// in any other state has files partially present or absent, and declaring paths
// for it would suppress drift on files the image does not actually own. The
// resulting over-report is the safe direction.
//
// Every failure is an error rather than a partial result. A database that
// cannot be fully read cannot be used to decide that an image is clean, so the
// caller surfaces this as ExitError and never as a clean run.
//
// # The false-negative question
//
// Construct an event that represents real drift but that this code would
// classify as clean.
//
// There is a direct one, and it is inherent to reading the database at all: a
// .list file containing the line "/tmp/kdevtmpfsi" declares that path as owned,
// and a miner dropped there is then reported clean. Nothing in this package can
// detect that, because a declared path is indistinguishable from a legitimately
// declared path.
//
// What bounds it is the same argument ADR 0002 makes for the alias table, and
// it is worth stating rather than hiding. Writing to /var/lib/dpkg requires
// compromising the image build, which is an earlier and different threat than
// the runtime drift this tool exists to detect; an attacker with that access
// has better options than editing a manifest. The declaration is also recorded
// in the serialized index, so the evasion is written down in a diffable,
// eventually-attested artifact rather than being invisible.
//
// What this package does do is refuse every spelling that would let a
// declaration mean something other than it appears to mean: unrooted paths,
// uncleaned paths whose "..' components collapse elsewhere, control bytes, and
// duplicate package identities. Those are the cases where a reviewer reading
// the database and the tool reading the database would disagree, and a
// disagreement there is an evasion that survives review.
func Build(ctx context.Context, fsys fs.FS) ([]index.Package, error) {
	stanzas, err := readStatus(ctx, fsys)
	if err != nil {
		return nil, err
	}

	// Grown rather than pre-sized: the stanza count comes from the input file.
	var pkgs []index.Package
	seen := make(map[string]struct{})
	total := 0

	for _, s := range stanzas {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("dpkg: build: %w", err)
		}

		id := packageID(s)
		if _, dup := seen[id]; dup {
			// Two packages sharing an ID would make ownership depend on
			// stanza order, and the index's own loader takes first-wins. A
			// database that cannot say unambiguously who owns a file is not
			// one this tool can reason about.
			return nil, fmt.Errorf("dpkg: package %q is declared twice in %s", id, statusPath)
		}
		seen[id] = struct{}{}

		files, err := readFileList(ctx, fsys, s)
		if err != nil {
			return nil, err
		}

		total += len(files)
		if total > maxTotalFiles {
			return nil, fmt.Errorf("dpkg: database declares more than %d files", maxTotalFiles)
		}

		pkgs = append(pkgs, index.Package{
			ID:      id,
			Name:    s.name,
			Version: s.version,
			Type:    "deb",
			Files:   files,
		})
	}

	// Sorted so that indexing the same rootfs twice produces byte-identical
	// output. Directory order is not guaranteed by fs.FS, and an index that
	// differs run to run cannot be compared, cached, or meaningfully signed.
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].ID < pkgs[j].ID })

	return pkgs, nil
}

// packageID builds the stable key the index uses to name a package.
//
// The architecture is part of the key, not decoration. On an image with a
// foreign architecture enabled, libc6:amd64 and libc6:i386 are two installed
// packages, usually at the same version, declaring different paths. Keyed on
// name and version alone they collide, and one of the two file lists is
// silently dropped — which is a suppression, so the key carries the
// architecture that distinguishes them.
func packageID(s stanza) string {
	return "deb:" + s.name + ":" + s.architecture + "@" + s.version
}

// cleanDeclaredPath validates one path from a .list file and returns it in the
// spelling the index stores.
//
// It rejects rather than repairs. path.Clean would happily turn
// "/usr/bin/../../tmp/miner" into "/tmp/miner", so accepting an uncleaned path
// means the file a reviewer reads and the path the tool indexes are different
// strings — and the difference is attacker-chosen. Measured on
// debian:bookworm, all 8,029 declared paths are already clean and absolute, so
// refusing anything else costs nothing on a real database.
func cleanDeclaredPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("path longer than %d bytes", maxPathBytes)
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	if hasControlBytes(p) {
		// These flow into the index and then into the table reporter, where a
		// newline forges an output line.
		return "", fmt.Errorf("path contains a control byte")
	}
	if path.Clean(p) != p {
		return "", fmt.Errorf("path %q is not in cleaned form", p)
	}
	// The filesystem root, which is not a file any package can own.
	//
	// Found by FuzzBuild, and it is a false negative rather than a tidiness
	// problem. "/" survives path.Clean unchanged, so it would be stored as a
	// declared path and become a live key in the lookup's owner map — and an
	// observed path of "/.." or "/" cleans to exactly that key, so an event
	// carrying a path field that collapses to the root would resolve to a real
	// package and report clean. dpkg spells the package root "/." and never
	// emits a bare "/": measured across debian:bookworm and
	// python:3.12-bookworm, 517 root markers and zero bare slashes in 37,835
	// declared lines.
	if p == "/" {
		return "", fmt.Errorf("path is the filesystem root")
	}
	return p, nil
}

// hasControlBytes reports whether s contains a C0 control byte or DEL.
//
// Per byte rather than per rune deliberately: every byte of a multi-byte UTF-8
// sequence is >= 0x80, so no continuation byte can be mistaken for a control
// character, and invalid UTF-8 is still screened.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
