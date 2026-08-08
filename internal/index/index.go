// Package index builds, serializes, and queries the file-to-package index:
// the mapping from a path inside a container filesystem to the package that
// declares that path.
//
// The index, not the SBOM, is the authority on paths. Most SBOMs carry no file
// lists, and the ones that do carry them unreliably, so resolving an observed
// path through the SBOM would work on some inputs and degrade silently on the
// rest. See docs/decisions/0001-index-is-the-spine.md.
package index

import (
	"path"
	"strings"
	"time"
)

// SchemaVersion identifies the on-disk index format. It is part of the tool's
// public contract from the first commit: a later attestation references the
// index it was computed against, so the format cannot change shape without
// changing this string and logging the change in docs/decisions/.
const SchemaVersion = "cruthu.dev/index/v0"

// Index is the serialized file-to-package mapping for one container
// filesystem, plus everything needed to interpret it later.
type Index struct {
	SchemaVersion string `json:"schemaVersion"`

	// Source records what this index was built from.
	Source Source `json:"source"`

	// Aliases records the directory symlinks found in the filesystem. They are
	// serialized rather than recomputed because `cruthu check` runs from the
	// index file alone, long after the filesystem it describes is gone, and it
	// still has to normalize the paths a sensor reports. Dropping them here
	// would make every observed path through an aliased directory fail to
	// match.
	Aliases []Alias `json:"aliases"`

	Packages []Package `json:"packages"`
}

// Source records the provenance of an index.
type Source struct {
	// Kind is "rootfs" or "image".
	Kind string `json:"kind"`

	// Reference is the directory or image reference the index was built from.
	Reference string `json:"reference"`

	// Digest is the image digest when one is known, empty otherwise.
	Digest string `json:"digest,omitempty"`

	BuiltAt time.Time `json:"builtAt"`
}

// Package is one installed package and the paths it declares.
type Package struct {
	// ID is a stable key across runs, of the form "deb:libc6@2.36-9+deb12u7".
	ID string `json:"id"`

	Name    string `json:"name"`
	Version string `json:"version"`

	// Type is the package database the entry came from: "deb", "apk", "rpm".
	Type string `json:"type"`

	// Files are absolute, cleaned, deduplicated paths inside the filesystem.
	Files []string `json:"files"`
}

// Alias records a directory symlink as a path rewrite, so that "/bin" pointing
// at "/usr/bin" becomes {From: "/bin", To: "/usr/bin"}.
type Alias struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Lookup resolves an observed path to the package that declares it.
//
// Implementations normalize the path through the index's aliases before
// matching. Callers pass the path exactly as the sensor reported it.
type Lookup interface {
	// Owner reports the package declaring path, if any. A false result means
	// no package declares it, which is the raw material of a drift finding.
	Owner(path string) (Package, bool)
}

// lookup is the Lookup built over a loaded Index.
type lookup struct {
	aliases *Aliases
	pkgs    []Package

	// owners maps a normalized path to an index into pkgs. Storing the index
	// rather than the Package keeps one copy of each package's file list.
	owners map[string]int
}

// NewLookup builds a path resolver over idx.
//
// Every declared path is normalized through the alias set at construction, and
// Owner normalizes the observed path the same way, so the two sides always meet
// in the same spelling. Normalizing only one side is the bug this design exists
// to prevent: see docs/decisions/0002-path-aliasing.md.
//
// When two packages declare the same path, the first in Packages order wins.
// That ambiguity affects which package is reported as the owner; it never
// affects whether a path is owned at all, which is what drift turns on.
func NewLookup(idx *Index) Lookup {
	aliases := NewAliases(idx.Aliases)

	// Not pre-sized: the file count comes from the input file, and sizing an
	// allocation from untrusted input is exactly what the house rules forbid.
	owners := make(map[string]int)

	for i := range idx.Packages {
		for _, f := range idx.Packages[i].Files {
			normalized := aliases.Normalize(f)
			if _, seen := owners[normalized]; seen {
				continue
			}
			owners[normalized] = i
		}
	}

	return &lookup{aliases: aliases, pkgs: idx.Packages, owners: owners}
}

func (l *lookup) Owner(p string) (Package, bool) {
	i, ok := l.owners[l.aliases.Normalize(p)]
	if !ok {
		return Package{}, false
	}
	return l.pkgs[i], true
}

// cleanAbs normalizes p to a cleaned, absolute, slash-separated path so that
// "/usr//bin/../bin/sh", "usr/bin/sh", and "/usr/bin/sh" all compare equal.
// Path comparison is detection logic, so every path entering the index or a
// lookup passes through here rather than being compared as a raw string.
func cleanAbs(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}
