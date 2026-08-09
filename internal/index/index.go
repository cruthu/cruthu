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
	"slices"
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
//
// A nil index yields a Lookup that owns nothing. Returning an empty result
// rather than panicking keeps the failure in the direction that over-reports
// drift, and means a caller that mishandles a load error still cannot crash the
// process on the query path.
//
// It returns an error only when the alias set does not converge, which makes
// the index unusable rather than merely empty: without a fixed point there is
// no spelling for the two sides to meet in. LoadVerified rejects such a table
// already, so this is reachable only from an Index built in memory.
func NewLookup(idx *Index) (Lookup, error) {
	if idx == nil {
		empty, err := NewAliases(nil)
		if err != nil {
			return nil, err
		}
		return &lookup{aliases: empty, owners: map[string]int{}}, nil
	}

	aliases, err := NewAliases(idx.Aliases)
	if err != nil {
		return nil, err
	}

	// Not pre-sized: the file count comes from the input file, and sizing an
	// allocation from untrusted input is exactly what the house rules forbid.
	owners := make(map[string]int)

	for i := range idx.Packages {
		for _, f := range idx.Packages[i].Files {
			normalized := aliases.Normalize(f)

			// An owned "" would be matched by any observed path that
			// normalizes away to nothing, so it is never a key. validate
			// rejects empty declared paths too; this does not depend on that,
			// because NewLookup is reachable from an index built in memory and
			// never passed through validate.
			if normalized == "" {
				continue
			}
			if _, seen := owners[normalized]; seen {
				continue
			}
			owners[normalized] = i
		}
	}

	return &lookup{aliases: aliases, pkgs: idx.Packages, owners: owners}, nil
}

func (l *lookup) Owner(p string) (Package, bool) {
	normalized := l.aliases.Normalize(p)

	// An unnormalizable path is not owned by anything. Without this, a
	// truncated event whose path field is empty looks up the "" key, and
	// "the sensor told us nothing" reads as "the sensor told us it was fine".
	if normalized == "" {
		return Package{}, false
	}

	i, ok := l.owners[normalized]
	if !ok {
		return Package{}, false
	}

	out := l.pkgs[i]

	// Clipped so that a caller appending to the returned Files writes into its
	// own array instead of over the next package's paths in the index's
	// storage. Callers still must not assign through the slice; Files is the
	// index's data, and the Lookup contract is read-only.
	out.Files = slices.Clip(out.Files)
	return out, true
}

// cleanAbs cleans p into the single spelling this package compares paths in,
// and returns "" for any path it cannot place — which is every path that does
// not start at the root.
//
// It used to prepend "/" to an unrooted path instead, making Owner("bin/sh")
// and Owner("/bin/sh") the same query. That is a false negative with a short
// recipe: an attacker in a writable working directory creates ./bin/sh and
// execs it by relative path; the sensor reports the binary as "bin/sh"; this
// function anchored it to /bin/sh; the alias table sent that to /usr/bin/sh;
// and a planted binary resolved to dash and reported clean.
//
// The anchoring was never a decision about paths, it was a guess at a missing
// working directory. Only the event adapter knows an event's cwd, so resolving
// a relative observed path is the adapter's job — against the cwd the event
// carries, dropping the event as unparseable when it carries none. Here, an
// unrooted path is simply not a path this index can reason about, and "" carries
// that to Owner, which owns nothing. The failure direction is over-reported
// drift rather than an invented match.
func cleanAbs(p string) string {
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	return path.Clean(p)
}
