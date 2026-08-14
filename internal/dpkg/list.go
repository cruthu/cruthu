package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
)

// rootMarker is the first line dpkg writes into every info/<pkg>.list: the
// package's own root. It is skipped rather than indexed. Cleaned it becomes
// "/", and an index in which "/" is an owned path would report the filesystem
// root as belonging to whichever package sorted first — a claim that means
// nothing and that the alias table drops anyway. Measured on debian:bookworm,
// all 88 lists carry it exactly once.
const rootMarker = "/."

// readFileList reads the paths one installed package declares.
//
// The filename follows dpkg's own multiarch rule: a package marked
// "Multi-Arch: same" is arch-qualified as <name>:<arch>.list because two
// architectures of it can be installed at once, and every other package uses a
// plain <name>.list. Measured on debian:bookworm, that rule picks the right
// file for all 88 installed packages.
//
// A missing list is an error. dpkg writes one for every unpacked package, so a
// package present in status with no list is a database that has been edited or
// truncated. Treating it as "this package declares nothing" would silently mark
// every file the package owns as unowned, and a user who tunes that noise away
// has tuned away the detector.
func readFileList(ctx context.Context, fsys fs.FS, s stanza) ([]string, error) {
	name := s.name + ".list"
	if s.multiArchSame {
		name = s.name + ":" + s.architecture + ".list"
	}
	listPath := infoDir + "/" + name

	// s.name and s.architecture were checked for "/" and ":" as they were read,
	// so this join cannot produce a path outside infoDir. fs.ValidPath is the
	// second check on the same property, because the cost of being wrong here
	// is reading a file outside the database.
	if !fs.ValidPath(listPath) {
		return nil, fmt.Errorf("dpkg: package %q: %q is not a valid path", s.name, listPath)
	}

	f, err := fsys.Open(listPath)
	if err != nil {
		return nil, fmt.Errorf("dpkg: package %q: open %s: %w", s.name, listPath, err)
	}
	defer f.Close() //nolint:errcheck // read-only; a close error cannot affect what was already read

	sc := bufio.NewScanner(io.LimitReader(f, maxListBytes+1))

	// One past the cap, because Scanner's limit is the buffer it may grow to
	// rather than the token it will return: given a max of n it accepts tokens
	// up to n-1. Passing maxPathBytes directly would reject a path of exactly
	// maxPathBytes, which the kernel accepts, and the cap would be off by one
	// against the constant that documents it.
	sc.Buffer(nil, maxPathBytes+1)

	// Grown rather than pre-sized: the path count comes from the input file.
	var files []string
	seen := make(map[string]struct{})
	read := 0
	line := 0

	for sc.Scan() {
		line++

		text := sc.Text()
		read += len(text) + 1
		if read > maxListBytes {
			return nil, fmt.Errorf("dpkg: package %q: %s exceeds %d bytes", s.name, listPath, maxListBytes)
		}

		// Once per 1024 paths: a bounded amount of work between checks,
		// without a context read on every line of a large list.
		if line%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("dpkg: package %q: read %s: %w", s.name, listPath, err)
			}
		}

		if text == rootMarker {
			continue
		}

		p, err := cleanDeclaredPath(text)
		if err != nil {
			// Refused rather than skipped. A skipped line is a path the tool
			// believes nothing declares, which over-reports and is safe; but a
			// database containing one is a database someone has edited, and
			// the rest of it cannot then be trusted to be complete.
			return nil, fmt.Errorf("dpkg: package %q: %s line %d: %w", s.name, listPath, line, err)
		}

		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		if len(files) >= maxFilesPerPackage {
			return nil, fmt.Errorf("dpkg: package %q declares more than %d files", s.name, maxFilesPerPackage)
		}
		files = append(files, p)
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("dpkg: package %q: %s has a line longer than %d bytes", s.name, listPath, maxPathBytes)
		}
		return nil, fmt.Errorf("dpkg: package %q: read %s: %w", s.name, listPath, err)
	}

	// Sorted for the same reason the package slice is: indexing one rootfs
	// twice must produce byte-identical output, and dpkg does not promise an
	// order.
	sort.Strings(files)

	return files, nil
}
