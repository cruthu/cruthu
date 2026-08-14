package dpkg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// stanza is the part of one status-file paragraph this package needs. The
// status file carries a few dozen fields per package; every one not read here
// is skipped rather than stored, so nothing in the database reaches the index
// unless it was asked for by name.
type stanza struct {
	name         string
	version      string
	architecture string

	// multiArchSame records "Multi-Arch: same", which is what decides whether
	// the package's file list is named <pkg>.list or <pkg>:<arch>.list.
	multiArchSame bool
}

// Field names this package reads, in dpkg's exact spelling.
//
// Deb822 field names are case-insensitive to dpkg, and a lenient reader here
// would be a parser differential: "package:" and "Package:" would name the same
// field to this code while a reviewer greps for one spelling. The status file
// is written by dpkg, which emits exactly these, so requiring them costs
// nothing on a real database and removes the ambiguity on a hostile one.
const (
	fieldPackage      = "Package"
	fieldVersion      = "Version"
	fieldArchitecture = "Architecture"
	fieldStatus       = "Status"
	fieldMultiArch    = "Multi-Arch"
)

// installedState is the third word of a Status field for a package whose files
// are fully present. Every other state — config-files, half-installed,
// unpacked, half-configured, triggers-awaiting — means the file list on disk
// and the file list in info/ disagree.
const installedState = "installed"

// readStatus parses var/lib/dpkg/status and returns one stanza per package
// that is fully installed.
//
// An unreadable or malformed status file is an error, never an empty result.
// An empty package set would make every observed path unowned, which reads as
// total drift rather than as a broken read — loud, but for the wrong reason,
// and a user who suppresses that noise has suppressed the detector.
func readStatus(ctx context.Context, fsys fs.FS) ([]stanza, error) {
	f, err := fsys.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("dpkg: open %s: %w", statusPath, err)
	}
	defer f.Close() //nolint:errcheck // read-only; a close error cannot affect what was already read

	// One byte past the cap, so hitting the limit is distinguishable from a
	// file that happens to be exactly maxStatusBytes long.
	sc := bufio.NewScanner(io.LimitReader(f, maxStatusBytes+1))

	// One past the cap, for the same reason as in readFileList: Scanner's limit
	// is the buffer size it may reach, so a max of n returns tokens only up to
	// n-1.
	sc.Buffer(nil, maxStatusLineBytes+1)

	var (
		stanzas []stanza
		fields  = map[string]string{}
		read    int
	)

	// flush ends the current paragraph. Called at every blank line and once at
	// EOF, because the status file's last stanza has no trailing blank line.
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		defer clear(fields)

		s, installed, err := stanzaFrom(fields)
		if err != nil {
			return err
		}
		if !installed {
			return nil
		}
		if len(stanzas) >= maxPackages {
			return fmt.Errorf("dpkg: %s declares more than %d packages", statusPath, maxPackages)
		}
		stanzas = append(stanzas, s)
		return nil
	}

	for sc.Scan() {
		line := sc.Text()

		read += len(line) + 1
		if read > maxStatusBytes {
			return nil, fmt.Errorf("dpkg: %s exceeds %d bytes", statusPath, maxStatusBytes)
		}

		// Cancellation is checked per line only when a paragraph ends, so the
		// check runs once per package rather than once per field.
		if line == "" {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("dpkg: read %s: %w", statusPath, err)
			}
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}

		// A continuation line belongs to the previous field's value. None of
		// the five fields read here is ever continued, so skipping these is
		// what keeps a crafted Description from being read as a field.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("dpkg: %s: line is not a field: %q", statusPath, truncate(line))
		}
		if !wantedField(name) {
			continue
		}
		if _, dup := fields[name]; dup {
			// dpkg emits each field once. A second one would be last-wins to
			// this parser and first-wins to a reader skimming the file, and
			// that disagreement is how a package hides its real version.
			return nil, fmt.Errorf("dpkg: %s: field %q appears twice in one stanza", statusPath, name)
		}
		fields[name] = strings.TrimSpace(value)
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("dpkg: %s: line longer than %d bytes", statusPath, maxStatusLineBytes)
		}
		return nil, fmt.Errorf("dpkg: read %s: %w", statusPath, err)
	}

	if err := flush(); err != nil {
		return nil, err
	}

	if len(stanzas) == 0 {
		// A Debian rootfs with no installed packages is not a Debian rootfs.
		// Returning an empty set here would hand the reconciler an index that
		// owns nothing, and "we could not read the database" would arrive as
		// "nothing in this image is declared".
		return nil, fmt.Errorf("dpkg: %s declares no installed packages", statusPath)
	}

	return stanzas, nil
}

// wantedField reports whether a field name is one of the five this package
// reads.
func wantedField(name string) bool {
	switch name {
	case fieldPackage, fieldVersion, fieldArchitecture, fieldStatus, fieldMultiArch:
		return true
	}
	return false
}

// stanzaFrom converts one paragraph's fields into a stanza, reporting whether
// the package is fully installed.
//
// A package that is not installed is skipped rather than rejected: the status
// file legitimately retains stanzas for removed packages, and refusing them
// would make an ordinary image unindexable.
func stanzaFrom(fields map[string]string) (stanza, bool, error) {
	status := fields[fieldStatus]
	if status == "" {
		return stanza{}, false, fmt.Errorf("dpkg: %s: stanza for %q has no %s field", statusPath, truncate(fields[fieldPackage]), fieldStatus)
	}

	// "<want> <error> <state>", exactly three words. A Status this parser
	// cannot read is refused rather than assumed uninstalled, because
	// "unreadable" and "not installed" have opposite consequences: one is a
	// broken database, the other silently drops a package's whole file list.
	parts := strings.Fields(status)
	if len(parts) != 3 {
		return stanza{}, false, fmt.Errorf("dpkg: %s: malformed %s %q", statusPath, fieldStatus, truncate(status))
	}
	if parts[2] != installedState {
		return stanza{}, false, nil
	}
	if parts[1] != "ok" {
		// A package in an error state has files in an unknown condition.
		// Skipping it over-reports drift, which is the safe direction.
		return stanza{}, false, nil
	}

	s := stanza{
		name:          fields[fieldPackage],
		version:       fields[fieldVersion],
		architecture:  fields[fieldArchitecture],
		multiArchSame: fields[fieldMultiArch] == "same",
	}

	for _, f := range []struct{ what, value string }{
		{fieldPackage, s.name},
		{fieldVersion, s.version},
		{fieldArchitecture, s.architecture},
	} {
		if f.value == "" {
			return stanza{}, false, fmt.Errorf("dpkg: %s: installed stanza for %q has no %s field", statusPath, truncate(s.name), f.what)
		}
		if hasControlBytes(f.value) {
			return stanza{}, false, fmt.Errorf("dpkg: %s: %s field contains a control byte", statusPath, f.what)
		}
	}

	// The name and architecture are concatenated into a filename below and
	// into the package ID above. A name carrying a slash or a colon would
	// escape both: "../../etc" as a package name builds a path outside info/,
	// and a colon makes the arch-qualified filename ambiguous.
	if err := validNameComponent(s.name); err != nil {
		return stanza{}, false, fmt.Errorf("dpkg: %s: package name %q: %w", statusPath, truncate(s.name), err)
	}
	if err := validNameComponent(s.architecture); err != nil {
		return stanza{}, false, fmt.Errorf("dpkg: %s: architecture %q: %w", statusPath, truncate(s.architecture), err)
	}

	return s, true, nil
}

// validNameComponent rejects a package name or architecture that cannot be
// safely joined into a filename or an identifier.
//
// Debian policy already restricts both to a narrow alphabet, so this rejects
// nothing a real database contains. It is here because the value is used to
// build a path, and a value used to build a path is checked where it enters,
// not where it is joined.
func validNameComponent(s string) error {
	if strings.ContainsAny(s, "/:") {
		return errors.New("contains a path or architecture separator")
	}
	if s == "." || s == ".." {
		return errors.New("names a directory rather than a package")
	}
	return nil
}

// truncate shortens a value for an error message. Error text derived from
// attacker-controlled input goes to a terminal and into CI logs, and an
// unbounded field would let a hostile database write a screen of output.
func truncate(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
