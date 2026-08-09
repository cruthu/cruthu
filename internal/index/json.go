package index

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Bounds on reading a serialized index. An index file is untrusted input like
// everything else cruthu reads: it arrives as a CI artifact, from a shared
// cache, or eventually from a registry.
const (
	// maxIndexBytes bounds the serialized form. A full Debian index is a few
	// megabytes; 256 MiB is far above any real image and far below a size that
	// would exhaust a CI runner.
	maxIndexBytes = 256 << 20

	// maxIndexFiles bounds the total declared paths across all packages. A
	// large distribution image declares a few hundred thousand.
	maxIndexFiles = 5_000_000

	// maxJSONDepth bounds nesting during the pre-parse scan. The index schema
	// nests four levels deep (document, packages array, package object, files
	// array); anything past this is not an index, and refusing it early keeps
	// the scan's own stack bounded by a constant rather than by the input.
	maxJSONDepth = 32
)

// digestPrefix is the only digest algorithm the index records. Free-form
// digests are where digest confusion starts, once two indices for "the same"
// image are compared.
const digestPrefix = "sha256:"

// schemaFieldNames is every field name the index schema uses, in its exact
// spelling.
//
// encoding/json matches field names case-insensitively, so DisallowUnknownFields
// alone accepts {"SCHEMAVERSION": ...} and populates SchemaVersion from it. Two
// parsers reading the same bytes and disagreeing about which fields are set is a
// parser differential, and this index is going to be signed. Requiring the exact
// spelling here removes the differential; DisallowUnknownFields still does the
// complementary job of rejecting a known name in the wrong position.
var schemaFieldNames = map[string]struct{}{
	"schemaVersion": {},
	"source":        {},
	"aliases":       {},
	"packages":      {},
	"kind":          {},
	"reference":     {},
	"digest":        {},
	"builtAt":       {},
	"id":            {},
	"name":          {},
	"version":       {},
	"type":          {},
	"files":         {},
	"from":          {},
	"to":            {},
}

// WriteJSON serializes idx, always stamping the current SchemaVersion so a
// caller cannot emit an index labeled with a version it does not conform to.
func WriteJSON(w io.Writer, idx *Index) error {
	if idx == nil {
		return fmt.Errorf("index: write: nil index")
	}

	out := *idx
	out.SchemaVersion = SchemaVersion

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&out); err != nil {
		return fmt.Errorf("index: write: %w", err)
	}
	return nil
}

// ReadBounded reads an index's bytes from r, refusing anything over
// maxIndexBytes.
//
// It exists so that the byte cap stays inside this package. LoadVerified takes
// bytes, which means something else has to do the reading, and a caller that
// reaches for io.ReadAll would restore exactly the unbounded read the cap is
// there to prevent. The returned bytes are the input to verification and then
// to LoadVerified, in that order.
func ReadBounded(r io.Reader) ([]byte, error) {
	// One byte past the cap, so that hitting the limit is distinguishable from
	// a file that happens to be exactly maxIndexBytes long.
	data, err := io.ReadAll(io.LimitReader(r, maxIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("index: read: %w", err)
	}
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("index: read: input exceeds %d bytes", maxIndexBytes)
	}
	return data, nil
}

// LoadVerified parses a serialized index from bytes whose authenticity the
// caller has already established.
//
// The signature is the trust boundary, and it takes []byte rather than an
// io.Reader for that reason: a signature covers a complete message, so anything
// that must be verified before it is parsed must be fully in hand before
// parsing starts. Nothing in this package verifies anything yet — signing
// arrives later — but the shape is fixed now so that adding verification is not
// a breaking change to a schema advertised as stable from its first commit.
//
// Every failure here is an error rather than a partial result. An index that
// cannot be fully trusted cannot be used to decide that an image is clean, so
// the caller must surface this as ExitError and never as a clean run.
func LoadVerified(data []byte) (*Index, error) {
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("index: read: input exceeds %d bytes", maxIndexBytes)
	}

	// Scanned before decoding, because the decoder silently resolves the
	// ambiguities this rejects rather than reporting them.
	if err := scanTokens(data); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var idx Index
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("index: parse: %w", err)
	}

	// A second value after the first would otherwise be ignored, letting one
	// file mean two different indices depending on who reads it.
	if dec.More() {
		return nil, fmt.Errorf("index: parse: trailing data after index object")
	}

	if err := validate(&idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

// jsonFrame is one open container during the token scan.
type jsonFrame struct {
	// keys holds the keys seen in this object, and is nil when the frame is an
	// array. Arrays have no keys, so nil doubles as the container-kind tag.
	keys map[string]struct{}

	// wantKey records whether the next string token in this object is a key
	// rather than a value. Object tokens alternate key, value, key, value, so
	// tracking the position is what distinguishes {"a": "b"} from {"b": "a"}.
	wantKey bool
}

// scanTokens walks the document and rejects duplicate object keys, field names
// that are not spelled exactly as the schema spells them, and nesting past
// maxJSONDepth.
//
// Duplicate keys matter because encoding/json takes the last one and silently
// discards the rest: {"aliases": [], "aliases": [<injected>]} decodes to the
// injected table while a reviewer reading the file top to bottom sees an empty
// one. Rejecting the file is the only reading of it that cannot be wrong.
func scanTokens(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))

	var stack []jsonFrame

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("index: parse: %w", err)
		}

		// A closing delimiter ends the innermost container, which is itself the
		// value its parent was waiting for.
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			noteValue(stack)
			continue
		}

		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.keys != nil && top.wantKey {
				key, isString := tok.(string)
				if !isString {
					// Unreachable: the decoder rejects a non-string object key
					// before Token returns it. Refused rather than ignored,
					// because an impossible case that falls through is how a
					// parser ends up trusting something it never checked.
					return fmt.Errorf("index: parse: object key is not a string")
				}

				if _, dup := top.keys[key]; dup {
					return fmt.Errorf("index: parse: duplicate key %q", key)
				}
				if _, known := schemaFieldNames[key]; !known {
					return fmt.Errorf("index: parse: unknown field %q", key)
				}
				top.keys[key] = struct{}{}
				top.wantKey = false
				continue
			}
		}

		if d, ok := tok.(json.Delim); ok {
			if len(stack) >= maxJSONDepth {
				return fmt.Errorf("index: parse: nested deeper than %d", maxJSONDepth)
			}
			if d == '{' {
				stack = append(stack, jsonFrame{keys: map[string]struct{}{}, wantKey: true})
			} else {
				stack = append(stack, jsonFrame{})
			}
			continue
		}

		noteValue(stack)
	}

	return nil
}

// noteValue records that the innermost container just consumed a complete
// value, so an object expects a key next.
func noteValue(stack []jsonFrame) {
	if len(stack) == 0 {
		return
	}
	if top := &stack[len(stack)-1]; top.keys != nil {
		top.wantKey = true
	}
}

// validate rejects an index that parsed as JSON but cannot be reasoned about.
//
// Everything here moves an input from accepted to rejected, and a rejected index
// is ExitError. None of it can make a dirty image read clean.
func validate(idx *Index) error {
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("index: unsupported schema version %q, want %q", idx.SchemaVersion, SchemaVersion)
	}

	if d := idx.Source.Digest; d != "" && !validDigest(d) {
		return fmt.Errorf("index: source digest %q is not %s plus 64 lowercase hex characters", d, digestPrefix)
	}

	if err := validateAliases(idx.Aliases); err != nil {
		return err
	}

	total := 0
	for i := range idx.Packages {
		p := &idx.Packages[i]

		// A package with no ID cannot be reported as the owner of anything,
		// and silently keeping it would mean drift attributed to "".
		if p.ID == "" {
			return fmt.Errorf("index: package at position %d has an empty id", i)
		}

		// These four fields are printed verbatim by the reporter. A package
		// named "coreutils\n[INFO] no drift detected" forges an output line,
		// and a reader of that output has no way to tell it was forged.
		for _, f := range []struct {
			what, value string
		}{
			{"id", p.ID},
			{"name", p.Name},
			{"version", p.Version},
		} {
			if hasControlBytes(f.value) {
				return fmt.Errorf("index: package %q has a control byte in its %s", p.ID, f.what)
			}
		}

		for _, path := range p.Files {
			// An empty declared path becomes an owned "" once normalized, and
			// an event whose path field was truncated away then matches it.
			if path == "" {
				return fmt.Errorf("index: package %q declares an empty path", p.ID)
			}
			// An unrooted declared path has no place in the filesystem the
			// index describes, and cleanAbs no longer guesses one for it.
			// Refused rather than dropped: an index quietly holding paths
			// nothing can ever match reports its own contents as drift.
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("index: package %q declares a relative path %q", p.ID, path)
			}
			if hasControlBytes(path) {
				return fmt.Errorf("index: package %q declares a path with a control byte", p.ID)
			}
		}

		total += len(p.Files)
		if total > maxIndexFiles {
			return fmt.Errorf("index: more than %d declared files", maxIndexFiles)
		}
	}
	return nil
}

// validateAliases enforces the canonical merged-/usr shape on a deserialized
// alias table.
//
// This is the narrowest rule that admits every alias the tool exists to handle,
// and it is narrow on purpose. The alias table is a drift-suppression primitive:
// both the declared paths and the observed path are normalized through it, so
// whoever controls the table controls where the two sides meet. An index arrives
// from a CI artifact or a shared cache with nothing verified, which puts that
// control one file edit away from an attacker who never touched the image.
//
// Well-formedness checks do not help here, because the dangerous entry is
// perfectly well formed. {"from": "/tmp", "to": "/usr/bin"} rewrites an exec of
// /tmp/ls onto the package-owned /usr/bin/ls and reports clean; the same entry
// reversed, {"from": "/bin", "to": "/tmp"}, relocates every owned path under
// /bin into /tmp and makes anything dropped there owned. Requiring the pair to
// be a top-level directory and its own /usr twin rejects both, and leaves an
// attacker who can edit the table with no entry that moves any path anywhere it
// would not already have resolved.
//
// Measured against the images this rule has to work on, it costs nothing:
// debian:bookworm and python:3.12-bookworm each carry exactly four directory
// symlinks of this shape (/bin, /lib, /lib64, /sbin) out of 26 and 88 total, and
// every dropped entry is documentation or timezone noise that never aliased
// anything. A distribution that merges some other way fails closed and loudly
// here, which is the right way to find out about it.
func validateAliases(aliases []Alias) error {
	// Real images have four. The cap is defense against a table that is trying
	// to be a denial of service rather than an alias set.
	if len(aliases) > maxAliases {
		return errTooManyAliases
	}

	seen := make(map[string]struct{}, len(aliases))

	for _, a := range aliases {
		if !singleRootComponent(a.From) {
			return fmt.Errorf("index: alias %q -> %q: %q is not a top-level directory", a.From, a.To, a.From)
		}

		// "/usr" -> "/usr/usr" satisfies the twin rule and means nothing. It
		// would rewrite every path under /usr and match nothing at all.
		if a.From == "/usr" {
			return fmt.Errorf("index: alias %q -> %q: /usr cannot be aliased", a.From, a.To)
		}

		if want := "/usr" + a.From; a.To != want {
			return fmt.Errorf("index: alias %q -> %q: only the merged-/usr rewrite to %q is allowed", a.From, a.To, want)
		}

		// Two entries for one From make the file's line order decide which
		// applies, which makes reordering a semantic change.
		if _, dup := seen[a.From]; dup {
			return fmt.Errorf("index: alias %q is declared twice", a.From)
		}
		seen[a.From] = struct{}{}
	}

	// The canonical shape cannot express a chain — a To of "/usr/bin" is two
	// components and no valid From is — so this cannot fire on a table that
	// passed the loop above. It runs anyway, because the two rules are
	// independent contracts and a later widening of the shape rule must not
	// silently reopen non-convergence.
	if _, err := NewAliases(aliases); err != nil {
		return err
	}

	return nil
}

// singleRootComponent reports whether p is "/" followed by exactly one ordinary
// path component: "/bin" yes, "/usr/bin", "/", "/..", and "bin" no.
func singleRootComponent(p string) bool {
	name, rooted := strings.CutPrefix(p, "/")
	if !rooted || name == "" {
		return false
	}
	if strings.Contains(name, "/") {
		return false
	}
	// cleanAbs would fold these into something else entirely, so a table
	// containing them does not mean what it appears to mean.
	return name != "." && name != ".."
}

// validDigest reports whether d is digestPrefix followed by exactly 64
// lowercase hex characters. Uppercase is rejected rather than folded, so that
// one digest has one spelling and two indices for the same image compare equal
// as strings.
func validDigest(d string) bool {
	hex, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hex) != 64 {
		return false
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// hasControlBytes reports whether s contains a C0 control byte or DEL.
//
// The check is per byte rather than per rune deliberately: every byte of a
// multi-byte UTF-8 sequence is >= 0x80, so no continuation byte can be mistaken
// for a control character, and invalid UTF-8 is still screened.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
