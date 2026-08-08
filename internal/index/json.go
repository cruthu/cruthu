package index

import (
	"encoding/json"
	"fmt"
	"io"
)

// Bounds on reading a serialized index. An index file is untrusted input like
// everything else cruthu reads: it arrives as a CI artifact, from a shared
// cache, or eventually from a registry, and nothing about it is verified before
// it is parsed.
const (
	// maxIndexBytes bounds the serialized form. A full Debian index is a few
	// megabytes; 256 MiB is far above any real image and far below a size that
	// would exhaust a CI runner.
	maxIndexBytes = 256 << 20

	// maxIndexFiles bounds the total declared paths across all packages. A
	// large distribution image declares a few hundred thousand.
	maxIndexFiles = 5_000_000
)

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

// ReadJSON parses a serialized index, enforcing the schema version and the size
// bounds above.
//
// Every failure here is an error rather than a partial result. An index that
// cannot be fully trusted cannot be used to decide that an image is clean, so
// the caller must surface this as ExitError and never as a clean run.
func ReadJSON(r io.Reader) (*Index, error) {
	// Read one byte past the cap so that hitting the limit is distinguishable
	// from a file that happens to be exactly maxIndexBytes long.
	data, err := io.ReadAll(io.LimitReader(r, maxIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("index: read: %w", err)
	}
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("index: read: input exceeds %d bytes", maxIndexBytes)
	}

	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("index: parse: %w", err)
	}

	if err := validate(&idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

// validate rejects an index that parsed as JSON but cannot be reasoned about.
func validate(idx *Index) error {
	if idx.SchemaVersion != SchemaVersion {
		return fmt.Errorf("index: unsupported schema version %q, want %q", idx.SchemaVersion, SchemaVersion)
	}

	total := 0
	for i := range idx.Packages {
		// A package with no ID cannot be reported as the owner of anything,
		// and silently keeping it would mean drift attributed to "".
		if idx.Packages[i].ID == "" {
			return fmt.Errorf("index: package at position %d has an empty id", i)
		}

		total += len(idx.Packages[i].Files)
		if total > maxIndexFiles {
			return fmt.Errorf("index: more than %d declared files", maxIndexFiles)
		}
	}
	return nil
}
