package index

import (
	"context"
	"fmt"
	"io/fs"
)

// Build assembles an Index from src and pkgs, computing the alias table from
// fsys.
//
// This is the only place an Index is constructed for writing, and it exists
// so that the tool cannot emit an index it would itself refuse to read: after
// assembling the fields, Build runs the same validate that LoadVerified runs
// on the way back in. An asymmetry between what a writer emits and what a
// reader accepts is where evasion lives — a check that trusted its own output
// unconditionally would have no way to notice that output had drifted from
// the shape its own reader enforces. See the false-negative note on the
// caller in internal/cli/index.go.
//
// src must already carry every field the caller intends to record, BuiltAt
// included: Build stamps nothing but SchemaVersion, so a test can inject a
// fixed Source and get byte-identical output across runs.
func Build(ctx context.Context, fsys fs.FS, src Source, pkgs []Package) (*Index, error) {
	aliases, err := BuildAliases(ctx, fsys)
	if err != nil {
		return nil, fmt.Errorf("index: build: %w", err)
	}

	idx := &Index{
		SchemaVersion: SchemaVersion,
		Source:        src,
		Aliases:       aliases,
		Packages:      pkgs,
	}

	if err := validate(idx); err != nil {
		return nil, fmt.Errorf("index: build: %w", err)
	}

	return idx, nil
}
