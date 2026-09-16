package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"cruthu.dev/core/internal/dpkg"
	"cruthu.dev/core/internal/index"
)

// newIndexCommand builds `cruthu index`, which reads a container rootfs and
// writes the file-to-package index that `cruthu check` will later reconcile
// against runtime events.
//
// It classifies nothing and so can never return a *DriftError: every failure
// here is ExitError, including a rootfs with no package database, which is an
// error rather than an empty index.
func newIndexCommand(out io.Writer) *cobra.Command {
	var rootfsDir string
	var digest string
	var outPath string

	cmd := &cobra.Command{
		Use:   "index",
		Short: "Build a file-to-package index from a container rootfs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIndex(cmd.Context(), out, indexOptions{
				rootfsDir: rootfsDir,
				digest:    digest,
				outPath:   outPath,
			})
		},
	}

	cmd.Flags().StringVar(&rootfsDir, "rootfs", "", "path to an extracted container rootfs (required; image references are not supported yet)")
	cmd.Flags().StringVar(&digest, "digest", "", "image digest to record as provenance, sha256:<64 lowercase hex characters>")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write the index here instead of stdout")

	return cmd
}

type indexOptions struct {
	rootfsDir string
	digest    string
	outPath   string
}

func runIndex(ctx context.Context, out io.Writer, opts indexOptions) error {
	if opts.rootfsDir == "" {
		return fmt.Errorf("cruthu index: --rootfs is required (image references are not supported yet)")
	}

	fsys, closeFn, err := index.OpenRootfs(opts.rootfsDir)
	if err != nil {
		return fmt.Errorf("cruthu index: %w", err)
	}
	defer closeFn() //nolint:errcheck // read-only; a close error cannot affect what was already read

	pkgs, err := dpkg.Build(ctx, fsys)
	if err != nil {
		return fmt.Errorf("cruthu index: %w", err)
	}

	src := index.Source{
		Kind:      "rootfs",
		Reference: opts.rootfsDir,
		Digest:    opts.digest,
		BuiltAt:   time.Now().UTC(),
	}

	idx, err := index.Build(ctx, fsys, src, pkgs)
	if err != nil {
		return fmt.Errorf("cruthu index: %w", err)
	}

	if opts.outPath == "" {
		if err := index.WriteJSON(out, idx); err != nil {
			return fmt.Errorf("cruthu index: %w", err)
		}
		return nil
	}

	return writeIndexAtomically(opts.outPath, idx)
}

// writeIndexAtomically writes idx to a temp file beside outPath and renames it
// into place, so a process killed mid-write never leaves a half-written index
// at outPath for a later `cruthu check` to load.
func writeIndexAtomically(outPath string, idx *index.Index) error {
	dir := filepath.Dir(outPath)

	tmp, err := os.CreateTemp(dir, ".cruthu-index-*.tmp")
	if err != nil {
		return fmt.Errorf("cruthu index: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Removed on every path out of this function; once os.Rename below has
	// succeeded there is nothing left at tmpPath, so this is a harmless no-op
	// rather than a hazard on the success path.
	defer os.Remove(tmpPath)

	if err := index.WriteJSON(tmp, idx); err != nil {
		tmp.Close()
		return fmt.Errorf("cruthu index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cruthu index: close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("cruthu index: write %q: %w", outPath, err)
	}
	return nil
}
