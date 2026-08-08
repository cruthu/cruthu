// Package cli implements the cruthu command tree.
//
// Commands are constructed rather than declared as package-level variables so
// that each invocation gets fresh state. Tests build a command tree per case
// and assert on the exit code and streams, which is the contract users depend
// on.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const rootLong = `cruthu reconciles a container's build-time SBOM against what it actually
executed at runtime.

An SBOM is a contract written at build time. Runtime is reality. cruthu reports
the difference between them: binaries and libraries that ran but were never
declared, and declared packages that never loaded.`

// NewRootCommand builds the cruthu command tree, writing all output to out and
// err rather than to the process streams directly.
func NewRootCommand(out, errOut io.Writer) *cobra.Command {
	var showVersion bool

	cmd := &cobra.Command{
		Use:   "cruthu",
		Short: "Verify that what's running in your container is what the SBOM says was built",
		Long:  rootLong,

		// cruthu owns its exit codes and its error formatting, so cobra must
		// not print or re-interpret either. Without these, a runtime failure
		// prints a full usage dump, which buries the actual message.
		SilenceErrors: true,
		SilenceUsage:  true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(out, currentBuild())
				return nil
			}
			return cmd.Help()
		},
	}

	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.Flags().BoolVar(&showVersion, "version", false, "print version information and exit")

	cmd.AddCommand(newVersionCommand(out))

	return cmd
}

func newVersionCommand(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(out, currentBuild())
			return nil
		},
	}
}

// Main runs the command tree and returns the process exit code.
func Main(args []string, out, errOut io.Writer) int {
	return run(NewRootCommand(out, errOut), args, errOut)
}

// run executes cmd and maps its outcome onto an exit code. It never panics out
// to the caller: an unexpected panic anywhere in the tree becomes ExitError,
// because a pipeline must not read a crashed drift detector as a drift
// detector that found nothing.
func run(cmd *cobra.Command, args []string, errOut io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "cruthu: internal error: %v\n", r)
			code = ExitError
		}
	}()

	cmd.SetArgs(args)

	err := cmd.Execute()
	if err != nil {
		var drift *DriftError
		if errors.As(err, &drift) {
			fmt.Fprintln(errOut, drift.Summary)
		} else {
			fmt.Fprintf(errOut, "cruthu: %v\n", err)
		}
	}

	return exitCodeFor(err)
}
