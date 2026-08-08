// Command cruthu reconciles a container's build-time SBOM against what it
// actually executed at runtime.
//
// The binary is a thin shell: all behavior lives in internal/cli so that the
// command tree can be exercised in-process by tests, which matters most for
// the exit-code contract that CI pipelines gate on.
package main

import (
	"os"

	"cruthu.dev/core/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
