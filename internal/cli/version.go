package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// version is overridable at link time for release builds:
//
//	go build -ldflags "-X cruthu.dev/core/internal/cli.version=0.1.0"
//
// When it is left at its default, buildVersion falls back to the module
// version recorded by the Go toolchain, which is what `go install` produces.
var version = ""

// buildInfo describes the running binary. Every field is best-effort: a binary
// built without VCS stamping still reports something useful rather than
// failing.
type buildInfo struct {
	Version  string
	Revision string
	Modified bool
	GoVer    string
	Platform string
}

func currentBuild() buildInfo {
	b := buildInfo{
		Version:  version,
		GoVer:    runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		if b.Version == "" {
			b.Version = "unknown"
		}
		return b
	}

	if b.Version == "" {
		// "(devel)" is what the toolchain reports for an untagged build.
		if v := info.Main.Version; v != "" && v != "(devel)" {
			b.Version = v
		} else {
			b.Version = "devel"
		}
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Revision = s.Value
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}

	return b
}

// String renders the version line. The dirty marker is not cosmetic: a binary
// built from a modified tree cannot be tied back to reviewed source, which
// matters for a tool whose output is meant to be evidence.
func (b buildInfo) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "cruthu %s", b.Version)

	if b.Revision != "" {
		rev := b.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		fmt.Fprintf(&sb, " (%s", rev)
		if b.Modified {
			sb.WriteString(", dirty")
		}
		sb.WriteString(")")
	}

	fmt.Fprintf(&sb, " %s %s", b.GoVer, b.Platform)

	return sb.String()
}
