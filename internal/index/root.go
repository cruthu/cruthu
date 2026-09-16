package index

import (
	"fmt"
	"io/fs"
	"os"
)

// OpenRootfs opens dir as a filesystem confined to that directory, and returns
// it alongside a close function the caller must call.
//
// It uses os.OpenRoot rather than os.DirFS deliberately, and the distinction is
// a security boundary rather than a style preference. os.DirFS does not stop a
// symlink inside the tree from resolving outside it — its own documentation
// says that DirFS("/prefix").Open("file") is the same as os.Open("/prefix/file")
// — and an extracted image filesystem is attacker-controlled. Under os.DirFS an
// image carrying `etc/passwd -> ../../../../etc/passwd` would have cruthu read
// and index the host's file. os.Root refuses to traverse any symlink that
// leaves the root, and refuses absolute symlinks entirely.
//
// The returned fs.FS also implements fs.ReadLinkFS, which BuildAliases requires
// in order to read directory symlink targets without traversing them.
func OpenRootfs(dir string) (fs.FS, func() error, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("index: open rootfs %q: %w", dir, err)
	}
	return root.FS(), root.Close, nil
}
