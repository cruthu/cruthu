package index

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenRootfsConfinesSymlinkEscape is the reason OpenRootfs exists. An
// extracted image filesystem is attacker-controlled, and os.DirFS would happily
// follow this link onto the host.
func TestOpenRootfsConfinesSymlinkEscape(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("host-only"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	rootfs := t.TempDir()
	if err := os.Symlink(secret, filepath.Join(rootfs, "escape")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	fsys, closeFn, err := OpenRootfs(rootfs)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	if got, err := fs.ReadFile(fsys, "escape"); err == nil {
		t.Fatalf("read through escaping symlink succeeded with %q; the root is not confined", got)
	}
}

func TestOpenRootfsConfinesParentTraversal(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	if err := os.Symlink("../../../etc", filepath.Join(rootfs, "up")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	fsys, closeFn, err := OpenRootfs(rootfs)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	if _, err := fs.Stat(fsys, "up"); err == nil {
		t.Fatal("stat through ../.. symlink succeeded; the root is not confined")
	}
}

func TestOpenRootfsReadsLinks(t *testing.T) {
	t.Parallel()

	// BuildAliases depends on this; if the returned FS ever stops implementing
	// fs.ReadLinkFS, alias discovery silently returns an error instead.
	rootfs := t.TempDir()

	fsys, closeFn, err := OpenRootfs(rootfs)
	if err != nil {
		t.Fatalf("OpenRootfs: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := closeFn(); closeErr != nil {
			t.Errorf("close rootfs: %v", closeErr)
		}
	})

	if _, ok := fsys.(fs.ReadLinkFS); !ok {
		t.Fatal("OpenRootfs returned a filesystem that cannot read symlinks")
	}
}

func TestOpenRootfsMissingDirectory(t *testing.T) {
	t.Parallel()

	if _, _, err := OpenRootfs(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("OpenRootfs on a missing directory returned no error")
	}
}
