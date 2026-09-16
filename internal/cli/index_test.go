package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isRoot reports whether the test process can bypass file permission bits, so
// a permission-denied fixture can be skipped rather than silently passing for
// the wrong reason under a root-run CI container.
func isRoot() bool {
	return os.Geteuid() == 0
}

// validRootfs builds the minimal merged-/usr rootfs with one installed dpkg
// package that `cruthu index` is meant to read: a real symlink for
// index.BuildAliases to discover, and a real dpkg database for dpkg.Build to
// parse.
func validRootfs(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for _, d := range []string{"usr/bin", "var/lib/dpkg/info"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/bin/sh"), []byte("elf"), 0o755); err != nil {
		t.Fatalf("write usr/bin/sh: %v", err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatalf("symlink bin: %v", err)
	}

	status := "Package: sh\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/sh.list"), []byte("/.\n/usr/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("write sh.list: %v", err)
	}

	return root
}

func TestIndex_BuildsAndWritesToStdout(t *testing.T) {
	t.Parallel()

	root := validRootfs(t)

	var stdout, stderr bytes.Buffer
	code := Main([]string{"index", "--rootfs", root}, &stdout, &stderr)

	if code != ExitClean {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitClean, stderr.String())
	}

	var got struct {
		SchemaVersion string `json:"schemaVersion"`
		Aliases       []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"aliases"`
		Packages []struct {
			ID string `json:"id"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout did not parse as an index: %v\nstdout: %s", err, stdout.String())
	}

	if got.SchemaVersion != "cruthu.dev/index/v0" {
		t.Errorf("schemaVersion = %q, want cruthu.dev/index/v0", got.SchemaVersion)
	}
	if len(got.Packages) != 1 {
		t.Errorf("packages = %d, want 1", len(got.Packages))
	}
	if len(got.Aliases) != 1 || got.Aliases[0].From != "/bin" || got.Aliases[0].To != "/usr/bin" {
		t.Errorf("aliases = %v, want a single /bin -> /usr/bin alias", got.Aliases)
	}
}

func TestIndex_WritesToFileAtomically(t *testing.T) {
	t.Parallel()

	root := validRootfs(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "index.json")

	var stdout, stderr bytes.Buffer
	code := Main([]string{"index", "--rootfs", root, "-o", outPath}, &stdout, &stderr)

	if code != ExitClean {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitClean, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty when -o is given", stdout.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	if !bytes.Contains(data, []byte("cruthu.dev/index/v0")) {
		t.Errorf("output file does not look like an index: %s", data)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "index.json" {
			t.Errorf("leftover file in output directory: %s (atomic write left debris)", e.Name())
		}
	}
}

// TestIndex_OutputDirectoryNotWritable exercises a real permission-denied
// directory rather than only a missing one. Skipped under a root-run test
// process, since root bypasses the permission bits this test relies on.
func TestIndex_OutputDirectoryNotWritable(t *testing.T) {
	t.Parallel()
	if isRoot() {
		t.Skip("running as root, which bypasses the permission bits this test relies on")
	}

	root := validRootfs(t)
	outDir := t.TempDir()
	if err := os.Chmod(outDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(outDir, 0o700); err != nil {
			t.Errorf("restore permissions: %v", err)
		}
	})

	var stdout, stderr bytes.Buffer
	code := Main([]string{"index", "--rootfs", root, "-o", filepath.Join(outDir, "index.json")}, &stdout, &stderr)

	if code != ExitError {
		t.Errorf("exit code = %d, want %d (stderr: %s)", code, ExitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "cruthu index:") {
		t.Errorf("stderr = %q, want it to report the write failure", stderr.String())
	}
}

func TestIndex_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       func(t *testing.T) []string
		wantStderr string
	}{
		{
			name: "--rootfs missing",
			args: func(t *testing.T) []string {
				return []string{"index"}
			},
			wantStderr: "--rootfs is required",
		},
		{
			name: "--rootfs points at a nonexistent directory",
			args: func(t *testing.T) []string {
				return []string{"index", "--rootfs", filepath.Join(t.TempDir(), "does-not-exist")}
			},
			wantStderr: "cruthu index:",
		},
		{
			name: "--rootfs points at a regular file",
			args: func(t *testing.T) []string {
				f := filepath.Join(t.TempDir(), "not-a-dir")
				if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
					t.Fatalf("write: %v", err)
				}
				return []string{"index", "--rootfs", f}
			},
			wantStderr: "cruthu index:",
		},
		{
			name: "rootfs has no dpkg database",
			args: func(t *testing.T) []string {
				return []string{"index", "--rootfs", t.TempDir()}
			},
			wantStderr: "cruthu index:",
		},
		{
			name: "rootfs has a malformed dpkg database",
			args: func(t *testing.T) []string {
				root := validRootfs(t)
				// A second stanza for the same package: dpkg.Build refuses a
				// database that cannot say unambiguously who owns a file.
				status, err := os.ReadFile(filepath.Join(root, "var/lib/dpkg/status"))
				if err != nil {
					t.Fatalf("read status: %v", err)
				}
				dup := string(status) + "\n" + string(status)
				if err := os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte(dup), 0o644); err != nil {
					t.Fatalf("write status: %v", err)
				}
				return []string{"index", "--rootfs", root}
			},
			wantStderr: "cruthu index:",
		},
		{
			name: "--digest is not sha256 plus 64 lowercase hex",
			args: func(t *testing.T) []string {
				return []string{"index", "--rootfs", validRootfs(t), "--digest", "sha256:not-hex"}
			},
			wantStderr: "cruthu index:",
		},
		{
			name: "-o's directory does not exist",
			args: func(t *testing.T) []string {
				return []string{"index", "--rootfs", validRootfs(t), "-o", filepath.Join(t.TempDir(), "missing", "index.json")}
			},
			wantStderr: "cruthu index:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := Main(tt.args(t), &stdout, &stderr)

			if code != ExitError {
				t.Errorf("exit code = %d, want %d (stdout: %s, stderr: %s)", code, ExitError, stdout.String(), stderr.String())
			}
			if code == ExitClean {
				t.Fatalf("index reported success on a hostile/broken input")
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
