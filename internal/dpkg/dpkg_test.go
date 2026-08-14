package dpkg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"cruthu.dev/core/internal/index"
)

// installed is the shortest status stanza this package accepts, as a helper so
// that each test case shows only the field it is exercising.
func installed(name, version, arch string, extra ...string) string {
	var b strings.Builder
	b.WriteString("Package: " + name + "\n")
	b.WriteString("Status: install ok installed\n")
	b.WriteString("Version: " + version + "\n")
	b.WriteString("Architecture: " + arch + "\n")
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	return b.String()
}

// rootfs builds an in-memory rootfs from a status file and a set of
// info/*.list files keyed by their base name.
func rootfs(status string, lists map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{statusPath: &fstest.MapFile{Data: []byte(status)}}
	for name, body := range lists {
		fsys[infoDir+"/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func TestBuild(t *testing.T) {
	tests := []struct {
		name   string
		status string
		lists  map[string]string
		want   []index.Package
	}{
		{
			name:   "one package with its declared paths",
			status: installed("dash", "0.5.12-2", "amd64"),
			lists:  map[string]string{"dash.list": "/.\n/bin\n/bin/dash\n/bin/sh\n"},
			want: []index.Package{{
				ID:      "deb:dash:amd64@0.5.12-2",
				Name:    "dash",
				Version: "0.5.12-2",
				Type:    "deb",
				Files:   []string{"/bin", "/bin/dash", "/bin/sh"},
			}},
		},
		{
			// dpkg arch-qualifies the list file for Multi-Arch: same packages
			// only. Reading the wrong name would mean no declared paths at all.
			name:   "Multi-Arch same reads the arch-qualified list",
			status: installed("libc6", "2.36-9", "amd64", "Multi-Arch: same"),
			lists:  map[string]string{"libc6:amd64.list": "/.\n/usr/lib/libc.so.6\n"},
			want: []index.Package{{
				ID:      "deb:libc6:amd64@2.36-9",
				Name:    "libc6",
				Version: "2.36-9",
				Type:    "deb",
				Files:   []string{"/usr/lib/libc.so.6"},
			}},
		},
		{
			name:   "Multi-Arch foreign reads the plain list",
			status: installed("bash", "5.2.15", "amd64", "Multi-Arch: foreign"),
			lists:  map[string]string{"bash.list": "/.\n/bin/bash\n"},
			want: []index.Package{{
				ID:      "deb:bash:amd64@5.2.15",
				Name:    "bash",
				Version: "5.2.15",
				Type:    "deb",
				Files:   []string{"/bin/bash"},
			}},
		},
		{
			// The status file legitimately retains stanzas for packages that
			// have been removed. Their files are gone, so declaring paths for
			// them would suppress drift on files the image does not own.
			name:   "a removed package is skipped, not rejected",
			status: installed("dash", "0.5.12-2", "amd64") + "\nPackage: nano\nStatus: deinstall ok config-files\nVersion: 7.2\nArchitecture: amd64\n",
			lists:  map[string]string{"dash.list": "/.\n/bin/dash\n"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
		{
			// A package mid-installation has files in an unknown condition.
			name:   "a half-installed package is skipped",
			status: installed("dash", "0.5.12-2", "amd64") + "\nPackage: nano\nStatus: install ok half-installed\nVersion: 7.2\nArchitecture: amd64\n",
			lists:  map[string]string{"dash.list": "/.\n/bin/dash\n"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
		{
			// An error flag means dpkg itself does not trust the package's
			// state on disk.
			name:   "a package in an error state is skipped",
			status: installed("dash", "0.5.12-2", "amd64") + "\nPackage: nano\nStatus: install reinstreq installed\nVersion: 7.2\nArchitecture: amd64\n",
			lists:  map[string]string{"dash.list": "/.\n/bin/dash\n"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
		{
			// A metapackage declares nothing but the root marker. An empty
			// file list is legitimate; a missing list file is not.
			name:   "a package declaring only the root marker yields no files",
			status: installed("build-essential", "12.9", "amd64"),
			lists:  map[string]string{"build-essential.list": "/.\n"},
			want: []index.Package{{
				ID: "deb:build-essential:amd64@12.9", Name: "build-essential",
				Version: "12.9", Type: "deb", Files: nil,
			}},
		},
		{
			name:   "duplicate declared paths are collapsed",
			status: installed("dash", "0.5.12-2", "amd64"),
			lists:  map[string]string{"dash.list": "/.\n/bin/dash\n/bin/dash\n/bin/dash\n"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
		{
			// Indexing one rootfs twice must produce byte-identical output, so
			// neither packages nor paths may arrive in database order.
			name:   "packages and paths are sorted",
			status: installed("zlib1g", "1.2.13", "amd64") + "\n" + installed("apt", "2.6.1", "amd64"),
			lists: map[string]string{
				"zlib1g.list": "/.\n/usr/lib/libz.so\n",
				"apt.list":    "/.\n/usr/bin/apt-get\n/usr/bin/apt\n",
			},
			want: []index.Package{
				{ID: "deb:apt:amd64@2.6.1", Name: "apt", Version: "2.6.1", Type: "deb",
					Files: []string{"/usr/bin/apt", "/usr/bin/apt-get"}},
				{ID: "deb:zlib1g:amd64@1.2.13", Name: "zlib1g", Version: "1.2.13", Type: "deb",
					Files: []string{"/usr/lib/libz.so"}},
			},
		},
		{
			// Description and Conffiles values are continuation lines. A
			// crafted one must not be read as a field, or a package could
			// restate its own Status from inside its description.
			name: "a continuation line is not read as a field",
			status: "Package: dash\n" +
				"Status: install ok installed\n" +
				"Version: 0.5.12-2\n" +
				"Architecture: amd64\n" +
				"Description: a shell\n" +
				" Package: evil\n" +
				" Status: install ok installed\n" +
				" Version: 9.9\n",
			lists: map[string]string{"dash.list": "/.\n/bin/dash\n"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
		{
			// The last stanza in a real status file has no trailing blank line.
			name:   "the final stanza needs no trailing blank line",
			status: strings.TrimSuffix(installed("dash", "0.5.12-2", "amd64"), "\n"),
			lists:  map[string]string{"dash.list": "/bin/dash"},
			want: []index.Package{{
				ID: "deb:dash:amd64@0.5.12-2", Name: "dash", Version: "0.5.12-2", Type: "deb",
				Files: []string{"/bin/dash"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Build(context.Background(), rootfs(tt.status, tt.lists))
			if err != nil {
				t.Fatalf("Build: unexpected error: %v", err)
			}
			assertPackages(t, got, tt.want)
		})
	}
}

func assertPackages(t *testing.T, got, want []index.Package) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.Name != w.Name || g.Version != w.Version || g.Type != w.Type {
			t.Errorf("package %d: got %+v, want %+v", i, g, w)
		}
		if len(g.Files) != len(w.Files) {
			t.Errorf("package %d (%s): got %d files %v, want %d %v", i, g.ID, len(g.Files), g.Files, len(w.Files), w.Files)
			continue
		}
		for j := range w.Files {
			if g.Files[j] != w.Files[j] {
				t.Errorf("package %d (%s) file %d: got %q, want %q", i, g.ID, j, g.Files[j], w.Files[j])
			}
		}
	}
}

// TestBuildRejects covers every path that returns an error. Each case is a
// database that cannot be interpreted unambiguously, and every one of them is
// ExitError rather than a partial index, because a partially read database
// cannot establish that an image is clean.
func TestBuildRejects(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		lists   map[string]string
		wantErr string
	}{
		{
			name:    "no status file",
			status:  "",
			wantErr: "open var/lib/dpkg/status",
		},
		{
			name:    "status file with no installed packages",
			status:  "Package: nano\nStatus: deinstall ok config-files\nVersion: 7.2\nArchitecture: amd64\n",
			wantErr: "declares no installed packages",
		},
		{
			name:    "stanza with no Status field",
			status:  "Package: dash\nVersion: 0.5.12-2\nArchitecture: amd64\n",
			wantErr: "has no Status field",
		},
		{
			// "unreadable" and "not installed" have opposite consequences, so a
			// Status this parser cannot read is refused rather than assumed.
			name:    "malformed Status field",
			status:  "Package: dash\nStatus: installed\nVersion: 0.5.12-2\nArchitecture: amd64\n",
			wantErr: "malformed Status",
		},
		{
			name:    "installed stanza with no Version",
			status:  "Package: dash\nStatus: install ok installed\nArchitecture: amd64\n",
			wantErr: "has no Version field",
		},
		{
			name:    "installed stanza with no Architecture",
			status:  "Package: dash\nStatus: install ok installed\nVersion: 0.5.12-2\n",
			wantErr: "has no Architecture field",
		},
		{
			name:    "installed stanza with no Package name",
			status:  "Status: install ok installed\nVersion: 0.5.12-2\nArchitecture: amd64\n",
			wantErr: "has no Package field",
		},
		{
			// Last-wins to this parser and first-wins to a reviewer skimming
			// the file is how a package hides its real version.
			name:    "duplicate field in one stanza",
			status:  "Package: dash\nPackage: evil\nStatus: install ok installed\nVersion: 0.5.12-2\nArchitecture: amd64\n",
			wantErr: `field "Package" appears twice`,
		},
		{
			name:    "line that is not a field",
			status:  "Package: dash\nthis is not a field\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n",
			wantErr: "line is not a field",
		},
		{
			// A name used to build a path is checked where it enters.
			name:    "package name containing a path separator",
			status:  installed("../../etc/shadow", "1", "amd64"),
			wantErr: "contains a path or architecture separator",
		},
		{
			name:    "package name containing a colon",
			status:  installed("libc6:amd64", "1", "amd64"),
			wantErr: "contains a path or architecture separator",
		},
		{
			name:    "package name that is a directory",
			status:  installed("..", "1", "amd64"),
			wantErr: "names a directory rather than a package",
		},
		{
			name:    "architecture containing a path separator",
			status:  installed("dash", "1", "../.."),
			wantErr: "contains a path or architecture separator",
		},
		{
			// A newline in a field forges a line of the table reporter's
			// output, and a reader cannot tell it was forged.
			name:    "control byte in a version",
			status:  installed("dash", "1\x00evil", "amd64"),
			wantErr: "control byte",
		},
		{
			// Two packages with one ID make ownership depend on stanza order.
			name:    "duplicate package identity",
			status:  installed("dash", "1", "amd64") + "\n" + installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/bin/dash\n"},
			wantErr: "is declared twice",
		},
		{
			// dpkg writes a list for every unpacked package. Treating a
			// missing one as "declares nothing" would mark every file the
			// package owns as unowned.
			name:    "installed package with no list file",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{},
			wantErr: "open var/lib/dpkg/info/dash.list",
		},
		{
			name:    "Multi-Arch same with only a plain list file",
			status:  installed("libc6", "1", "amd64", "Multi-Arch: same"),
			lists:   map[string]string{"libc6.list": "/.\n/usr/lib/libc.so.6\n"},
			wantErr: "open var/lib/dpkg/info/libc6:amd64.list",
		},
		{
			name:    "declared path that is not absolute",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\nusr/bin/dash\n"},
			wantErr: "is not absolute",
		},
		{
			// path.Clean would turn this into /tmp/miner, so the string a
			// reviewer reads and the path the tool indexes would differ.
			name:    "declared path with traversal components",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/usr/bin/../../tmp/miner\n"},
			wantErr: "is not in cleaned form",
		},
		{
			name:    "declared path with a trailing slash",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/usr/bin/\n"},
			wantErr: "is not in cleaned form",
		},
		{
			name:    "declared path with a doubled slash",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/usr//bin/dash\n"},
			wantErr: "is not in cleaned form",
		},
		{
			name:    "empty declared path",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n\n/bin/dash\n"},
			wantErr: "empty path",
		},
		{
			// Found by FuzzBuild. "/" survives path.Clean, so it would become a
			// live key in the owner map, and an observed path of "/" or "/.."
			// cleans to exactly that key — an event whose path field collapsed
			// to the root would resolve to a real package and report clean.
			name:    "declared path that is the filesystem root",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/\n/bin/dash\n"},
			wantErr: "path is the filesystem root",
		},
		{
			// "/.." also cleans to "/", so the check cannot be a string
			// comparison against the raw line.
			name:    "declared path that traverses above the root",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/..\n"},
			wantErr: "is not in cleaned form",
		},
		{
			name:    "declared path with a control byte",
			status:  installed("dash", "1", "amd64"),
			lists:   map[string]string{"dash.list": "/.\n/bin/da\x00sh\n"},
			wantErr: "control byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := rootfs(tt.status, tt.lists)
			if tt.status == "" {
				delete(fsys, statusPath)
			}

			got, err := Build(context.Background(), fsys)
			if err == nil {
				t.Fatalf("Build: want error containing %q, got %d packages", tt.wantErr, len(got))
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Build: got error %q, want it to contain %q", err, tt.wantErr)
			}
			if got != nil {
				t.Errorf("Build: returned %d packages alongside an error; a rejected database must yield nothing", len(got))
			}
		})
	}
}

// TestBuildBounds exercises each cap at its boundary. Every one of these bounds
// a quantity taken from an attacker-controlled filesystem.
func TestBuildBounds(t *testing.T) {
	t.Run("a status line longer than the cap is refused", func(t *testing.T) {
		long := "Description: " + strings.Repeat("a", maxStatusLineBytes)
		fsys := rootfs(installed("dash", "1", "amd64", long), map[string]string{"dash.list": "/.\n/bin/dash\n"})

		_, err := Build(context.Background(), fsys)
		if err == nil || !strings.Contains(err.Error(), "line longer than") {
			t.Fatalf("want a line-length error, got %v", err)
		}
	})

	t.Run("a declared path longer than the cap is refused", func(t *testing.T) {
		long := "/" + strings.Repeat("a", maxPathBytes)
		fsys := rootfs(installed("dash", "1", "amd64"), map[string]string{"dash.list": "/.\n" + long + "\n"})

		_, err := Build(context.Background(), fsys)
		if err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Fatalf("want a path-length error, got %v", err)
		}
	})

	t.Run("a path at exactly the cap is accepted", func(t *testing.T) {
		// The boundary itself must pass, or the cap is off by one and rejects
		// a path the kernel would allow.
		p := "/" + strings.Repeat("a", maxPathBytes-1)
		fsys := rootfs(installed("dash", "1", "amd64"), map[string]string{"dash.list": "/.\n" + p + "\n"})

		got, err := Build(context.Background(), fsys)
		if err != nil {
			t.Fatalf("Build: unexpected error: %v", err)
		}
		if len(got) != 1 || len(got[0].Files) != 1 || got[0].Files[0] != p {
			t.Fatalf("want the boundary path accepted, got %+v", got)
		}
	})
}

func TestBuildHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fsys := rootfs(installed("dash", "1", "amd64"), map[string]string{"dash.list": "/.\n/bin/dash\n"})

	_, err := Build(ctx, fsys)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// TestDeclaredPathsResolveThroughTheAliasTable is the property the whole
// pipeline turns on, and it is asserted here rather than only in internal/index
// because this package produces one of the two sides.
//
// Measured on debian:bookworm, dpkg declares /bin/ls while the kernel reports
// an exec of it as /usr/bin/ls: the merged-/usr symlink is resolved before
// Tetragon ever sees the path. So the declared side is the side that needs
// rewriting, which is the opposite of the example in ADR 0002. If either side
// stopped being normalized, every binary on a Debian image would report as
// unowned.
func TestDeclaredPathsResolveThroughTheAliasTable(t *testing.T) {
	fsys := rootfs(
		installed("coreutils", "9.1-1", "amd64"),
		map[string]string{"coreutils.list": "/.\n/bin/ls\n"},
	)

	pkgs, err := Build(context.Background(), fsys)
	if err != nil {
		t.Fatalf("Build: unexpected error: %v", err)
	}

	lk, err := index.NewLookup(&index.Index{
		Aliases:  []index.Alias{{From: "/bin", To: "/usr/bin"}},
		Packages: pkgs,
	})
	if err != nil {
		t.Fatalf("NewLookup: unexpected error: %v", err)
	}

	tests := []struct {
		observed string
		want     bool
		why      string
	}{
		{"/usr/bin/ls", true, "the spelling a sensor actually reports, after the kernel resolved /bin"},
		{"/bin/ls", true, "the spelling dpkg declares, in case a sensor reports it unresolved"},
		{"/tmp/ls", false, "a binary dropped under a real package file's name is still drift"},
		{"/tmp/kdevtmpfsi", false, "the obvious case, which would pass even with normalization broken"},
		{"/usr/bin/lsof", false, "a path that shares a prefix with a declared one is not declared"},
	}

	for _, tt := range tests {
		t.Run(tt.observed, func(t *testing.T) {
			if _, ok := lk.Owner(tt.observed); ok != tt.want {
				t.Errorf("Owner(%q) = %v, want %v: %s", tt.observed, ok, tt.want, tt.why)
			}
		})
	}
}
