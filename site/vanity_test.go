// Package site holds the static content served from cruthu.dev, including the
// module-resolution pages that make `go get cruthu.dev/core` work.
//
// It contains no Go code — only these tests, which pin the one property that
// nothing else can catch: that the go-import tags on disk agree with the module
// path in go.mod. A wrong repository URL in a go-import tag redirects every
// `go get` to code we did not write, and it does so silently, on our users'
// machines rather than in our CI. So the check runs offline, on every
// `make test`, and fails closed.
//
// See docs/decisions/0004-module-path-and-domain.md.
package site

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// vanityModules is the set of module paths this site is responsible for
// resolving. It is the spec: every entry must have a page whose go-import tag
// matches, and the module path declared in go.mod must appear here.
//
// Adding a module means adding a row here, a page, and a row in the table in
// functions/core/[[path]].js. All three are compared below, so a partial
// addition fails rather than half-working.
var vanityModules = []struct {
	name string
	// modulePath is the import path users type. It must equal the first field
	// of the page's go-import tag.
	modulePath string
	// page is the file, relative to this directory, that serves the tag for the
	// exact module root. This is the URL proxy.golang.org fetches.
	page string
	// repo is the backing repository. Deliberately unrelated to the module
	// path: that indirection is the entire point of a vanity path.
	repo string
}{
	{
		name:       "open-source core",
		modulePath: "cruthu.dev/core",
		page:       "core/index.html",
		repo:       "https://github.com/cruthu/cruthu",
	},
}

// goImport is a parsed go-import meta tag: the three space-separated fields the
// go command reads to resolve a module path.
type goImport struct {
	modulePath string
	vcs        string
	repo       string
}

var (
	goImportRE = regexp.MustCompile(`<meta\s+name="go-import"\s+content="([^"]*)"\s*/?>`)
	goSourceRE = regexp.MustCompile(`<meta\s+name="go-source"\s+content="([^"]*)"\s*/?>`)
	// jsTableRE reads the allowlist out of the wildcard handler. The markers
	// keep the match anchored to the table rather than to any string elsewhere
	// in the file; if the format is reformatted past recognition the tests fail
	// loudly, which is the correct outcome for a file this load-bearing.
	jsTableRE  = regexp.MustCompile(`(?s)VANITY-TABLE-BEGIN(.*?)VANITY-TABLE-END`)
	jsEntryRE  = regexp.MustCompile(`"([^"]+)":\s*"([^"]+)"`)
	goModuleRE = regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)

	wildcardJS = filepath.Join("functions", "core", "[[path]].js")
	goModPath  = filepath.Join("..", "go.mod")
)

// parseGoImport extracts the single go-import tag from an HTML document. It is
// an error for a document to carry none, or more than one: a resolution page
// serves exactly one module path, and a second tag would mean two answers to
// the question of where the code lives.
func parseGoImport(doc string) (goImport, error) {
	matches := goImportRE.FindAllStringSubmatch(doc, -1)
	switch {
	case len(matches) == 0:
		return goImport{}, errNoTag
	case len(matches) > 1:
		return goImport{}, errMultipleTags
	}

	fields := strings.Fields(matches[0][1])
	if len(fields) != 3 {
		return goImport{}, errFieldCount
	}

	return goImport{modulePath: fields[0], vcs: fields[1], repo: fields[2]}, nil
}

type tagError string

func (e tagError) Error() string { return string(e) }

const (
	errNoTag        = tagError("no go-import meta tag found")
	errMultipleTags = tagError("multiple go-import meta tags found")
	errFieldCount   = tagError("go-import content must have exactly three fields")
)

// moduleFromGoMod reads the module path out of the repository's go.mod. This is
// the authority every other check compares against.
func moduleFromGoMod(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	m := goModuleRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no module line in go.mod")
	}

	return string(m[1])
}

func TestParseGoImport(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    goImport
		wantErr error
	}{
		{
			name: "well formed",
			doc:  `<meta name="go-import" content="cruthu.dev/core git https://example.test/r">`,
			want: goImport{"cruthu.dev/core", "git", "https://example.test/r"},
		},
		{
			name: "self closing with extra whitespace",
			doc:  `<meta  name="go-import"   content="a git https://b" />`,
			want: goImport{"a", "git", "https://b"},
		},
		{
			name: "prose mentioning the tag name is not a tag",
			doc:  `<p>the go-import tag below</p><meta name="go-import" content="a git https://b">`,
			want: goImport{"a", "git", "https://b"},
		},
		{
			name:    "no tag",
			doc:     `<html><head><title>nothing</title></head></html>`,
			wantErr: errNoTag,
		},
		{
			name: "two tags",
			doc: `<meta name="go-import" content="a git https://b">` +
				`<meta name="go-import" content="c git https://d">`,
			wantErr: errMultipleTags,
		},
		{
			name:    "too few fields",
			doc:     `<meta name="go-import" content="cruthu.dev/core git">`,
			wantErr: errFieldCount,
		},
		{
			name:    "too many fields",
			doc:     `<meta name="go-import" content="a git https://b extra">`,
			wantErr: errFieldCount,
		},
		{
			name:    "empty content",
			doc:     `<meta name="go-import" content="">`,
			wantErr: errFieldCount,
		},
		{
			name:    "go-source is not go-import",
			doc:     `<meta name="go-source" content="a https://b https://c https://d">`,
			wantErr: errNoTag,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGoImport(tc.doc)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("parseGoImport error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGoImport: unexpected error %v", err)
			}
			if got != tc.want {
				t.Errorf("parseGoImport = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestVanityPagesResolveCorrectly is the check that matters: the tag served to
// the go command names the module path go.mod declares, over git, at an https
// repository.
func TestVanityPagesResolveCorrectly(t *testing.T) {
	for _, tc := range vanityModules {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.page)
			if err != nil {
				t.Fatalf("read %s: %v", tc.page, err)
			}

			tag, err := parseGoImport(string(data))
			if err != nil {
				t.Fatalf("parse %s: %v", tc.page, err)
			}

			if tag.modulePath != tc.modulePath {
				t.Errorf("go-import module path = %q, want %q", tag.modulePath, tc.modulePath)
			}
			if tag.vcs != "git" {
				t.Errorf("go-import vcs = %q, want %q", tag.vcs, "git")
			}
			if tag.repo != tc.repo {
				t.Errorf("go-import repo = %q, want %q", tag.repo, tc.repo)
			}

			// A plain-http repository would have the go command fetch code over
			// a channel anyone on the path can rewrite.
			if !strings.HasPrefix(tag.repo, "https://") {
				t.Errorf("repo %q must be https", tag.repo)
			}

			// A repo URL pointing back at the vanity domain would make
			// resolution refer to itself instead of to a code host.
			if strings.Contains(tag.repo, "cruthu.dev") {
				t.Errorf("repo %q points at the vanity domain, not a code host", tag.repo)
			}
		})
	}
}

// TestGoModIsServed catches the case where go.mod's module path is renamed and
// the site is not updated with it, which would leave the advertised install
// command resolving to nothing.
func TestGoModIsServed(t *testing.T) {
	want := moduleFromGoMod(t)

	for _, tc := range vanityModules {
		if tc.modulePath == want {
			return
		}
	}

	t.Fatalf("go.mod declares module %q, but no vanity page serves it", want)
}

// TestGoSourceMatchesModulePath keeps the pkg.go.dev source links pointed at the
// same module the go-import tag resolves.
func TestGoSourceMatchesModulePath(t *testing.T) {
	for _, tc := range vanityModules {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.page)
			if err != nil {
				t.Fatalf("read %s: %v", tc.page, err)
			}

			m := goSourceRE.FindStringSubmatch(string(data))
			if m == nil {
				t.Skip("no go-source tag on this page")
			}

			fields := strings.Fields(m[1])
			if len(fields) != 4 {
				t.Fatalf("go-source content has %d fields, want 4", len(fields))
			}
			if fields[0] != tc.modulePath {
				t.Errorf("go-source module path = %q, want %q", fields[0], tc.modulePath)
			}
		})
	}
}

// TestWildcardTableMatchesPages compares the allowlist in the Cloudflare
// function against the static pages. The two are served by different mechanisms
// and could drift; a subpackage resolving to a different repository than the
// module root is exactly the kind of split-brain that would not show up until a
// user hit it.
func TestWildcardTableMatchesPages(t *testing.T) {
	data, err := os.ReadFile(wildcardJS)
	if err != nil {
		t.Fatalf("read %s: %v", wildcardJS, err)
	}

	region := jsTableRE.FindSubmatch(data)
	if region == nil {
		t.Fatalf("%s: no VANITY-TABLE markers found; the table format changed", wildcardJS)
	}

	got := make(map[string]string)
	for _, m := range jsEntryRE.FindAllStringSubmatch(string(region[1]), -1) {
		got[m[1]] = m[2]
	}

	if len(got) == 0 {
		t.Fatalf("%s: vanity table is empty", wildcardJS)
	}

	for _, tc := range vanityModules {
		repo, ok := got[tc.modulePath]
		if !ok {
			t.Errorf("%s: no entry for module %q", wildcardJS, tc.modulePath)
			continue
		}
		if repo != tc.repo {
			t.Errorf("%s: module %q maps to %q, want %q", wildcardJS, tc.modulePath, repo, tc.repo)
		}
	}

	// An extra entry is a module path we serve without a page or a test row for
	// it, which is a hole in the allowlist.
	for modulePath := range got {
		found := false
		for _, tc := range vanityModules {
			if tc.modulePath == modulePath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: serves module %q that no vanity page or test row declares",
				wildcardJS, modulePath)
		}
	}
}
