package cli

import (
	"strings"
	"testing"
)

func TestBuildInfoString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		info     buildInfo
		want     []string // substrings that must appear
		wantNot  []string // substrings that must not appear
		wantHead string
	}{
		{
			name: "release build",
			info: buildInfo{
				Version:  "0.1.0",
				Revision: "abcdef0123456789abcdef",
				GoVer:    "go1.23.0",
				Platform: "linux/amd64",
			},
			want:     []string{"cruthu 0.1.0", "abcdef012345", "go1.23.0", "linux/amd64"},
			wantNot:  []string{"dirty"},
			wantHead: "cruthu 0.1.0",
		},
		{
			name: "revision is truncated to twelve characters",
			info: buildInfo{
				Version:  "0.1.0",
				Revision: "abcdef0123456789abcdef",
				GoVer:    "go1.23.0",
				Platform: "linux/amd64",
			},
			// The full revision must not appear; only the short form.
			wantNot: []string{"abcdef0123456789abcdef"},
			want:    []string{"(abcdef012345)"},
		},
		{
			name: "short revision is left intact",
			info: buildInfo{
				Version:  "0.1.0",
				Revision: "abc123",
				GoVer:    "go1.23.0",
				Platform: "linux/amd64",
			},
			want: []string{"(abc123)"},
		},
		{
			// A binary built from a modified tree cannot be tied back to
			// reviewed source. For a tool whose output is evidence, saying so
			// is not cosmetic.
			name: "dirty tree is marked",
			info: buildInfo{
				Version:  "0.1.0",
				Revision: "abc123",
				Modified: true,
				GoVer:    "go1.23.0",
				Platform: "linux/amd64",
			},
			want: []string{"dirty"},
		},
		{
			name: "missing revision omits the parenthetical entirely",
			info: buildInfo{
				Version:  "devel",
				GoVer:    "go1.23.0",
				Platform: "linux/amd64",
			},
			want:    []string{"cruthu devel", "go1.23.0"},
			wantNot: []string{"(", ")"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.info.String()

			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("String() = %q, want substring %q", got, want)
				}
			}
			for _, notWant := range tt.wantNot {
				if strings.Contains(got, notWant) {
					t.Errorf("String() = %q, want it to omit %q", got, notWant)
				}
			}
			if tt.wantHead != "" && !strings.HasPrefix(got, tt.wantHead) {
				t.Errorf("String() = %q, want prefix %q", got, tt.wantHead)
			}
		})
	}
}

// currentBuild must always produce something printable, even when the binary
// carries no VCS stamping and no link-time version.
func TestCurrentBuildAlwaysReportsAVersion(t *testing.T) {
	t.Parallel()

	got := currentBuild()

	if got.Version == "" {
		t.Error("Version is empty; --version would print a bare 'cruthu'")
	}
	if got.GoVer == "" {
		t.Error("GoVer is empty")
	}
	if got.Platform == "" || !strings.Contains(got.Platform, "/") {
		t.Errorf("Platform = %q, want GOOS/GOARCH", got.Platform)
	}
	if !strings.HasPrefix(got.String(), "cruthu ") {
		t.Errorf("String() = %q, want it to start with the binary name", got.String())
	}
}
