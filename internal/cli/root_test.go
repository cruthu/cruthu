package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMain_ExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		wantCode    int
		wantStdout  string // substring
		wantStderr  string // substring
		wantNoUsage bool
	}{
		{
			name:       "version flag prints version and exits clean",
			args:       []string{"--version"},
			wantCode:   ExitClean,
			wantStdout: "cruthu ",
		},
		{
			name:       "version subcommand prints version and exits clean",
			args:       []string{"version"},
			wantCode:   ExitClean,
			wantStdout: "cruthu ",
		},
		{
			name:       "bare invocation prints help and exits clean",
			args:       []string{},
			wantCode:   ExitClean,
			wantStdout: "Usage:",
		},
		{
			name:        "unknown command is a tool error, not a drift result",
			args:        []string{"definitely-not-a-command"},
			wantCode:    ExitError,
			wantStderr:  "unknown command",
			wantNoUsage: true,
		},
		{
			name:       "unknown flag is a tool error",
			args:       []string{"--not-a-flag"},
			wantCode:   ExitError,
			wantStderr: "unknown flag",
		},
		{
			name:       "version subcommand rejects arguments",
			args:       []string{"version", "extra"},
			wantCode:   ExitError,
			wantStderr: "cruthu:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			code := Main(tt.args, &stdout, &stderr)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr.String())
			}
			if tt.wantStdout != "" && !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantNoUsage && strings.Contains(stderr.String(), "Usage:") {
				t.Errorf("stderr dumped usage, burying the message: %q", stderr.String())
			}
		})
	}
}

// A panic anywhere in a command must surface as ExitError. If it escaped as a
// crash the process would still exit nonzero, but the recovery keeps the exit
// code inside the documented contract rather than leaving it to the runtime.
func TestRun_RecoversPanicAsToolError(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{
		Use:           "boom",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			panic("parser exploded on hostile input")
		},
	}

	var stderr bytes.Buffer
	code := run(cmd, nil, &stderr)

	if code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "internal error") {
		t.Errorf("stderr = %q, want it to report an internal error", stderr.String())
	}
	if !strings.Contains(stderr.String(), "parser exploded") {
		t.Errorf("stderr = %q, want it to include the panic value", stderr.String())
	}
}

// A command reporting drift exits 1 and prints its summary without the
// "cruthu:" error prefix, because drift is a result rather than a failure.
func TestRun_DriftErrorExitsOneWithoutErrorPrefix(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{
		Use:           "check",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return &DriftError{Summary: "1 critical finding: /tmp/kdevtmpfsi"}
		},
	}

	var stderr bytes.Buffer
	code := run(cmd, nil, &stderr)

	if code != ExitDrift {
		t.Errorf("exit code = %d, want %d", code, ExitDrift)
	}
	if got := stderr.String(); !strings.Contains(got, "/tmp/kdevtmpfsi") {
		t.Errorf("stderr = %q, want the drift summary", got)
	}
	if strings.Contains(stderr.String(), "cruthu:") {
		t.Errorf("drift summary was formatted as a tool error: %q", stderr.String())
	}
}

func TestRun_PlainErrorExitsTwo(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{
		Use:           "check",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("index: unsupported schema version")
		},
	}

	var stderr bytes.Buffer
	if code := run(cmd, nil, &stderr); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr.String(), "unsupported schema version") {
		t.Errorf("stderr = %q, want the underlying message", stderr.String())
	}
}

// Output must go to the writers the caller supplied. Slice 5's end-to-end
// tests capture reports this way, and a stray os.Stdout write would make them
// silently pass.
func TestNewRootCommand_WritesOnlyToProvidedWriters(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"version"}, &stdout, &stderr); code != ExitClean {
		t.Fatalf("exit code = %d, want %d", code, ExitClean)
	}

	if stdout.Len() == 0 {
		t.Error("nothing was written to the provided stdout")
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty on a successful run", stderr.String())
	}
}
