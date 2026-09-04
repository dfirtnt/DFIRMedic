// Package runner is the single chokepoint for executing external commands.
// Every call — real or dry-run — is written to the audit log.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

type ExitError struct{ Result Result }

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit %d: %s", e.Result.ExitCode, strings.TrimSpace(e.Result.Stderr))
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// ---- real ----

type execRunner struct {
	log *audit.Log
	m   *audit.Manifest
}

func NewExec(log *audit.Log, manifest *audit.Manifest) Runner {
	return &execRunner{log: log, m: manifest}
}

func (r *execRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String(), Duration: time.Since(start)}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.ExitCode = -1
	}
	argv := append([]string{name}, args...)
	c := audit.Command{Argv: argv, ExitCode: res.ExitCode, DurationMS: res.Duration.Milliseconds(), TSUTC: start.UTC()}
	if r.m != nil {
		r.m.Commands = append(r.m.Commands, c)
	}
	if r.log != nil {
		_ = r.log.Record("cmd", map[string]any{
			"argv": argv, "exit_code": res.ExitCode, "duration_ms": c.DurationMS,
			"stderr": truncate(res.Stderr, 4096),
		})
	}
	if runErr != nil && res.ExitCode == -1 {
		return res, runErr
	}
	if res.ExitCode != 0 {
		return res, &ExitError{res}
	}
	return res, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// ---- dry run ----

type dryRunner struct{ log *audit.Log }

func NewDryRun(log *audit.Log) Runner { return &dryRunner{log: log} }

func (r *dryRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	if r.log != nil {
		_ = r.log.Record("dryrun", map[string]any{"argv": append([]string{name}, args...)})
	}
	return Result{}, nil
}

// ---- fake ----

type Fake struct {
	Calls     [][]string
	Responses map[string]Result
	Errors    map[string]error
}

func NewFake() *Fake {
	return &Fake{Responses: map[string]Result{}, Errors: map[string]error{}}
}

func (f *Fake) Key(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

func (f *Fake) Run(_ context.Context, name string, args ...string) (Result, error) {
	argv := append([]string{name}, args...)
	f.Calls = append(f.Calls, argv)
	full := strings.Join(argv, " ")
	best := ""
	for k := range f.Responses {
		if strings.HasPrefix(full, k) && len(k) > len(best) {
			best = k
		}
	}
	for k := range f.Errors {
		if strings.HasPrefix(full, k) && len(k) > len(best) {
			best = k
		}
	}
	if best == "" {
		return Result{}, nil
	}
	if err, ok := f.Errors[best]; ok {
		return f.Responses[best], err
	}
	res := f.Responses[best]
	if res.ExitCode != 0 {
		return res, &ExitError{res}
	}
	return res, nil
}

// Called reports whether any recorded call starts with the given argv prefix.
func (f *Fake) Called(name string, args ...string) bool {
	want := f.Key(name, args...)
	for _, c := range f.Calls {
		if strings.HasPrefix(strings.Join(c, " "), want) {
			return true
		}
	}
	return false
}

// ---- helpers ----

func PS(ctx context.Context, r Runner, script string) (Result, error) {
	return r.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}
