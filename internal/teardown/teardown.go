// Package teardown reverses everything staging did (spec §13) and provides
// the local break-glass path (spec §10.1). Best-effort: every step runs.
package teardown

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

type Deps struct {
	Inc     *config.Incident
	WorkDir string
	R       runner.Runner
	Log     *audit.Log
	Man     *audit.Manifest
	FW      win.Firewall
	Net     win.Net
	Sys     win.Sys
	Velo    velo.Client
	Now     func() time.Time
}

// installDir returns the parent directory of a Windows-style install path,
// e.g. `C:\Program Files\Velociraptor\Velociraptor.exe` ->
// `C:\Program Files\Velociraptor`. This deliberately does not use
// filepath.Dir: this package is exercised by `go test` on the dev/CI host
// (darwin or linux), where path/filepath treats "/" as the separator and
// would silently return "." for a backslash-only path, even though the
// compiled dfirmedic.exe (built with GOOS=windows) would handle it
// correctly at incident-response time. config.Incident validation
// guarantees InstallPath contains `:\`, so it is always Windows-style.
//
// A drive-root install path (e.g. `C:\Velociraptor.exe`) needs special
// handling: the last backslash sits at index 2, so a naive path[:i] would
// return "C:" rather than "C:\". In Windows path semantics "C:" means the
// current directory on drive C, while "C:\" means the root of drive C -
// feeding the former into RemoveDirIfExists (`cmd.exe /c if exist C:
// rmdir /s /q C:`) would be an ambiguous argument to a destructive
// filesystem operation. This mirrors exeDir in cmd/dfirmedic/cmds.go, which
// solves the same problem for executable paths; the two can't share code
// today because internal/teardown can't import the cmd/dfirmedic main
// package.
func installDir(path string) string {
	i := strings.LastIndexByte(path, '\\')
	switch {
	case i < 0:
		return path
	case i == 2 && path[1] == ':': // `C:\Velociraptor.exe` -> `C:\`
		return path[:3]
	default:
		return path[:i]
	}
}

func CodeHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (d Deps) phase(name string) {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.Phases[name] = d.Now().UTC()
	_ = d.Log.Phase(name)
}

func Run(ctx context.Context, d Deps) error {
	if d.Now == nil {
		d.Now = time.Now
	}
	d.phase("TEARDOWN")
	var errs []error
	step := func(name string, fn func() error) {
		if err := fn(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			_ = d.Log.Record("teardown_step_failed", map[string]string{"step": name, "error": err.Error()})
		}
	}
	step("stop Velociraptor", func() error { return d.Velo.Stop(ctx) })
	step("remove Velociraptor service", func() error { return d.Velo.RemoveService(ctx) })
	step("delete Velociraptor install directory", func() error {
		return d.Sys.RemoveDirIfExists(ctx, installDir(d.Inc.Velociraptor.InstallPath))
	})
	step("delete startup task", func() error { return d.Sys.DeleteStartupTask(ctx, stage.TaskNamePrefix+d.Inc.CaseID) })
	step("remove firewall rule group", func() error { return d.FW.RemoveGroup(ctx, d.Inc.RuleGroup()) })
	step("import original firewall policy", func() error {
		return d.FW.Import(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw"))
	})
	// connect.FailClosed disables every physical adapter when the watchdog
	// fires, and that is exactly the state someone runs breakglass from, so
	// restoring the firewall alone would leave the host still offline.
	// Re-enabling an already-enabled adapter is a no-op, so enable them all
	// rather than tracking which ones were disabled.
	step("re-enable network adapters", func() error {
		ads, err := d.Net.PhysicalAdapters(ctx)
		if err != nil {
			return err
		}
		return d.Net.EnableAll(ctx, ads)
	})
	step("restore firewall profiles", func() error {
		raw, err := os.ReadFile(filepath.Join(d.WorkDir, "baseline.json"))
		if err != nil {
			return err
		}
		var base stage.Baseline
		if err := json.Unmarshal(raw, &base); err != nil {
			return err
		}
		return d.FW.RestoreProfiles(ctx, base.Profiles)
	})
	d.phase("TEARDOWN_COMPLETE")
	if err := d.Man.Save(filepath.Join(d.WorkDir, "manifest.json")); err != nil {
		errs = append(errs, fmt.Errorf("save manifest: %w", err))
	}
	return errors.Join(errs...)
}

func Breakglass(ctx context.Context, d Deps, code string) error {
	if d.Now == nil {
		d.Now = time.Now
	}
	got, want := CodeHash(code), d.Inc.BreakglassCodeHash
	ok := subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	_ = d.Log.Record("breakglass_attempt", map[string]any{"accepted": ok, "at": d.Now().UTC()})
	if !ok {
		return errors.New("E60 break-glass code rejected")
	}
	return Run(ctx, d)
}
