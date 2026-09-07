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
	"regexp"
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

// safeInstallDirRe is deliberately one level stricter than
// config.installPathRe: config validates the install *path*
// (`<drive>:\<dir>\<file>`), this validates the *directory* installDir is
// about to hand to `rmdir /s /q`, so that directory must itself be at least
// two segments below the drive root. `C:\Program Files\Velociraptor` passes;
// `C:\Program Files` and `C:\` do not.
var safeInstallDirRe = regexp.MustCompile(`^[A-Za-z]:\\[^\\]+\\[^\\]+`)

// hasDotSegment mirrors config.hasDotSegment: a "." or ".." segment in dir
// would let `C:\a\..\..\..\Windows` (which passes safeInstallDirRe's shape
// check) resolve to `C:\Windows` once handed to `rmdir /s /q`. config.Validate
// already rejects this shape for a freshly built kit, but this is defence in
// depth for a config that predates that check.
func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, `\`) {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// installDir returns the parent directory of a Windows-style install path,
// e.g. `C:\Program Files\Velociraptor\Velociraptor.exe` ->
// `C:\Program Files\Velociraptor`, or "" when that parent is not a safe
// deletion target. This deliberately does not use filepath.Dir: this package
// is exercised by `go test` on the dev/CI host (darwin or linux), where
// path/filepath treats "/" as the separator and would silently return "."
// for a backslash-only path, even though the compiled dfirmedic.exe (built
// with GOOS=windows) would handle it correctly at incident-response time.
//
// Unlike exeDir in cmd/dfirmedic/cmds.go - which solves the same
// separator problem for a *read* path and therefore keeps drive roots
// (`E:\dfirmedic.exe` -> `E:\`) - this is a *delete* path: the result goes
// straight into `cmd.exe /c if exist <dir> rmdir /s /q <dir>` on a live
// host. The two differ on purpose. A drive-root or top-level result
// (`C:\`, `C:` - which in Windows path semantics means "the current
// directory on drive C" - or `C:\Program Files`) is refused with "" rather
// than passed on; the caller then records a skipped-for-safety error
// instead of deleting a drive or all of Program Files.
func installDir(path string) string {
	i := strings.LastIndexByte(path, '\\')
	if i < 0 {
		return ""
	}
	dir := path[:i]
	if !safeInstallDirRe.MatchString(dir) || hasDotSegment(dir) {
		return ""
	}
	return dir
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
		dir := installDir(d.Inc.Velociraptor.InstallPath)
		if dir == "" {
			return fmt.Errorf("refusing to delete the install directory for install_path %q: "+
				"it resolves to a drive root or a top-level directory, and this step runs "+
				"`rmdir /s /q`; remove the Velociraptor files by hand", d.Inc.Velociraptor.InstallPath)
		}
		return d.Sys.RemoveDirIfExists(ctx, dir)
	})
	step("delete startup task", func() error { return d.Sys.DeleteStartupTask(ctx, stage.TaskNamePrefix+d.Inc.CaseID) })
	step("remove firewall rule group", func() error { return d.FW.RemoveGroup(ctx, d.Inc.RuleGroup()) })
	step("import original firewall policy", func() error {
		return d.FW.Import(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw"))
	})
	// connect.FailClosed disables every physical adapter when the watchdog
	// fires, and that is exactly the state someone runs breakglass from, so
	// restoring the firewall alone would leave the host still offline. Use
	// the names FailClosed recorded, not a fresh PhysicalAdapters() query:
	// a name from either list can be stale by the time teardown runs (a USB
	// NIC unplugged, a virtual adapter torn down), and EnableAll now skips
	// exactly that phantom-adapter error rather than aborting the batch on
	// it (real-host test 2026-09-05: "enable Wi-Fi 5: ... Requested
	// operation not supported on adapter", a name from a state list that no
	// longer matched anything, when nothing had actually been disabled).
	// A manifest from before this field existed falls back to whatever
	// baseline.json recorded as Up - the best available guess at what a
	// watchdog trip would have disabled.
	step("re-enable network adapters", func() error {
		names := d.Man.DisabledAdapters
		if len(names) == 0 {
			raw, err := os.ReadFile(filepath.Join(d.WorkDir, "baseline.json"))
			if err != nil {
				return err
			}
			var base stage.Baseline
			if err := json.Unmarshal(raw, &base); err != nil {
				return err
			}
			for _, a := range base.Adapters {
				if strings.EqualFold(a.Status, "Up") {
					names = append(names, a.Name)
				}
			}
		}
		ads := make([]win.Adapter, len(names))
		for i, n := range names {
			ads[i] = win.Adapter{Name: n}
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
