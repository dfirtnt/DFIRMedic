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
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
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
	TS      tailscale.Client
	Velo    velo.Client
	Now     func() time.Time
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
	step("delete startup task", func() error { return d.Sys.DeleteStartupTask(ctx, stage.TaskNamePrefix+d.Inc.CaseID) })
	step("tailscale logout", func() error { return d.TS.Logout(ctx) })
	step("uninstall Tailscale", func() error { return d.TS.UninstallMSI(ctx) })
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
