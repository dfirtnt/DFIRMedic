// Package connect runs the online half of the workflow (spec §9 and §10):
// wait for a link, verify the tunnel is to the responder, start Velociraptor,
// then watch the tunnel and fail closed if it is lost.
package connect

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

type Deps struct {
	Inc     *config.Incident
	WorkDir string
	R       runner.Runner
	Log     *audit.Log
	Man     *audit.Manifest
	Beacon  *ui.Beacon
	Net     win.Net
	TS      tailscale.Client
	Velo    velo.Client
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Poll    time.Duration
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (d *Deps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
}

func (d Deps) phase(name string) error {
	d.Man.Phases[name] = d.Now().UTC()
	_ = d.Man.Save(filepath.Join(d.WorkDir, "manifest.json"))
	return d.Log.Phase(name)
}

func WaitLinkUp(ctx context.Context, d Deps) error {
	d.defaults()
	for {
		up, _, err := d.Net.AnyPhysicalUp(ctx)
		if err != nil {
			return err
		}
		if up {
			return d.Log.Record("link_up", map[string]string{"at": d.Now().UTC().Format(time.RFC3339)})
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			return err
		}
	}
}

func (d Deps) responderOnline(ctx context.Context) bool {
	st, err := d.TS.Status(ctx)
	if err != nil {
		return false
	}
	return st.ResponderOnline(d.Inc.Tailscale.ResponderNodeKey)
}

func Run(ctx context.Context, d Deps) error {
	d.defaults()
	if err := WaitLinkUp(ctx, d); err != nil {
		return err
	}
	if err := d.phase("CONNECT"); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Connecting")

	deadline := d.Now().Add(time.Duration(d.Inc.Watchdog.TunnelTimeoutSec) * time.Second)
	for !d.responderOnline(ctx) {
		if !d.Now().Before(deadline) {
			return FailClosed(ctx, d, "E50 tunnel not established in time")
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			return err
		}
	}
	_ = d.Log.Record("tunnel_verified", map[string]string{"responder_node_key": d.Inc.Tailscale.ResponderNodeKey})

	if err := d.Velo.Start(ctx); err != nil {
		return FailClosed(ctx, d, "E52 Velociraptor failed to start")
	}
	if err := d.phase("CONNECTED"); err != nil {
		return err
	}
	d.Beacon.Set(ui.Connected, "")

	grace := time.Duration(d.Inc.Watchdog.HeartbeatGraceSec) * time.Second
	lastOK := d.Now()
	for {
		if err := d.Sleep(ctx, d.Poll); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if d.responderOnline(ctx) {
			lastOK = d.Now()
			continue
		}
		if d.Now().Sub(lastOK) > grace {
			return FailClosed(ctx, d, "E51 tunnel lost")
		}
	}
}

// FailClosed is the watchdog response from spec §10: stop Velociraptor, take
// every physical adapter down, keep the firewall locked, show ERROR.
func FailClosed(ctx context.Context, d Deps, reason string) error {
	d.defaults()
	_ = d.Log.Record("fail_closed", map[string]string{"reason": reason})
	_ = d.Velo.Stop(ctx)
	ads, err := d.Net.PhysicalAdapters(ctx)
	if err == nil {
		_ = d.Net.DisableAll(ctx, ads)
	}
	_ = d.phase("FAILED")
	d.Beacon.Set(ui.Error, reason)
	return fmt.Errorf("%s", reason)
}
