// Package connect runs the online half of the workflow (spec §9 and §10):
// wait for a link, verify the server is ours via a pinned-CA TLS probe,
// start Velociraptor, then watch the probe and fail closed if it is lost.
package connect

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/probe"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
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
	Probe   probe.Prober
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
	if d.Man == nil {
		d.Man = &audit.Manifest{}
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

// probeLogEvery caps how often an unchanging probe failure is written to the
// audit log. The poll interval is two seconds and the tunnel timeout is ten
// minutes by default, so recording every failure would bury the interesting
// lines under ~300 identical ones.
const probeLogEvery = 30

// probeLogFloor bounds how often a *change* in error text can trigger a
// record, independent of probeLogEvery: without it, an error that alternates
// between two texts every poll would satisfy "msg != t.recorded" on every
// single call and write probe_failed every poll instead of being rate-limited.
const probeLogFloor = 10

// probeTracker turns a stream of probe results into (a) a rate-limited
// probe_failed audit trail and (b) the last error text, so the E50/E51
// FailClosed reason - which is what reaches the beacon and the responder -
// says *why* the server could not be verified. Without it an E50 arrived
// with no diagnostic at all.
type probeTracker struct {
	last     string // most recent failure text, for the FailClosed reason
	recorded string // failure text of the last audit record written
	since    int    // fail() calls since that record, any text
	seen     bool   // a failure has happened since the last success
}

func (t *probeTracker) fail(d Deps, msg string) {
	t.last = msg
	t.since++
	changed := msg != t.recorded
	if !t.seen || (changed && t.since >= probeLogFloor) || t.since >= probeLogEvery {
		_ = d.Log.Record("probe_failed", map[string]string{"server": d.Inc.Server.IP, "error": msg})
		t.recorded, t.since = msg, 0
	}
	t.seen = true
}

func (t *probeTracker) ok() { *t = probeTracker{} }

// reason appends the last probe error to a FailClosed reason so the code and
// the diagnosis travel together.
func (t *probeTracker) reason(code string) string {
	if t.last == "" {
		return code
	}
	return fmt.Sprintf("%s (last probe error: %s)", code, t.last)
}

// serverVerified is the tunnel-verified condition from spec 2026-09-05 §7:
// a TLS handshake with server_ip:port whose certificate chains to the CA in
// the shipped client config. A captive portal or a stranger on that IP
// cannot pass it. Every outcome goes through t so failures are attributable
// after the fact.
func (d Deps) serverVerified(ctx context.Context, t *probeTracker) (string, bool) {
	if d.Probe == nil {
		t.fail(d, "no prober configured")
		return "", false
	}
	fp, err := d.Probe.Verify(ctx)
	if err != nil {
		t.fail(d, err.Error())
		return "", false
	}
	t.ok()
	return fp, true
}

func Run(ctx context.Context, d Deps) error {
	d.defaults()
	if err := WaitLinkUp(ctx, d); err != nil {
		d.Beacon.Set(ui.Error, fmt.Sprintf("network wait failed: %v", err))
		return err
	}
	if err := d.phase("CONNECT"); err != nil {
		d.Beacon.Set(ui.Error, fmt.Sprintf("audit log error: %v", err))
		return err
	}
	d.Beacon.Set(ui.Staging, "Connecting")

	deadline := d.Now().Add(time.Duration(d.Inc.Watchdog.TunnelTimeoutSec) * time.Second)
	pt := &probeTracker{}
	var leaf string
	for {
		var ok bool
		if leaf, ok = d.serverVerified(ctx, pt); ok {
			break
		}
		if !d.Now().Before(deadline) {
			return FailClosed(ctx, d, pt.reason("E50 server not verified in time"))
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			d.Beacon.Set(ui.Error, fmt.Sprintf("server verification interrupted: %v", err))
			return err
		}
	}
	_ = d.Log.Record("server_verified", map[string]string{"server": d.Inc.Server.IP, "leaf_sha256": leaf})

	if err := d.Velo.Start(ctx); err != nil {
		return FailClosed(ctx, d, "E52 Velociraptor failed to start")
	}
	// Best-effort: once Velociraptor is running, an audit-write hiccup must
	// not skip the heartbeat watchdog below (spec §10 — the host must never
	// be left online and monitored without something watching the tunnel).
	_ = d.phase("CONNECTED")
	d.Beacon.Set(ui.Connected, "")

	grace := time.Duration(d.Inc.Watchdog.HeartbeatGraceSec) * time.Second
	lastOK := d.Now()
	for {
		if err := d.Sleep(ctx, d.Poll); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return FailClosed(ctx, d, pt.reason(fmt.Sprintf("E51 server unreachable (sleep error: %v)", err)))
		}
		if _, ok := d.serverVerified(ctx, pt); ok {
			lastOK = d.Now()
			continue
		}
		if d.Now().Sub(lastOK) > grace {
			return FailClosed(ctx, d, pt.reason("E51 server unreachable"))
		}
	}
}

// FailClosed is the watchdog response from spec §10: stop Velociraptor, take
// every physical adapter down, keep the firewall locked, show ERROR.
func FailClosed(ctx context.Context, d Deps, reason string) error {
	d.defaults()
	_ = d.Log.Record("fail_closed", map[string]string{"reason": reason})

	// Remediation must not ride on the caller's context: if ctx's own
	// cancellation/expiry is what triggered this call (or races with it),
	// commands started with it would refuse to even run. Detach and give
	// the close its own bounded timeout instead.
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	veloErr := d.Velo.Stop(closeCtx)

	ads, adsErr := d.Net.PhysicalAdapters(closeCtx)
	var disableErrs []error
	var disabled []string
	if adsErr != nil {
		disableErrs = append(disableErrs, fmt.Errorf("list adapters: %w", adsErr))
	} else {
		for _, a := range ads {
			if err := d.Net.DisableAll(closeCtx, []win.Adapter{a}); err != nil {
				disableErrs = append(disableErrs, err)
			} else {
				disabled = append(disabled, a.Name)
			}
		}
	}
	// Recorded so teardown/breakglass re-enable exactly these adapters later,
	// not every adapter physically present at that (possibly much later)
	// time - a name here can be stale by then, and a name never disabled
	// here was never this watchdog trip's doing.
	d.Man.DisabledAdapters = disabled

	_ = d.Log.Record("fail_closed_result", map[string]any{
		"velo_stop_ok":    veloErr == nil,
		"velo_stop_error": fmt.Sprintf("%v", veloErr),
		"adapters_ok":     len(disableErrs) == 0,
		"adapters_error":  fmt.Sprintf("%v", errors.Join(disableErrs...)),
		"disabled":        disabled,
	})

	_ = d.phase("FAILED")
	d.Beacon.Set(ui.Error, reason)
	return fmt.Errorf("%s", reason)
}
