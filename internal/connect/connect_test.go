package connect

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const (
	stNeedsLogin = `{"BackendState":"NeedsLogin","Peer":{}}`
	stRespOnline = `{"BackendState":"Running","Peer":{"nodekey:resp":{"PublicKey":"nodekey:resp","Online":true}}}`
	stRespOff    = `{"BackendState":"Running","Peer":{"nodekey:resp":{"PublicKey":"nodekey:resp","Online":false}}}`
	adUp         = `[{"Name":"Wi-Fi","Status":"Up"}]`
	adDown       = `[{"Name":"Wi-Fi","Status":"Disconnected"}]`
)

// seq is a Runner that returns scripted responses in order for matching
// argv prefixes (repeating the last one), and delegates everything else to a Fake.
type seq struct {
	f     *runner.Fake
	steps map[string][]runner.Result
	idx   map[string]int
}

func newSeq() *seq {
	return &seq{f: runner.NewFake(), steps: map[string][]runner.Result{}, idx: map[string]int{}}
}

func (s *seq) script(key string, outs ...string) {
	for _, o := range outs {
		s.steps[key] = append(s.steps[key], runner.Result{Stdout: o})
	}
}

func (s *seq) Run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	full := strings.Join(append([]string{name}, args...), " ")
	for k, outs := range s.steps {
		if strings.HasPrefix(full, k) {
			s.f.Calls = append(s.f.Calls, append([]string{name}, args...))
			i := s.idx[k]
			if i >= len(outs) {
				i = len(outs) - 1
			}
			s.idx[k]++
			return outs[i], nil
		}
	}
	return s.f.Run(ctx, name, args...)
}

type clock struct {
	t      time.Time
	step   time.Duration
	sleeps int
	cancel context.CancelFunc
	after  int // cancel ctx after this many sleeps (0 = never)
}

func (c *clock) now() time.Time { return c.t }
func (c *clock) sleep(ctx context.Context, _ time.Duration) error {
	c.sleeps++
	c.t = c.t.Add(c.step)
	if c.after > 0 && c.sleeps >= c.after && c.cancel != nil {
		c.cancel()
	}
	return ctx.Err()
}

func deps(t *testing.T, r runner.Runner, c *clock) Deps {
	t.Helper()
	work := t.TempDir()
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	inc := &config.Incident{
		CaseID:    "C1",
		Tailscale: config.Tailscale{ResponderNodeKey: "nodekey:resp"},
		Watchdog:  config.Watchdog{TunnelTimeoutSec: 600, HeartbeatGraceSec: 300},
		Contact:   config.Contact{Name: "Alex", Phone: "+1555"},
	}
	return Deps{
		Inc: inc, WorkDir: work, R: r, Log: log, Man: &audit.Manifest{Phases: map[string]time.Time{}},
		Beacon: ui.New(&strings.Builder{}, inc.Contact),
		Net: win.Net{R: r}, TS: tailscale.Client{R: r}, Velo: velo.Client{R: r},
		Now: c.now, Sleep: c.sleep, Poll: 2 * time.Second,
	}
}

func psPrefix(script string) string {
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + script
}

func TestRunConnectsThenStartsVelociraptorThenHeartbeats(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adDown, adDown, adUp)
	s.script(tailscale.ExePath+" status --json", stNeedsLogin, stRespOnline)
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 2 * time.Second, cancel: cancel, after: 12}
	d := deps(t, s, c)
	err := Run(ctx, d)
	if err != nil {
		t.Fatalf("normal cancel must return nil, got %v", err)
	}
	if !s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor not started")
	}
	if d.Beacon.State() != ui.Connected {
		t.Fatalf("beacon %v", d.Beacon.State())
	}
	for _, p := range []string{"CONNECT", "CONNECTED"} {
		if _, ok := d.Man.Phases[p]; !ok {
			t.Fatalf("missing phase %s", p)
		}
	}
	if s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("must not disable adapters on a clean run")
	}
}

func TestTunnelTimeoutFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stNeedsLogin)
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second}
	d := deps(t, s, c)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E50") {
		t.Fatalf("want E50, got %v", err)
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter -Name 'Wi-Fi'") {
		t.Fatal("adapters must be disabled on timeout")
	}
	if s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor must never start without a verified tunnel")
	}
	if d.Beacon.State() != ui.Error || !strings.Contains(d.Beacon.Render(), "E50") {
		t.Fatal("beacon must show E50")
	}
}

func TestHeartbeatLossFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline, stRespOnline, stRespOff)
	c := &clock{t: time.Unix(1000, 0), step: 100 * time.Second}
	d := deps(t, s, c)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E51") {
		t.Fatalf("want E51, got %v", err)
	}
	if !s.f.Called("sc.exe", "stop", "Velociraptor") {
		t.Fatal("Velociraptor must be stopped on fail-closed")
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("adapters must be disabled")
	}
}

func TestHeartbeatToleratesBriefBlip(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline, stRespOff, stRespOff, stRespOnline)
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 50 * time.Second, cancel: cancel, after: 8}
	d := deps(t, s, c)
	if err := Run(ctx, d); err != nil {
		t.Fatalf("a blip shorter than the grace period must not fail closed: %v", err)
	}
}

func TestVelociraptorStartFailure(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline)
	s.f.Responses[s.f.Key("sc.exe", "start", "Velociraptor")] = runner.Result{ExitCode: 1053, Stderr: "did not respond"}
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	err := Run(context.Background(), deps(t, s, c))
	if err == nil || !strings.Contains(err.Error(), "E52") {
		t.Fatalf("want E52, got %v", err)
	}
}
