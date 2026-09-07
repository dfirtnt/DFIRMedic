package connect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/probe"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const (
	adUp   = `[{"Name":"Wi-Fi","Status":"Up"}]`
	adDown = `[{"Name":"Wi-Fi","Status":"Disconnected"}]`
)

// fakeProbe returns scripted results in order, repeating the last one.
type fakeProbe struct {
	errs []error
	i    int
	n    int
}

func (p *fakeProbe) Verify(context.Context) (string, error) {
	p.n++
	i := p.i
	if i >= len(p.errs) {
		i = len(p.errs) - 1
	}
	p.i++
	if err := p.errs[i]; err != nil {
		return "", err
	}
	return "leaf0", nil
}

var errDown = errors.New("probe: dial tcp: i/o timeout")

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

func deps(t *testing.T, r runner.Runner, c *clock, pr probe.Prober) Deps {
	t.Helper()
	work := t.TempDir()
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	inc := &config.Incident{
		CaseID:   "C1",
		Server:   config.Server{IP: "203.0.113.10", Port: 443},
		Watchdog: config.Watchdog{TunnelTimeoutSec: 600, HeartbeatGraceSec: 300},
		Contact:  config.Contact{Name: "Alex", Phone: "+1555"},
	}
	return Deps{
		Inc: inc, WorkDir: work, R: r, Log: log, Man: &audit.Manifest{Phases: map[string]time.Time{}},
		Beacon: ui.New(&strings.Builder{}, inc.Contact),
		Net:    win.Net{R: r}, Probe: pr, Velo: velo.Client{R: r},
		Now: c.now, Sleep: c.sleep, Poll: 2 * time.Second,
	}
}

func psPrefix(script string) string {
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + script
}

func TestRunConnectsThenStartsVelociraptorThenHeartbeats(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adDown, adDown, adUp)
	pr := &fakeProbe{errs: []error{errDown, errDown, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 2 * time.Second, cancel: cancel, after: 12}
	d := deps(t, s, c, pr)
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
	if pr.n < 4 {
		t.Fatalf("heartbeat should keep probing after CONNECTED, got %d calls", pr.n)
	}
}

func TestTunnelTimeoutFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{errDown}}
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second}
	d := deps(t, s, c, pr)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E50") {
		t.Fatalf("want E50, got %v", err)
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter -Name 'Wi-Fi'") {
		t.Fatal("adapters must be disabled on timeout")
	}
	if s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor must never start without a verified server")
	}
	if d.Beacon.State() != ui.Error || !strings.Contains(d.Beacon.Render(), "E50") {
		t.Fatal("beacon must show E50")
	}
}

func TestHeartbeatLossFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil, errDown}}
	c := &clock{t: time.Unix(1000, 0), step: 100 * time.Second}
	d := deps(t, s, c, pr)
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
	pr := &fakeProbe{errs: []error{nil, errDown, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 50 * time.Second, cancel: cancel, after: 8}
	d := deps(t, s, c, pr)
	if err := Run(ctx, d); err != nil {
		t.Fatalf("a blip shorter than the grace period must not fail closed: %v", err)
	}
}

func TestVelociraptorStartFailure(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil}}
	s.f.Responses[s.f.Key("sc.exe", "start", "Velociraptor")] = runner.Result{ExitCode: 1053, Stderr: "did not respond"}
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	err := Run(context.Background(), deps(t, s, c, pr))
	if err == nil || !strings.Contains(err.Error(), "E52") {
		t.Fatalf("want E52, got %v", err)
	}
}

// TestProbeTrackerFloorLimitsAlternatingErrors proves probeTracker.fail no
// longer writes a probe_failed record on every single call when the error
// text alternates: "msg != t.recorded" alone was true on every call for two
// alternating texts, defeating probeLogEvery's rate limit entirely. The
// floor caps that at roughly one record per probeLogFloor calls regardless
// of how often the text changes.
func TestProbeTrackerFloorLimitsAlternatingErrors(t *testing.T) {
	s := newSeq()
	c := &clock{t: time.Unix(1000, 0)}
	d := deps(t, s, c, &fakeProbe{})
	pt := &probeTracker{}
	msgs := []string{"error A", "error B"}
	const calls = 40
	for i := 0; i < calls; i++ {
		pt.fail(d, msgs[i%2])
	}
	raw, err := os.ReadFile(filepath.Join(d.WorkDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := strings.Count(string(raw), `"event":"probe_failed"`)
	if n < 1 {
		t.Fatal("must still log at least the first failure")
	}
	if n > calls/probeLogFloor+2 {
		t.Fatalf("floor should bound records to roughly one per %d calls, got %d records for %d calls", probeLogFloor, n, calls)
	}
}

// TestHeartbeatSleepErrorReasonIncludesLastProbeError proves the sleep-error
// E51 branch no longer discards diagnostic information: it used to build its
// reason with a bare fmt.Sprintf, which meant a genuine prior probe failure
// (the reason the connection was already in trouble) never reached the
// beacon or the responder, only the sleep mechanism's own error text.
func TestHeartbeatSleepErrorReasonIncludesLastProbeError(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil, errDown}}
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	d := deps(t, s, c, pr)
	sleepErr := errors.New("deadline exceeded")
	sleepN := 0
	d.Sleep = func(context.Context, time.Duration) error {
		sleepN++
		if sleepN == 2 {
			return sleepErr
		}
		return nil
	}

	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("error must carry the sleep failure detail, got %v", err)
	}
	if !strings.Contains(err.Error(), errDown.Error()) {
		t.Fatalf("error must also carry the last probe error, got %v", err)
	}
}

// TestHeartbeatSleepErrorFailsClosed proves Finding 1's second gap is closed:
// once Velociraptor has started, a non-cancellation Sleep error in the
// heartbeat loop must go through FailClosed, not a bare error return that
// would leave the host online and unmonitored.
func TestHeartbeatSleepErrorFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil}}
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	d := deps(t, s, c, pr)
	sleepErr := errors.New("deadline exceeded")
	d.Sleep = func(context.Context, time.Duration) error { return sleepErr }

	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E51") {
		t.Fatalf("want E51, got %v", err)
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("error should carry the sleep failure detail, got %v", err)
	}
	if !s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor should have started before the sleep error")
	}
	if !s.f.Called("sc.exe", "stop", "Velociraptor") {
		t.Fatal("a non-cancellation sleep error must still stop Velociraptor via FailClosed")
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("a non-cancellation sleep error must still disable adapters via FailClosed")
	}
	if d.Beacon.State() != ui.Error {
		t.Fatalf("beacon must show error, got %v", d.Beacon.State())
	}
}

// TestFailClosedDisablesAllAdaptersDespitePartialFailure proves Finding 2 is
// closed: FailClosed must attempt every adapter even when an earlier one
// fails to disable, instead of aborting the whole batch on the first error.
func TestFailClosedDisablesAllAdaptersDespitePartialFailure(t *testing.T) {
	s := newSeq()
	twoAds := `[{"Name":"Adapter1","Status":"Up"},{"Name":"Adapter2","Status":"Up"}]`
	s.script(psPrefix("Get-NetAdapter"), twoAds)
	pr := &fakeProbe{errs: []error{errDown}}
	s.f.Errors[s.f.Key("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Disable-NetAdapter -Name 'Adapter1' -Confirm:$false")] = errors.New("access denied")
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second}
	d := deps(t, s, c, pr)

	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E50") {
		t.Fatalf("want E50, got %v", err)
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Disable-NetAdapter -Name 'Adapter1'") {
		t.Fatal("adapter1 disable must have been attempted")
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Disable-NetAdapter -Name 'Adapter2'") {
		t.Fatal("adapter2 disable must still be attempted even though adapter1 failed")
	}
}

// ctxCheckingRunner simulates exec.CommandContext's real behavior of
// refusing to even start a command when the context handed to Run is already
// done, which the in-memory Fake does not otherwise reproduce.
type ctxCheckingRunner struct{ inner runner.Runner }

func (r ctxCheckingRunner) Run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	if err := ctx.Err(); err != nil {
		return runner.Result{}, err
	}
	return r.inner.Run(ctx, name, args...)
}

// TestFailClosedRemediatesWithCancelledContext proves Finding 3 is closed:
// FailClosed must still run its remediation commands when invoked with (or
// racing) an already-cancelled context, because context.WithoutCancel
// detaches the remediation from the caller's cancellation.
func TestFailClosedRemediatesWithCancelledContext(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	cr := ctxCheckingRunner{inner: s}
	d := deps(t, cr, c, &fakeProbe{errs: []error{errDown}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := FailClosed(ctx, d, "E99 test reason")
	if err == nil || !strings.Contains(err.Error(), "E99") {
		t.Fatalf("want E99, got %v", err)
	}
	if !s.f.Called("sc.exe", "stop", "Velociraptor") {
		t.Fatal("Velociraptor stop must still be attempted with an already-cancelled context")
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("adapter disable must still be attempted with an already-cancelled context")
	}
}

// TestWaitLinkUpFailureSetsErrorBeacon proves Finding 5 is closed: a
// pre-CONNECTED failure (here, WaitLinkUp erroring) must not leave the
// beacon frozen on STAGING forever.
func TestWaitLinkUpFailureSetsErrorBeacon(t *testing.T) {
	s := newSeq()
	s.f.Errors[psPrefix("Get-NetAdapter")] = errors.New("wmi failure")
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	d := deps(t, s, c, &fakeProbe{errs: []error{errDown}})

	err := Run(context.Background(), d)
	if err == nil {
		t.Fatal("expected an error from WaitLinkUp")
	}
	if d.Beacon.State() != ui.Error {
		t.Fatalf("beacon must show ui.Error after a WaitLinkUp failure, got %v", d.Beacon.State())
	}
}

// TestDepsDefaultsNilManifest proves the cheap nil-Manifest guard: defaults()
// must not panic when Man is nil.
func TestDepsDefaultsNilManifest(t *testing.T) {
	d := Deps{}
	d.defaults()
	if d.Man == nil || d.Man.Phases == nil {
		t.Fatal("defaults() must initialize a nil Manifest and its Phases map")
	}
}

// ---- probe failure diagnostics (spec §7, integration row 13) ----

func auditText(t *testing.T, d Deps) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d.WorkDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func countEvent(t *testing.T, d Deps, event string) int {
	t.Helper()
	return strings.Count(auditText(t, d), `"event":"`+event+`"`)
}

var errPinnedCA = errors.New("probe: certificate not signed by the pinned CA: x509: certificate signed by unknown authority")

// TestProbeFailuresAreRecordedAndRateLimited: an E50 used to arrive with no
// diagnostic at all. Every probe failure must now be attributable from
// audit.jsonl, but a ten-minute outage polled every two seconds must not
// write three hundred lines, and the reason that reaches the beacon must
// carry the last probe error.
func TestProbeFailuresAreRecordedAndRateLimited(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{errPinnedCA}}
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second} // 600s timeout -> ~21 probes
	d := deps(t, s, c, pr)

	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E50") {
		t.Fatalf("want E50, got %v", err)
	}
	if !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("E50 reason must carry the last probe error, got %q", err)
	}
	if !strings.Contains(d.Beacon.Render(), "pinned CA") {
		t.Fatalf("beacon must show the probe error: %s", d.Beacon.Render())
	}
	a := auditText(t, d)
	if !strings.Contains(a, `"event":"probe_failed"`) || !strings.Contains(a, "pinned CA") {
		t.Fatalf("audit log must record probe_failed naming the error:\n%s", a)
	}
	if !strings.Contains(a, d.Inc.Server.IP) {
		t.Fatalf("probe_failed must name the server:\n%s", a)
	}
	if n, probes := countEvent(t, d, "probe_failed"), pr.n; n >= probes || n == 0 {
		t.Fatalf("probe_failed written %d times for %d identical failures; want rate limiting", n, probes)
	}
}

// TestProbeFailureRecordedAgainWhenTheErrorChanges: rate limiting must not
// hide a *different* failure - "connection refused" turning into "not signed
// by the pinned CA" is the whole diagnosis.
func TestProbeFailureRecordedAgainWhenTheErrorChanges(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{errDown, errDown, errPinnedCA}}
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second}
	d := deps(t, s, c, pr)

	if err := Run(context.Background(), d); err == nil {
		t.Fatal("want E50")
	}
	a := auditText(t, d)
	if !strings.Contains(a, "i/o timeout") || !strings.Contains(a, "pinned CA") {
		t.Fatalf("both distinct probe errors must appear:\n%s", a)
	}
	if n := countEvent(t, d, "probe_failed"); n != 2 {
		t.Fatalf("probe_failed written %d times, want 2 (one per distinct error)", n)
	}
}

// TestHeartbeatLossRecordsProbeFailuresAndCarriesTheReason covers the E51
// half: the watchdog reason must name why the heartbeat stopped.
func TestHeartbeatLossRecordsProbeFailuresAndCarriesTheReason(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil, errPinnedCA}}
	c := &clock{t: time.Unix(1000, 0), step: 100 * time.Second}
	d := deps(t, s, c, pr)

	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E51") {
		t.Fatalf("want E51, got %v", err)
	}
	if !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("E51 reason must carry the last probe error, got %q", err)
	}
	if countEvent(t, d, "probe_failed") == 0 {
		t.Fatalf("heartbeat probe failures must be recorded:\n%s", auditText(t, d))
	}
}

// TestServerVerifiedRecordedOnceOnSuccess is the deferred Task 9 ledger
// check: the successful verification is a single, findable audit line, and
// the heartbeat's own successes do not spam the log.
func TestServerVerifiedRecordedOnceOnSuccess(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	pr := &fakeProbe{errs: []error{nil}}
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 2 * time.Second, cancel: cancel, after: 10}
	d := deps(t, s, c, pr)

	if err := Run(ctx, d); err != nil {
		t.Fatal(err)
	}
	if n := countEvent(t, d, "server_verified"); n != 1 {
		t.Fatalf("server_verified recorded %d times, want exactly 1", n)
	}
	if n := countEvent(t, d, "probe_failed"); n != 0 {
		t.Fatalf("a clean run must record no probe_failed, got %d", n)
	}
	if !strings.Contains(auditText(t, d), `"leaf_sha256":"leaf0"`) {
		t.Fatal("server_verified must carry the leaf fingerprint")
	}
}
