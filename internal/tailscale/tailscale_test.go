package tailscale

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const statusJSON = `{
 "BackendState":"Running",
 "Self":{"PublicKey":"nodekey:self","HostName":"ir-C1","Online":true,"TailscaleIPs":["100.64.0.9"]},
 "Peer":{
   "nodekey:resp":{"PublicKey":"nodekey:resp","HostName":"analyst","Online":true,"TailscaleIPs":["100.64.0.1"]},
   "nodekey:other":{"PublicKey":"nodekey:other","HostName":"nas","Online":false,"TailscaleIPs":["100.64.0.2"]}
 }}`

func TestParseStatusAndResponderOnline(t *testing.T) {
	s, err := ParseStatus(statusJSON)
	if err != nil {
		t.Fatal(err)
	}
	if s.BackendState != "Running" || s.Self.HostName != "ir-C1" || len(s.Peers) != 2 {
		t.Fatalf("%+v", s)
	}
	if !s.ResponderOnline("nodekey:resp") {
		t.Fatal("responder should be online")
	}
	if s.ResponderOnline("nodekey:other") {
		t.Fatal("offline peer must not count")
	}
	if s.ResponderOnline("nodekey:missing") {
		t.Fatal("unknown peer must not count")
	}
	s.BackendState = "NeedsLogin"
	if s.ResponderOnline("nodekey:resp") {
		t.Fatal("must require Running")
	}
}

func TestUpTreatsTimeoutAsSuccess(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" up"] = runner.Result{ExitCode: 1, Stderr: "timeout waiting for Tailscale service to enter state Running"}
	c := Client{R: f}
	if err := c.Up(context.Background(), "tskey-x", "ir-C1"); err != nil {
		t.Fatalf("offline timeout must not be fatal: %v", err)
	}
	argv := strings.Join(f.Calls[0], " ")
	for _, want := range []string{"--authkey=tskey-x", "--hostname=ir-C1", "--accept-routes=false", "--accept-dns=false", "--timeout=15s"} {
		if !strings.Contains(argv, want) {
			t.Fatalf("missing %s in %s", want, argv)
		}
	}
}

func TestUpPropagatesRealErrors(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" up"] = runner.Result{ExitCode: 1, Stderr: "invalid key: key expired"}
	if err := (Client{R: f}).Up(context.Background(), "tskey-x", "ir-C1"); err == nil {
		t.Fatal("expired key must be fatal")
	}
}

func TestInstallAndUninstallMSI(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, MSIPath: `C:\w\payload\tailscale-setup.msi`}
	c.InstallMSI(context.Background())
	c.UninstallMSI(context.Background())
	if !f.Called("msiexec.exe", "/i", c.MSIPath, "/quiet", "/norestart") || !f.Called("msiexec.exe", "/x", c.MSIPath, "/quiet", "/norestart") {
		t.Fatalf("%v", f.Calls)
	}
}

func TestStatusUsesJSONFlag(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" status --json"] = runner.Result{Stdout: statusJSON}
	s, err := (Client{R: f}).Status(context.Background())
	if err != nil || s.BackendState != "Running" {
		t.Fatalf("%+v %v", s, err)
	}
}
