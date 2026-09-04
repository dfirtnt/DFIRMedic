package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func TestRecordBuildsChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Phase("PREFLIGHT"); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("cmd", map[string]any{"argv": []string{"netsh"}}); err != nil {
		t.Fatal(err)
	}
	n, err := VerifyChain(p)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var e0, e1 Entry
	json.Unmarshal([]byte(lines[0]), &e0)
	json.Unmarshal([]byte(lines[1]), &e1)
	if e0.PrevHash != strings.Repeat("0", 64) || e1.PrevHash != e0.Hash || e1.Seq != 2 {
		t.Fatalf("chain wrong: %+v %+v", e0, e1)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(p, fixedClock())
	l.Phase("A")
	l.Phase("B")
	l.Phase("C")
	b, _ := os.ReadFile(p)
	tampered := strings.Replace(string(b), `"name":"B"`, `"name":"X"`, 1)
	os.WriteFile(p, []byte(tampered), 0o600)
	_, err := VerifyChain(p)
	if err == nil || !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("expected tamper at seq 2, got %v", err)
	}
}

func TestOpenResumesExistingChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(p, fixedClock())
	l.Phase("A")
	l2, err := Open(p, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	l2.Phase("B")
	n, err := VerifyChain(p)
	if err != nil || n != 2 {
		t.Fatalf("resume broke chain: n=%d err=%v", n, err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "manifest.json")
	m := &Manifest{CaseID: "C", Phases: map[string]time.Time{"READY": time.Now().UTC()}, Payload: map[string]string{"a": "b"}}
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadManifest(p)
	if err != nil || got.CaseID != "C" || got.Payload["a"] != "b" {
		t.Fatalf("round trip failed: %v %+v", err, got)
	}
}
