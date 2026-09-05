package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/config"
)

func TestBigTextShape(t *testing.T) {
	rows := BigText("READY")
	if len(rows) != 5 {
		t.Fatalf("want 5 rows, got %d", len(rows))
	}
	w := len([]rune(rows[0]))
	for _, r := range rows {
		if len([]rune(r)) != w {
			t.Fatalf("ragged rows:\n%s", strings.Join(rows, "\n"))
		}
	}
	if !strings.Contains(strings.Join(rows, "\n"), "█") {
		t.Fatal("expected block glyphs")
	}
}

func TestBigTextUnknownRuneIsBlank(t *testing.T) {
	rows := BigText("A?")
	if len(rows) != 5 || len([]rune(rows[0])) != 11 { // 5 + 1 gap + 5
		t.Fatalf("%v", rows)
	}
}

func TestRenderStates(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf, config.Contact{Name: "Alex", Phone: "+15555550100"})
	if b.State() != Staging {
		t.Fatal("initial state must be Staging")
	}
	if !strings.Contains(b.Render(), "STAGING") {
		t.Fatal("staging word missing")
	}
	b.Set(Ready, "")
	out := b.Render()
	if !strings.Contains(out, "RECONNECT NETWORK NOW") || !strings.Contains(out, "\x1b[32m") {
		t.Fatalf("ready screen wrong:\n%s", out)
	}
	b.Set(Error, "E14 tunnel timeout")
	out = b.Render()
	for _, want := range []string{"ERROR", "CALL Alex +15555550100", "E14 tunnel timeout", "\x1b[31m"} {
		if !strings.Contains(out, want) {
			t.Fatalf("error screen missing %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(buf.String(), "\x1b[2J\x1b[H") {
		t.Fatal("Set must write a cleared screen to the writer")
	}
}

func TestEnableVTCompiles(t *testing.T) { EnableVT() }
