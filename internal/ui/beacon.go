// Package ui is the single-screen status beacon shown to the on-site person.
// It shows one of four states and nothing else: no logs, no findings.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/dfirtnt/DFIRMedic/internal/config"
)

type State int

const (
	Staging State = iota
	Ready
	Connected
	Error
)

const (
	ansiClear  = "\x1b[2J\x1b[H"
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
)

type Beacon struct {
	mu      sync.Mutex
	w       io.Writer
	contact config.Contact
	state   State
	detail  string
}

func New(w io.Writer, contact config.Contact) *Beacon {
	return &Beacon{w: w, contact: contact, state: Staging}
}

func (b *Beacon) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *Beacon) Set(state State, detail string) {
	b.mu.Lock()
	b.state, b.detail = state, detail
	b.mu.Unlock()
	fmt.Fprint(b.w, b.Render())
}

func (b *Beacon) Render() string {
	b.mu.Lock()
	state, detail := b.state, b.detail
	b.mu.Unlock()

	var word, colour, instruction string
	switch state {
	case Staging:
		word, colour, instruction = "STAGING", ansiYellow, "Please wait. Do not touch the computer."
	case Ready:
		word, colour, instruction = "READY", ansiGreen, "RECONNECT NETWORK NOW"
	case Connected:
		word, colour, instruction = "CONNECTED", ansiGreen, "You may leave. Leave this window open and the computer on."
	case Error:
		word, colour, instruction = "ERROR", ansiRed, fmt.Sprintf("CALL %s %s", b.contact.Name, b.contact.Phone)
	}

	rows := BigText(word)
	width := len([]rune(rows[0])) + 6
	if len(instruction)+6 > width {
		width = len(instruction) + 6
	}
	if len(detail)+6 > width {
		width = len(detail) + 6
	}
	line := strings.Repeat("═", width)
	center := func(s string) string {
		pad := width - len([]rune(s))
		l := pad / 2
		return strings.Repeat(" ", l) + s + strings.Repeat(" ", pad-l)
	}

	var out strings.Builder
	out.WriteString(ansiClear)
	out.WriteString(word + "\n")
	out.WriteString(colour + ansiBold)
	out.WriteString("╔" + line + "╗\n")
	out.WriteString("║" + center("") + "║\n")
	for _, r := range rows {
		out.WriteString("║" + center(r) + "║\n")
	}
	out.WriteString("║" + center("") + "║\n")
	out.WriteString("║" + center(instruction) + "║\n")
	if detail != "" {
		out.WriteString("║" + center(detail) + "║\n")
	}
	out.WriteString("║" + center("") + "║\n")
	out.WriteString("╚" + line + "╝\n")
	out.WriteString(ansiReset)
	out.WriteString("\nDFIRMedic\n")
	return out.String()
}
