// Package audit is the append-only, hash-chained evidence log and the
// manifest.json summary. Nothing in this package is ever overwritten.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Seq      int             `json:"seq"`
	TSUTC    time.Time       `json:"ts_utc"`
	Event    string          `json:"event"`
	Data     json.RawMessage `json:"data"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

func (e *Entry) computeHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s", e.Seq, e.TSUTC.UTC().Format(time.RFC3339Nano), e.Event, string(e.Data), e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  int
	last string
	now  func() time.Time
}

func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	l := &Log{now: now, last: genesis}
	if _, err := os.Stat(path); err == nil {
		n, last, err := walk(path)
		if err != nil {
			return nil, fmt.Errorf("existing audit log is corrupt: %w", err)
		}
		l.seq, l.last = n, last
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Record(event string, data any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	e := Entry{Seq: l.seq + 1, TSUTC: l.now().UTC(), Event: event, Data: raw, PrevHash: l.last}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq, l.last = e.Seq, e.Hash
	return nil
}

func (l *Log) Phase(name string) error {
	return l.Record("phase", map[string]string{"name": name})
}

func (l *Log) Close() error { return l.f.Close() }

// walk validates the chain and returns (count, lastHash).
func walk(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	prev, n := genesis, 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, prev, fmt.Errorf("seq %d: unparsable: %w", n+1, err)
		}
		if e.Seq != n+1 {
			return n, prev, fmt.Errorf("seq %d: expected seq %d", e.Seq, n+1)
		}
		if e.PrevHash != prev {
			return n, prev, fmt.Errorf("seq %d: prev_hash does not match previous entry", e.Seq)
		}
		if e.computeHash() != e.Hash {
			return n, prev, fmt.Errorf("seq %d: hash mismatch (entry modified)", e.Seq)
		}
		prev, n = e.Hash, e.Seq
	}
	return n, prev, sc.Err()
}

func VerifyChain(path string) (int, error) {
	n, _, err := walk(path)
	return n, err
}

type Command struct {
	Argv       []string  `json:"argv"`
	ExitCode   int       `json:"exit_code"`
	DurationMS int64     `json:"duration_ms"`
	TSUTC      time.Time `json:"ts_utc"`
}

type Manifest struct {
	CaseID             string               `json:"case_id"`
	KitVersion         string               `json:"kit_version"`
	OrchestratorSHA256 string               `json:"orchestrator_sha256"`
	Phases             map[string]time.Time `json:"phases"`
	Payload            map[string]string    `json:"payload"`
	Baseline           json.RawMessage      `json:"baseline,omitempty"`
	Rules              []string             `json:"rules"`
	Commands           []Command            `json:"commands"`
}

func (m *Manifest) Save(path string) error {
	if m.Phases == nil {
		m.Phases = map[string]time.Time{}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
