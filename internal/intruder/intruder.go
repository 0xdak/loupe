// Package intruder sends many variations of a request, substituting payloads
// at marked positions, and keeps the results.
package intruder

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"loupe/internal/flow"
)

// Marker delimits payload positions in a template, as in Burp.
const Marker = "§"

// MaxRequests caps the size of one attack.
const MaxRequests = 100000

// maxStored caps the bytes kept per stored request and response.
const maxStored = 256 << 10

// Attack types.
const (
	Sniper       = "sniper"
	BatteringRam = "battering_ram"
	Pitchfork    = "pitchfork"
	ClusterBomb  = "cluster_bomb"
)

// Exchanger sends request text to a target without recording it.
type Exchanger interface {
	Exchange(ctx context.Context, target flow.Target, raw []byte) (*flow.Flow, error)
}

// PayloadSet produces payload strings.
type PayloadSet struct {
	Type string   `json:"type"` // "list" or "numbers"
	List []string `json:"list,omitempty"`
	From int      `json:"from,omitempty"`
	To   int      `json:"to,omitempty"`
	Step int      `json:"step,omitempty"`
}

func (p PayloadSet) values() ([]string, error) {
	switch p.Type {
	case "", "list":
		return p.List, nil
	case "numbers":
		step := p.Step
		if step == 0 {
			step = 1
		}
		if (step > 0 && p.From > p.To) || (step < 0 && p.From < p.To) {
			return nil, errors.New("numbers: the step does not lead from 'from' to 'to'")
		}
		var out []string
		for n := p.From; (step > 0 && n <= p.To) || (step < 0 && n >= p.To); n += step {
			if len(out) >= MaxRequests {
				return nil, fmt.Errorf("numbers: more than %d payloads", MaxRequests)
			}
			out = append(out, strconv.Itoa(n))
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown payload type %q", p.Type)
}

// Config describes an attack.
type Config struct {
	Target      flow.Target  `json:"target"`
	Template    string       `json:"template"` // request text with §marked§ positions
	Type        string       `json:"type"`
	Sets        []PayloadSet `json:"sets"`
	URLEncode   bool         `json:"urlEncode"` // encode characters that would break the request
	Concurrency int          `json:"concurrency"`
	DelayMs     int          `json:"delayMs"`
}

// Result is the outcome of one request of an attack.
type Result struct {
	N        int      `json:"n"` // 1-based request number
	Payloads []string `json:"payloads"`
	Status   int      `json:"status"`
	Length   int      `json:"length"`
	Millis   int64    `json:"ms"`
	Error    string   `json:"error,omitempty"`
	Request  []byte   `json:"-"`
	Response []byte   `json:"-"`
}

// Attack is a running or finished attack.
type Attack struct {
	ID     int64
	Config Config
	Total  int

	cancel  context.CancelFunc
	mu      sync.Mutex
	done    bool
	stopped bool
	res     []*Result
}

// Status is a snapshot of an attack.
type Status struct {
	ID      int64     `json:"id"`
	Type    string    `json:"type"`
	Target  string    `json:"target"`
	Total   int       `json:"total"`
	Sent    int       `json:"sent"`
	Done    bool      `json:"done"`
	Stopped bool      `json:"stopped"`
	Results []*Result `json:"results,omitempty"`
}

// Status returns the progress, with results when withResults is set.
func (a *Attack) Status(withResults bool) Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	scheme := "http"
	if a.Config.Target.TLS {
		scheme = "https"
	}
	s := Status{
		ID: a.ID, Type: a.Config.Type, Total: a.Total, Sent: len(a.res), Done: a.done, Stopped: a.stopped,
		Target: fmt.Sprintf("%s://%s:%d", scheme, a.Config.Target.Host, a.Config.Target.Port),
	}
	if withResults {
		s.Results = append([]*Result(nil), a.res...)
	}
	return s
}

// Result returns the result of request number n.
func (a *Attack) Result(n int) (*Result, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.res {
		if r.N == n {
			return r, true
		}
	}
	return nil, false
}

// Stop cancels the requests that have not been sent.
func (a *Attack) Stop() {
	a.mu.Lock()
	if !a.done {
		a.stopped = true
	}
	a.mu.Unlock()
	a.cancel()
}

// Manager runs attacks.
type Manager struct {
	ex Exchanger

	mu      sync.Mutex
	nextID  int64
	attacks map[int64]*Attack
	subs    []func(*Attack, *Result)
}

// NewManager returns a manager that sends requests with ex.
func NewManager(ex Exchanger) *Manager {
	return &Manager{ex: ex, attacks: map[int64]*Attack{}}
}

// Subscribe calls fn for every result, and with a nil result when an attack ends.
func (m *Manager) Subscribe(fn func(*Attack, *Result)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs = append(m.subs, fn)
}

func (m *Manager) notify(a *Attack, r *Result) {
	m.mu.Lock()
	subs := m.subs
	m.mu.Unlock()
	for _, fn := range subs {
		fn(a, r)
	}
}

// Get returns an attack.
func (m *Manager) Get(id int64) (*Attack, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.attacks[id]
	return a, ok
}

// Delete stops an attack and forgets its results.
func (m *Manager) Delete(id int64) {
	m.mu.Lock()
	a := m.attacks[id]
	delete(m.attacks, id)
	m.mu.Unlock()
	if a != nil {
		a.Stop()
	}
}

// Start validates cfg and runs the attack in the background.
func (m *Manager) Start(cfg Config) (*Attack, error) {
	literals, defaults, err := Positions(cfg.Template)
	if err != nil {
		return nil, err
	}
	sets := make([][]string, len(cfg.Sets))
	for i, s := range cfg.Sets {
		if sets[i], err = s.values(); err != nil {
			return nil, fmt.Errorf("payload set %d: %w", i+1, err)
		}
	}
	tuples, err := Combine(cfg.Type, defaults, sets)
	if err != nil {
		return nil, err
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 5
	}
	cfg.Concurrency = min(cfg.Concurrency, 50)

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.nextID++
	a := &Attack{ID: m.nextID, Config: cfg, Total: len(tuples), cancel: cancel}
	m.attacks[a.ID] = a
	m.mu.Unlock()

	go m.run(ctx, a, literals, tuples)
	return a, nil
}

func (m *Manager) run(ctx context.Context, a *Attack, literals []string, tuples [][]string) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range a.Config.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				r := m.send(ctx, a, i+1, literals, tuples[i])
				a.mu.Lock()
				a.res = append(a.res, r)
				a.mu.Unlock()
				m.notify(a, r)
				if a.Config.DelayMs > 0 {
					select {
					case <-time.After(time.Duration(a.Config.DelayMs) * time.Millisecond):
					case <-ctx.Done():
					}
				}
			}
		}()
	}
feed:
	for i := range tuples {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	a.mu.Lock()
	a.done = true
	a.mu.Unlock()
	a.cancel()
	m.notify(a, nil)
}

func (m *Manager) send(ctx context.Context, a *Attack, n int, literals, payloads []string) *Result {
	var b strings.Builder
	shown := make([]string, len(payloads))
	for i, lit := range literals {
		b.WriteString(lit)
		if i < len(payloads) {
			v := payloads[i]
			shown[i] = v
			if a.Config.URLEncode {
				v = urlEncode(v)
			}
			b.WriteString(v)
		}
	}
	raw := []byte(b.String())
	r := &Result{N: n, Payloads: shown, Request: capBytes(raw)}
	start := time.Now()
	f, err := m.ex.Exchange(ctx, a.Config.Target, raw)
	r.Millis = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Status, r.Error, r.Length = f.Status, f.Error, len(f.Response)
	r.Request, r.Response = capBytes(f.Request), capBytes(f.Response)
	return r
}

func capBytes(b []byte) []byte {
	if len(b) > maxStored {
		return b[:maxStored]
	}
	return b
}

// Positions splits a template at its markers into the literal text around
// the positions and the default value inside each position.
func Positions(template string) (literals, defaults []string, err error) {
	parts := strings.Split(template, Marker)
	if len(parts)%2 == 0 {
		return nil, nil, errors.New("the template has an unpaired § marker")
	}
	if len(parts) == 1 {
		return nil, nil, errors.New("mark at least one payload position with §…§")
	}
	for i, p := range parts {
		if i%2 == 0 {
			literals = append(literals, p)
		} else {
			defaults = append(defaults, p)
		}
	}
	return literals, defaults, nil
}

// Combine lists the payload value for every position of every request.
func Combine(attack string, defaults []string, sets [][]string) ([][]string, error) {
	n := len(defaults)
	need := func(k int) error {
		if len(sets) < k {
			return fmt.Errorf("this attack type needs %d payload set(s)", k)
		}
		for i := range k {
			if len(sets[i]) == 0 {
				return fmt.Errorf("payload set %d is empty", i+1)
			}
		}
		return nil
	}
	var out [][]string
	tooMany := fmt.Errorf("the attack would send more than %d requests", MaxRequests)
	switch attack {
	case "", Sniper:
		if err := need(1); err != nil {
			return nil, err
		}
		if n*len(sets[0]) > MaxRequests {
			return nil, tooMany
		}
		for pos := range n {
			for _, v := range sets[0] {
				t := append([]string(nil), defaults...)
				t[pos] = v
				out = append(out, t)
			}
		}
	case BatteringRam:
		if err := need(1); err != nil {
			return nil, err
		}
		if len(sets[0]) > MaxRequests {
			return nil, tooMany
		}
		for _, v := range sets[0] {
			t := make([]string, n)
			for i := range t {
				t[i] = v
			}
			out = append(out, t)
		}
	case Pitchfork:
		if err := need(n); err != nil {
			return nil, err
		}
		count := len(sets[0])
		for i := range n {
			count = min(count, len(sets[i]))
		}
		if count > MaxRequests {
			return nil, tooMany
		}
		for k := range count {
			t := make([]string, n)
			for i := range t {
				t[i] = sets[i][k]
			}
			out = append(out, t)
		}
	case ClusterBomb:
		if err := need(n); err != nil {
			return nil, err
		}
		total := 1
		for i := range n {
			total *= len(sets[i])
			if total > MaxRequests {
				return nil, tooMany
			}
		}
		idx := make([]int, n)
		for range total {
			t := make([]string, n)
			for i := range t {
				t[i] = sets[i][idx[i]]
			}
			out = append(out, t)
			// The first payload set varies fastest, as in Burp.
			for i := 0; i < n; i++ {
				idx[i]++
				if idx[i] < len(sets[i]) {
					break
				}
				idx[i] = 0
			}
		}
	default:
		return nil, fmt.Errorf("unknown attack type %q", attack)
	}
	return out, nil
}

// urlEncode percent-encodes the characters Burp encodes by default, plus
// whitespace and control characters, so a payload cannot break the request.
func urlEncode(s string) string {
	const special = "./\\=<>?+&*;:\"{}|^`#% "
	var b strings.Builder
	for _, c := range []byte(s) {
		if c < 0x21 || c >= 0x7f || strings.IndexByte(special, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
