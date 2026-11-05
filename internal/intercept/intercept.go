// Package intercept holds requests and responses until a person forwards,
// edits or drops them.
package intercept

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"lightproxy/internal/flow"
	"lightproxy/internal/pipeline"
	"lightproxy/internal/rawhttp"
)

// ErrNotFound means the message is no longer held: it was already decided,
// or its client gave up waiting.
var ErrNotFound = errors.New("message is no longer held")

// Filter reports whether messages of a request may be held. Nil holds all.
type Filter func(*http.Request) bool

// Item is a held message.
type Item struct {
	ID     int64     `json:"id"`
	FlowID int64     `json:"flowId"`
	Kind   string    `json:"kind"` // "request" or "response"
	Time   time.Time `json:"time"`
	Method string    `json:"method"`
	URL    string    `json:"url"`
	Status int       `json:"status,omitempty"`
	Length int       `json:"length"`
	// Binary means the body is not valid UTF-8, so editing it as text would change it.
	Binary bool `json:"binary,omitempty"`

	raw    []byte
	decide chan decision
}

type decision struct {
	drop bool
	raw  []byte // nil: unchanged
}

// Settings controls what is held.
type Settings struct {
	Requests   bool `json:"requests"`   // hold requests ("Intercept is on")
	Responses  bool `json:"responses"`  // hold responses as well
	SkipStatic bool `json:"skipStatic"` // let images, scripts, styles and fonts pass
}

// State is a snapshot of the queue, without message bytes.
type State struct {
	Settings
	Pending []Item `json:"pending"`
}

// Queue is a request and response hook that holds messages.
type Queue struct {
	filter  Filter
	maxBody int64

	mu       sync.Mutex
	settings Settings
	nextID   int64
	pending  []*Item
	subs     []func()
}

// New returns a queue that holds nothing until configured. Messages whose
// body is longer than maxBody are never held, since they could not be shown
// in full.
func New(filter Filter, maxBody int64) *Queue {
	return &Queue{filter: filter, maxBody: maxBody, settings: Settings{SkipStatic: true}}
}

// Subscribe calls fn after every change of State.
func (q *Queue) Subscribe(fn func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.subs = append(q.subs, fn)
}

func (q *Queue) notify() {
	q.mu.Lock()
	subs := q.subs
	q.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// State returns the settings and held messages, oldest first.
func (q *Queue) State() State {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := State{Settings: q.settings, Pending: make([]Item, len(q.pending))}
	for i, it := range q.pending {
		s.Pending[i] = it.public()
	}
	return s
}

func (it *Item) public() Item {
	c := *it
	c.raw, c.decide = nil, nil
	return c
}

// Configure changes the settings. Messages that would no longer be held are
// forwarded unchanged.
func (q *Queue) Configure(s Settings) {
	q.mu.Lock()
	q.settings = s
	var keep, release []*Item
	for _, it := range q.pending {
		if (it.Kind == "request" && s.Requests) || (it.Kind == "response" && s.Responses) {
			keep = append(keep, it)
		} else {
			release = append(release, it)
		}
	}
	q.pending = keep
	q.mu.Unlock()
	for _, it := range release {
		it.decide <- decision{}
	}
	q.notify()
}

// Get returns a held message and its text.
func (q *Queue) Get(id int64) (Item, []byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range q.pending {
		if it.ID == id {
			return it.public(), it.raw, true
		}
	}
	return Item{}, nil, false
}

// Forward releases a held message. A nil raw sends it unchanged; otherwise
// raw is the edited text, which must parse or the message stays held.
func (q *Queue) Forward(id int64, raw []byte) error {
	if raw != nil {
		it, _, ok := q.Get(id)
		if !ok {
			return ErrNotFound
		}
		var err error
		if it.Kind == "request" {
			_, err = rawhttp.ParseRequest(raw)
		} else {
			_, err = rawhttp.ParseResponse(raw)
		}
		if err != nil {
			return err
		}
	}
	it := q.take(id)
	if it == nil {
		return ErrNotFound
	}
	it.decide <- decision{raw: raw}
	return nil
}

// Drop releases a held message without passing it on.
func (q *Queue) Drop(id int64) error {
	it := q.take(id)
	if it == nil {
		return ErrNotFound
	}
	it.decide <- decision{drop: true}
	return nil
}

func (q *Queue) take(id int64) *Item {
	q.mu.Lock()
	var found *Item
	for i, it := range q.pending {
		if it.ID == id {
			found = it
			q.pending = append(q.pending[:i:i], q.pending[i+1:]...)
			break
		}
	}
	q.mu.Unlock()
	if found != nil {
		q.notify()
	}
	return found
}

// hold queues it and waits for a decision, the queue letting it go, or ctx.
func (q *Queue) hold(ctx context.Context, it *Item, kind string) (decision, bool) {
	it.Kind, it.Time, it.decide = kind, time.Now(), make(chan decision, 1)
	q.mu.Lock()
	on := q.settings.Requests
	if kind == "response" {
		on = q.settings.Responses
	}
	if !on { // turned off while the body was read
		q.mu.Unlock()
		return decision{}, true
	}
	q.nextID++
	it.ID = q.nextID
	q.pending = append(q.pending, it)
	q.mu.Unlock()
	q.notify()
	select {
	case d := <-it.decide:
		return d, true
	case <-ctx.Done():
		q.take(it.ID)
		return decision{}, false
	}
}

// OnRequest holds req while requests are intercepted.
func (q *Queue) OnRequest(f *flow.Flow, req *http.Request) pipeline.Action {
	if !q.wants(req, false) {
		return pipeline.Continue
	}
	body, whole, err := rawhttp.ReadBody(req, q.maxBody)
	if err != nil {
		f.Note = "intercept: reading the request body failed: " + err.Error()
		return pipeline.Drop
	}
	if !whole {
		f.Note = "not intercepted: the body is larger than the capture limit"
		return pipeline.Continue
	}
	raw := append(rawhttp.RequestHead(req), body...)
	it := &Item{FlowID: f.ID, Method: req.Method, URL: req.URL.String(), Length: len(raw), Binary: !utf8.Valid(body), raw: raw}
	d, ok := q.hold(req.Context(), it, "request")
	switch {
	case !ok:
		f.Note = "the client gave up while the request was held"
		return pipeline.Drop
	case d.drop:
		f.Note = "request dropped in intercept"
		return pipeline.Drop
	case d.raw != nil:
		edited, err := rawhttp.ParseRequest(d.raw) // validated by Forward
		if err != nil {
			return pipeline.Continue
		}
		f.KeepOriginalRequest(raw)
		rawhttp.ReplaceRequest(req, edited)
	}
	return pipeline.Continue
}

// OnResponse holds resp while responses are intercepted.
func (q *Queue) OnResponse(f *flow.Flow, resp *http.Response) pipeline.Action {
	if resp.Request == nil || !q.wants(resp.Request, true) {
		return pipeline.Continue
	}
	body, whole, err := rawhttp.ReadResponseBody(resp, q.maxBody)
	if err != nil || !whole {
		return pipeline.Continue
	}
	raw := append(rawhttp.ResponseHead(resp), body...)
	// A compressed body is shown inflated, without Content-Encoding, so it can
	// be read and edited; forwarding it unchanged still sends the original.
	shown := raw
	if d := rawhttp.Decompressed(raw); d != nil {
		shown = d
		_, body = rawhttp.Split(d)
	}
	it := &Item{
		FlowID: f.ID, Method: resp.Request.Method, URL: resp.Request.URL.String(), Status: resp.StatusCode,
		Length: len(shown), Binary: !utf8.Valid(body), raw: shown,
	}
	d, ok := q.hold(resp.Request.Context(), it, "response")
	switch {
	case !ok:
		return pipeline.Drop
	case d.drop:
		f.Note = "response dropped in intercept"
		return pipeline.Drop
	case d.raw != nil:
		edited, err := rawhttp.ParseResponse(d.raw)
		if err != nil {
			return pipeline.Continue
		}
		f.KeepOriginalResponse(raw)
		rawhttp.ReplaceResponse(resp, edited)
	}
	return pipeline.Continue
}

func (q *Queue) wants(req *http.Request, response bool) bool {
	q.mu.Lock()
	s := q.settings
	q.mu.Unlock()
	on := s.Requests
	if response {
		on = s.Responses
	}
	if !on || (s.SkipStatic && isStatic(req.URL.Path)) {
		return false
	}
	return q.filter == nil || q.filter(req)
}

var staticExt = map[string]bool{
	".gif": true, ".jpg": true, ".jpeg": true, ".png": true, ".webp": true, ".avif": true, ".ico": true,
	".svg": true, ".css": true, ".js": true, ".mjs": true, ".map": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".eot": true, ".mp4": true, ".webm": true, ".mp3": true,
}

func isStatic(p string) bool { return staticExt[strings.ToLower(path.Ext(p))] }
