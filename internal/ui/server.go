// Package ui serves the browser-based interface: proxy history, intercept,
// repeater, intruder, decoder and settings.
package ui

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"loupe/internal/assist"
	"loupe/internal/flow"
	"loupe/internal/history"
	"loupe/internal/intercept"
	"loupe/internal/intruder"
	"loupe/internal/rawhttp"
	"loupe/internal/rules"
	"loupe/internal/scope"
	"loupe/internal/websocket"
)

//go:embed static
var static embed.FS

// Options configures the UI server. Intercept and Scope are required.
type Options struct {
	// ProxyAddr is the address clients should use as their HTTP proxy.
	ProxyAddr string
	// OpenBrowser starts a browser routed through the proxy. Nil disables the button.
	OpenBrowser func() error
	// CACert is the interception CA in PEM form. Nil means HTTPS is not decrypted.
	CACert     []byte
	Intercept  *intercept.Queue
	Scope      *scope.Scope
	Sender     Sender            // Repeater
	Rules      *rules.Engine     // match and replace
	Intruder   *intruder.Manager // nil disables Intruder
	WebSockets *websocket.Store  // nil disables WebSockets history
	// Assistant answers questions about an exchange. Nil disables the
	// assistant; AssistantErr then says why. AssistantName labels the active
	// model in the interface (e.g. "Claude", "Ollama · qwen2.5").
	Assistant     Chatter
	AssistantErr  string
	AssistantName string
}

// Chatter talks to Claude about an HTTP exchange.
type Chatter interface {
	Chat(ctx context.Context, ex assist.Exchange, history []assist.Message, onText func(string)) error
}

// Sender sends request text to a target and records the exchange.
type Sender interface {
	Send(ctx context.Context, target flow.Target, raw []byte) (*flow.Flow, error)
}

// Server is the UI's http.Handler.
type Server struct {
	store *history.Store
	opts  Options
	mux   *http.ServeMux

	mu      sync.Mutex
	clients map[chan event]struct{}
}

// event is one server-sent event. An empty name is a new flow.
type event struct {
	name string
	data []byte
}

// New returns a UI server for store. It subscribes to changes immediately.
func New(store *history.Store, opts Options) *Server {
	s := &Server{store: store, opts: opts, mux: http.NewServeMux(), clients: map[chan event]struct{}{}}
	files, _ := fs.Sub(static, "static")
	m := s.mux
	m.Handle("GET /", http.FileServerFS(files))
	m.HandleFunc("GET /api/info", s.info)
	m.HandleFunc("GET /api/events", s.events)
	m.HandleFunc("GET /api/flows", s.listFlows)
	m.HandleFunc("GET /api/flows/{id}", s.getFlow)
	m.HandleFunc("POST /api/browser", s.openBrowser)
	m.HandleFunc("GET /loupe-ca.crt", s.caCert)
	m.HandleFunc("GET /api/scope", s.getScope)
	m.HandleFunc("PUT /api/scope", s.putScope)
	m.HandleFunc("GET /api/intercept", s.getIntercept)
	m.HandleFunc("PUT /api/intercept", s.putIntercept)
	m.HandleFunc("GET /api/intercept/{id}", s.getHeld)
	m.HandleFunc("POST /api/intercept/{id}", s.decideHeld)
	m.HandleFunc("POST /api/repeater", s.repeat)
	m.HandleFunc("GET /api/rules", s.getRules)
	m.HandleFunc("PUT /api/rules", s.putRules)
	m.HandleFunc("POST /api/intruder", s.startAttack)
	m.HandleFunc("GET /api/intruder/{id}", s.getAttack)
	m.HandleFunc("POST /api/intruder/{id}/stop", s.stopAttack)
	m.HandleFunc("DELETE /api/intruder/{id}", s.deleteAttack)
	m.HandleFunc("GET /api/intruder/{id}/results/{n}", s.getAttackResult)
	m.HandleFunc("GET /api/ws", s.listWS)
	m.HandleFunc("GET /api/ws/{id}", s.getWS)
	m.HandleFunc("POST /api/assist", s.assist)

	store.Subscribe(func(f *flow.Flow) { s.broadcastJSON("", s.summarize(f)) })
	opts.Intercept.Subscribe(func() { s.broadcastJSON("intercept", opts.Intercept.State()) })
	if opts.Intruder != nil {
		opts.Intruder.Subscribe(func(a *intruder.Attack, r *intruder.Result) {
			s.broadcastJSON("intruder", map[string]any{"status": a.Status(false), "result": r})
		})
	}
	if opts.WebSockets != nil {
		opts.WebSockets.Subscribe(func(m *websocket.Message) { s.broadcastJSON("ws", wsSummary(m)) })
	}
	return s
}

// ServeHTTP only answers requests addressed to a loopback name, so a web page
// cannot read captured traffic through DNS rebinding.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		http.Error(w, "the UI only answers on localhost", http.StatusForbidden)
		return
	}
	// Changes need a custom header: a cross-site page cannot send one without
	// a CORS preflight, which this server never approves.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Lightproxy") != "1" {
		http.Error(w, "missing X-Lightproxy header", http.StatusForbidden)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	s.mux.ServeHTTP(w, r)
}

// summary is the list view of a flow, without message bytes.
type summary struct {
	ID        int64     `json:"id"`
	Start     time.Time `json:"start"`
	Millis    int64     `json:"ms"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	URL       string    `json:"url"`
	TLS       bool      `json:"tls"`
	Status    int       `json:"status"`
	Source    string    `json:"source,omitempty"`
	InScope   bool      `json:"inScope"`
	Noise     bool      `json:"noise,omitempty"`
	Edited    bool      `json:"edited,omitempty"`
	Params    bool      `json:"params,omitempty"`
	MIME      string    `json:"mime,omitempty"`
	Ext       string    `json:"ext,omitempty"`
	ReqSize   int       `json:"reqSize"`
	RespSize  int       `json:"respSize"`
	Truncated bool      `json:"truncated,omitempty"`
	Error     string    `json:"error,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// detail carries whole messages; []byte fields travel as base64 so binary
// bodies survive and can be shown as hex.
type detail struct {
	summary
	Request          []byte `json:"request"`
	Response         []byte `json:"response"`
	ResponseDecoded  []byte `json:"responseDecoded,omitempty"` // gzip/deflate body inflated
	OriginalRequest  []byte `json:"originalRequest,omitempty"`
	OriginalResponse []byte `json:"originalResponse,omitempty"`
}

func (s *Server) summarize(f *flow.Flow) summary {
	sum := summary{
		ID: f.ID, Start: f.Start, Millis: f.Duration.Milliseconds(), Method: f.Method, Source: f.Source,
		URL: f.URL, TLS: f.Target.TLS, Status: f.Status, ReqSize: len(f.Request), Edited: f.Edited,
		RespSize: len(f.Response), Truncated: f.Truncated, Error: f.Error, Note: f.Note,
	}
	if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
		sum.Host, sum.Path = u.Host, u.RequestURI()
		sum.Ext = strings.TrimPrefix(strings.ToLower(path.Ext(u.Path)), ".")
		_, body := rawhttp.Split(f.Request)
		sum.Params = u.RawQuery != "" || len(body) > 0
	} else {
		sum.Host = f.URL // CONNECT targets are plain host:port
	}
	sum.MIME = mimeType(headerValue(f.Response, "Content-Type"))
	sum.InScope, sum.Noise = s.opts.Scope.Includes(sum.Host), scope.Noise(sum.Host)
	return sum
}

func (s *Server) detail(f *flow.Flow) detail {
	return detail{
		summary: s.summarize(f), Request: f.Request, Response: f.Response, ResponseDecoded: rawhttp.Decode(f.Response),
		OriginalRequest: f.OriginalRequest, OriginalResponse: f.OriginalResponse,
	}
}

// headerValue returns the first value of a header in a rendered message.
func headerValue(msg []byte, name string) string {
	head, _ := rawhttp.Split(msg)
	for _, line := range strings.Split(string(head), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// mimeType names a Content-Type the way Burp's history does.
func mimeType(ct string) string {
	ct = strings.ToLower(ct)
	switch {
	case ct == "":
		return ""
	case strings.Contains(ct, "html"):
		return "HTML"
	case strings.Contains(ct, "json"):
		return "JSON"
	case strings.Contains(ct, "javascript"), strings.Contains(ct, "ecmascript"):
		return "script"
	case strings.Contains(ct, "css"):
		return "CSS"
	case strings.Contains(ct, "xml"):
		return "XML"
	case strings.HasPrefix(ct, "image/"):
		return "image"
	case strings.Contains(ct, "font"):
		return "font"
	case strings.HasPrefix(ct, "text/"):
		return "text"
	case strings.HasPrefix(ct, "video/"), strings.HasPrefix(ct, "audio/"):
		return "media"
	}
	return "binary"
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"proxy": s.opts.ProxyAddr, "browser": s.opts.OpenBrowser != nil, "mitm": s.opts.CACert != nil,
		"intruder": s.opts.Intruder != nil, "websockets": s.opts.WebSockets != nil, "rules": s.opts.Rules != nil,
		"assistant": s.opts.Assistant != nil, "assistantError": s.opts.AssistantErr,
		"assistantName": s.opts.AssistantName,
	})
}

func (s *Server) caCert(w http.ResponseWriter, r *http.Request) {
	if s.opts.CACert == nil {
		http.Error(w, "HTTPS decryption is off", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="loupe-ca.crt"`)
	w.Write(s.opts.CACert)
}

func (s *Server) openBrowser(w http.ResponseWriter, r *http.Request) {
	if s.opts.OpenBrowser == nil {
		http.Error(w, "browser launching is disabled", http.StatusNotImplemented)
		return
	}
	if err := s.opts.OpenBrowser(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 1000
	}
	flows := s.store.Recent(limit)
	out := make([]summary, len(flows))
	for i, f := range flows {
		out[i] = s.summarize(f)
	}
	writeJSON(w, out)
}

func (s *Server) getFlow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r, "id")
	if !ok {
		return
	}
	f, found := s.store.Get(id)
	if !found {
		http.Error(w, "flow not in memory; use `loupe history -id` for older flows", http.StatusNotFound)
		return
	}
	writeJSON(w, s.detail(f))
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"patterns": s.opts.Scope.Patterns()})
}

func (s *Server) putScope(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Patterns []string `json:"patterns"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.opts.Scope.Set(in.Patterns); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := map[string]any{"patterns": s.opts.Scope.Patterns()}
	s.broadcastJSON("scope", out)
	writeJSON(w, out)
}

func (s *Server) getIntercept(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.opts.Intercept.State())
}

func (s *Server) putIntercept(w http.ResponseWriter, r *http.Request) {
	var in intercept.Settings
	if !readJSON(w, r, &in) {
		return
	}
	s.opts.Intercept.Configure(in)
	writeJSON(w, s.opts.Intercept.State())
}

func (s *Server) getHeld(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r, "id")
	if !ok {
		return
	}
	it, raw, found := s.opts.Intercept.Get(id)
	if !found {
		http.Error(w, intercept.ErrNotFound.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		intercept.Item
		Raw []byte `json:"raw"`
	}{it, raw})
}

func (s *Server) decideHeld(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Action string  `json:"action"`
		Raw    *string `json:"raw"` // absent: forward unchanged
	}
	if !readJSON(w, r, &in) {
		return
	}
	var err error
	switch in.Action {
	case "forward":
		var raw []byte
		if in.Raw != nil {
			raw = []byte(*in.Raw)
		}
		err = s.opts.Intercept.Forward(id, raw)
	case "drop":
		err = s.opts.Intercept.Drop(id)
	default:
		http.Error(w, `action must be "forward" or "drop"`, http.StatusBadRequest)
		return
	}
	switch {
	case errors.Is(err, intercept.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// repeat sends request text to a target given as a URL such as
// https://example.com or http://10.0.0.5:8080.
func (s *Server) repeat(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Target string `json:"target"`
		Raw    string `json:"raw"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if s.opts.Sender == nil {
		http.Error(w, "Repeater is not available", http.StatusNotImplemented)
		return
	}
	target, err := parseTarget(in.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	f, err := s.opts.Sender.Send(ctx, target, []byte(in.Raw))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.detail(f))
}

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	if s.opts.Rules == nil {
		writeJSON(w, []rules.Rule{})
		return
	}
	writeJSON(w, s.opts.Rules.Rules())
}

func (s *Server) putRules(w http.ResponseWriter, r *http.Request) {
	var in []rules.Rule
	if !readJSON(w, r, &in) {
		return
	}
	if s.opts.Rules == nil {
		http.Error(w, "match and replace is not available", http.StatusNotImplemented)
		return
	}
	if err := s.opts.Rules.Set(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.opts.Rules.Rules())
}

func (s *Server) attack(w http.ResponseWriter, r *http.Request) (*intruder.Attack, bool) {
	if s.opts.Intruder == nil {
		http.Error(w, "Intruder is not available", http.StatusNotImplemented)
		return nil, false
	}
	id, ok := pathInt(w, r, "id")
	if !ok {
		return nil, false
	}
	a, found := s.opts.Intruder.Get(id)
	if !found {
		http.Error(w, "no such attack", http.StatusNotFound)
	}
	return a, found
}

func (s *Server) startAttack(w http.ResponseWriter, r *http.Request) {
	var in struct {
		intruder.Config
		TargetURL string `json:"targetUrl"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if s.opts.Intruder == nil {
		http.Error(w, "Intruder is not available", http.StatusNotImplemented)
		return
	}
	target, err := parseTarget(in.TargetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in.Config.Target = target
	a, err := s.opts.Intruder.Start(in.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, a.Status(false))
}

func (s *Server) getAttack(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.attack(w, r); ok {
		writeJSON(w, a.Status(true))
	}
}

func (s *Server) stopAttack(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.attack(w, r); ok {
		a.Stop()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) deleteAttack(w http.ResponseWriter, r *http.Request) {
	if a, ok := s.attack(w, r); ok {
		s.opts.Intruder.Delete(a.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) getAttackResult(w http.ResponseWriter, r *http.Request) {
	a, ok := s.attack(w, r)
	if !ok {
		return
	}
	n, ok := pathInt(w, r, "n")
	if !ok {
		return
	}
	res, found := a.Result(int(n))
	if !found {
		http.Error(w, "no such result", http.StatusNotFound)
		return
	}
	writeJSON(w, struct {
		*intruder.Result
		Request         []byte `json:"request"`
		Response        []byte `json:"response"`
		ResponseDecoded []byte `json:"responseDecoded,omitempty"`
	}{res, res.Request, res.Response, rawhttp.Decode(res.Response)})
}

type wsSum struct {
	ID        int64     `json:"id"`
	FlowID    int64     `json:"flowId"`
	Time      time.Time `json:"time"`
	URL       string    `json:"url"`
	ToServer  bool      `json:"toServer"`
	Opcode    int       `json:"opcode"`
	Length    int       `json:"length"`
	Preview   string    `json:"preview"`
	Truncated bool      `json:"truncated,omitempty"`
}

func wsSummary(m *websocket.Message) wsSum {
	preview := m.Data
	if len(preview) > 200 {
		preview = preview[:200]
	}
	p := string(bytes.ToValidUTF8(preview, []byte("·")))
	if m.Opcode == websocket.OpBinary {
		p = fmt.Sprintf("[binary, %d bytes]", m.Length)
	}
	return wsSum{ID: m.ID, FlowID: m.FlowID, Time: m.Time, URL: m.URL, ToServer: m.ToServer,
		Opcode: m.Opcode, Length: m.Length, Preview: p, Truncated: m.Truncated}
}

func (s *Server) listWS(w http.ResponseWriter, r *http.Request) {
	out := []wsSum{}
	if s.opts.WebSockets != nil {
		for _, m := range s.opts.WebSockets.Recent(5000) {
			out = append(out, wsSummary(m))
		}
	}
	writeJSON(w, out)
}

func (s *Server) getWS(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(w, r, "id")
	if !ok {
		return
	}
	if s.opts.WebSockets == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	m, found := s.opts.WebSockets.Get(id)
	if !found {
		http.Error(w, "message no longer kept", http.StatusNotFound)
		return
	}
	writeJSON(w, m)
}

// assist streams Claude's answer as JSON lines: {"text": "..."} chunks, then
// {"done": true} or {"error": "..."}.
func (s *Server) assist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Exchange assist.Exchange  `json:"exchange"`
		History  []assist.Message `json:"history"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if s.opts.Assistant == nil {
		msg := s.opts.AssistantErr
		if msg == "" {
			msg = "the AI assistant is not available"
		}
		http.Error(w, msg, http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	rc := http.NewResponseController(w)
	enc := json.NewEncoder(w)
	send := func(v any) {
		enc.Encode(v)
		rc.Flush()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	err := s.opts.Assistant.Chat(ctx, in.Exchange, in.History, func(t string) { send(map[string]string{"text": t}) })
	if err != nil {
		send(map[string]string{"error": err.Error()})
		return
	}
	send(map[string]bool{"done": true})
}

func parseTarget(raw string) (flow.Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return flow.Target{}, fmt.Errorf("target must look like https://example.com or http://host:8080")
	}
	t := flow.Target{Host: u.Hostname(), TLS: u.Scheme == "https", Port: 80}
	if t.TLS {
		t.Port = 443
	}
	if u.Port() != "" {
		if t.Port, err = strconv.Atoi(u.Port()); err != nil || t.Port < 1 || t.Port > 65535 {
			return flow.Target{}, fmt.Errorf("invalid port %q", u.Port())
		}
	}
	return t, nil
}

func pathInt(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		http.Error(w, "invalid "+name, http.StatusBadRequest)
		return 0, false
	}
	return n, true
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// events streams new flows and state changes as server-sent events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ch := make(chan event, 1024)
	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
	}()

	w.WriteHeader(http.StatusOK)
	rc.Flush()
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if ev.name != "" {
				fmt.Fprintf(w, "event: %s\n", ev.name)
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", ev.data); err != nil {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
		}
		rc.Flush()
	}
}

func (s *Server) broadcastJSON(name string, v any) {
	data, _ := json.Marshal(v)
	s.broadcast(event{name: name, data: data})
}

// broadcast fans an event out to connected browsers. A browser that falls
// behind misses events rather than slowing the proxy down.
func (s *Server) broadcast(ev event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}
