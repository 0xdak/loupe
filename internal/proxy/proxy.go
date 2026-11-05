// Package proxy implements the intercepting HTTP proxy.
//
// Plain HTTP requests are parsed, passed through the hook pipeline, forwarded
// and recorded. For CONNECT requests the proxy terminates TLS with a
// certificate from its own authority, so the decrypted requests take the same
// path; anything that is not TLS is tunnelled unchanged.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"lightproxy/internal/ca"
	"lightproxy/internal/flow"
	"lightproxy/internal/history"
	"lightproxy/internal/pipeline"
	"lightproxy/internal/rawhttp"
	"lightproxy/internal/websocket"
)

// DefaultMaxBody is the number of body bytes recorded per message by default.
const DefaultMaxBody = 10 << 20

// Config holds optional proxy settings.
type Config struct {
	// MaxBody is how many bytes of each body are recorded. Bodies are always
	// forwarded in full. Zero or less means DefaultMaxBody.
	MaxBody int64
	// DialTimeout limits connecting to upstream servers. Zero means 15s.
	DialTimeout time.Duration
	// Logger receives hook failures and recording errors. Nil means slog.Default().
	Logger *slog.Logger
	// CA enables TLS interception. Nil tunnels HTTPS without inspecting it.
	CA *ca.Authority
	// InsecureUpstream skips verifying upstream server certificates, for
	// testing servers with self-signed certificates.
	InsecureUpstream bool
	// WebSockets receives WebSocket messages. Nil relays them without recording.
	WebSockets *websocket.Store
}

// Proxy is an http.Handler that acts as a forward proxy.
type Proxy struct {
	hooks     *pipeline.Chain
	history   *history.Store
	transport *http.Transport
	dialer    *net.Dialer
	maxBody   int64
	log       *slog.Logger
	ca        *ca.Authority
	tlsConfig *tls.Config
	ws        *websocket.Store
}

// New returns a proxy that runs traffic through hooks and records it in store.
func New(hooks *pipeline.Chain, store *history.Store, cfg Config) *Proxy {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	dialer := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.InsecureUpstream}
	return &Proxy{
		tlsConfig: tlsConfig,
		ws:        cfg.WebSockets,
		hooks:     hooks,
		history:   store,
		dialer:    dialer,
		maxBody:   cfg.MaxBody,
		log:       cfg.Logger,
		ca:        cfg.CA,
		transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     tlsConfig,
			DisableCompression:  true, // pass Accept-Encoding and bodies through untouched
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
}

// ServeHTTP dispatches proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.handleConnect(w, r)
	case !r.URL.IsAbs() || r.URL.Hostname() == "lightproxy":
		// Not a proxy request: the proxy address, or http://lightproxy/, was opened directly.
		p.serveInfo(w, r)
	default:
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if isWebSocket(r) {
		p.handleWebSocket(w, r)
		return
	}
	f := p.newFlow(r)
	defer p.record(f)

	out := r.Clone(r.Context())
	out.RequestURI = ""
	prepareOutbound(out)
	limitEncodings(out.Header)

	act, errs := p.hooks.RunRequest(f, out)
	p.logHookErrors(f, errs)
	if act == pipeline.Drop {
		f.Request = rawhttp.RequestHead(out)
		f.Error = "dropped by request hook"
		http.Error(w, "request dropped by proxy", http.StatusBadGateway)
		return
	}
	prepareOutbound(out) // hooks may have replaced the headers

	// Capture after the hooks so the record shows what was actually sent.
	reqBody := newCapture(p.maxBody)
	if out.Body != nil && out.Body != http.NoBody {
		out.Body = teeReadCloser{io.TeeReader(out.Body, reqBody), out.Body}
	}
	f.Method, f.URL, f.Target = out.Method, out.URL.String(), targetOf(out.URL)

	resp, err := p.transport.RoundTrip(out)
	defer func() {
		f.Request = append(rawhttp.RequestHead(out), reqBody.Bytes()...)
		f.Truncated = f.Truncated || reqBody.Truncated()
	}()
	if err != nil {
		f.Error = err.Error()
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)

	act, errs = p.hooks.RunResponse(f, resp)
	p.logHookErrors(f, errs)
	f.Status = resp.StatusCode
	if act == pipeline.Drop {
		f.Response = rawhttp.ResponseHead(resp)
		f.Error = "dropped by response hook"
		http.Error(w, "response dropped by proxy", http.StatusBadGateway)
		return
	}

	respBody := newCapture(p.maxBody)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = copyFlushing(w, io.TeeReader(resp.Body, respBody))
	f.Response = append(rawhttp.ResponseHead(resp), respBody.Bytes()...)
	f.Truncated = respBody.Truncated()
	if err != nil {
		f.Error = "relaying response: " + err.Error()
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	f := p.newFlow(r)
	f.URL = r.Host
	f.Request = connectHead(r)
	record := true
	defer func() {
		if record {
			p.record(f)
		}
	}()

	host, portStr, err := net.SplitHostPort(r.Host)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil {
		f.Error = "invalid CONNECT target"
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	f.Target = flow.Target{Host: host, Port: port}

	client, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		f.Error = "hijack: " + err.Error()
		http.Error(w, "proxy cannot tunnel this connection", http.StatusInternalServerError)
		return
	}
	const established = "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := io.WriteString(client, established); err != nil {
		client.Close()
		f.Error = err.Error()
		return
	}
	f.Status = http.StatusOK
	f.Response = []byte(established)

	// The client may already have sent bytes that sit in the server's buffer.
	var fromClient io.Reader = client
	if n := brw.Reader.Buffered(); n > 0 {
		fromClient = io.MultiReader(io.LimitReader(brw.Reader, int64(n)), client)
	}
	conn := &bufferedConn{Conn: client, r: bufio.NewReader(fromClient)}

	isTLS, closed := conn.peekTLS()
	if closed {
		// Browsers open spare connections and close them unused; nothing to record.
		record = false
		client.Close()
		return
	}
	if p.ca != nil && isTLS {
		f.Target.TLS = true
		if err := p.intercept(conn, host, port); err != nil {
			f.Error = "TLS handshake with the client failed; it may not trust the lightproxy CA or may pin certificates: " + err.Error()
			return
		}
		record = false // the decrypted requests are recorded one by one
		return
	}

	upstream, err := p.dialer.DialContext(context.Background(), "tcp", r.Host)
	if err != nil {
		client.Close()
		f.Error = err.Error()
		return
	}
	sent, received := tunnel(client, conn, upstream)
	f.Note = fmt.Sprintf("tunnel, not inspected: %d bytes sent, %d bytes received", sent, received)
}

// intercept terminates the client's TLS connection and serves the requests
// inside it through the normal HTTP path, aimed at the CONNECT target.
func (p *Proxy) intercept(conn net.Conn, host string, port int) error {
	tlsConn := tls.Server(conn, p.ca.ServerConfig(host))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return err
	}

	authority := net.JoinHostPort(host, strconv.Itoa(port))
	if port == 443 {
		authority = strings.TrimSuffix(authority, ":443")
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = "https"
			r.URL.Host = authority
			p.handleHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Serve returns once the single connection is accepted; the connection
	// itself keeps being served on its own goroutine until it closes.
	srv.Serve(&oneConnListener{conn: tlsConn})
	return nil
}

// Send sends request text to target, as Repeater does, and records the
// exchange in the history.
func (p *Proxy) Send(ctx context.Context, target flow.Target, raw []byte) (*flow.Flow, error) {
	f, err := p.Exchange(ctx, target, raw)
	if err != nil {
		return nil, err
	}
	f.ID, f.Source = p.history.NextID(), "repeater"
	p.record(f)
	return f, nil
}

// Exchange sends request text to target without recording it. Hooks do not
// run, so the request goes out exactly as written. Errors from parsing are
// returned; upstream failures are reported in the flow.
func (p *Proxy) Exchange(ctx context.Context, target flow.Target, raw []byte) (*flow.Flow, error) {
	req, err := rawhttp.ParseRequest(raw)
	if err != nil {
		return nil, err
	}
	scheme, port := "http", 80
	if target.TLS {
		scheme, port = "https", 443
	}
	authority := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	if target.Port == port {
		authority = target.Host
		if strings.Contains(authority, ":") {
			authority = "[" + authority + "]"
		}
	}
	req.URL.Scheme, req.URL.Host = scheme, authority
	if req.Host == "" {
		req.Host = authority
	}
	prepareOutbound(req)
	req = req.WithContext(ctx)

	f := &flow.Flow{Start: time.Now(), Method: req.Method, URL: req.URL.String(), Target: target}
	defer func() { f.Duration = time.Since(f.Start) }()
	body, _ := req.GetBody()
	sent, _ := io.ReadAll(body)
	f.Request = append(rawhttp.RequestHead(req), sent...)

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		f.Error = err.Error()
		return f, nil
	}
	defer resp.Body.Close()
	f.Status = resp.StatusCode
	got := newCapture(p.maxBody)
	_, err = io.Copy(got, resp.Body)
	f.Response = append(rawhttp.ResponseHead(resp), got.Bytes()...)
	f.Truncated = got.Truncated()
	if err != nil {
		f.Error = "reading the response: " + err.Error()
	}
	return f, nil
}

func (p *Proxy) serveInfo(w http.ResponseWriter, r *http.Request) {
	if p.ca != nil && (r.URL.Path == "/cert" || r.URL.Path == "/lightproxy-ca.crt") {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="lightproxy-ca.crt"`)
		w.Write(p.ca.CertPEM())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "lightproxy is running.\nSet this address as the HTTP proxy of your browser or client.\n")
	if p.ca != nil {
		io.WriteString(w, "Download the CA certificate from /cert (through the proxy: http://lightproxy/cert).\n")
	}
}

func (p *Proxy) newFlow(r *http.Request) *flow.Flow {
	return &flow.Flow{
		ID:     p.history.NextID(),
		Start:  time.Now(),
		Source: "proxy",
		Method: r.Method,
		URL:    r.URL.String(),
	}
}

func (p *Proxy) record(f *flow.Flow) {
	f.Duration = time.Since(f.Start)
	if err := p.history.Add(f); err != nil {
		p.log.Error("recording flow", "id", f.ID, "err", err)
	}
}

func (p *Proxy) logHookErrors(f *flow.Flow, errs []error) {
	for _, err := range errs {
		p.log.Warn("hook failed", "flow", f.ID, "err", err)
	}
}

// tunnel copies bytes both ways until both directions are finished.
func tunnel(client net.Conn, fromClient io.Reader, upstream net.Conn) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	sent, _ = io.Copy(upstream, fromClient)
	closeWrite(upstream)
	wg.Wait()
	client.Close()
	upstream.Close()
	return sent, received
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// copyFlushing relays a response body and flushes after every chunk so
// streaming responses such as server-sent events reach the client promptly.
func copyFlushing(w http.ResponseWriter, r io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			written, werr := w.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
			rc.Flush()
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// hopHeaders apply to a single connection and must not be forwarded (RFC 9110 7.6.1).
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// limitEncodings keeps only the content codings that can be decoded for
// display (gzip and deflate), as Burp does by default, so responses are not
// compressed with brotli or zstd.
func limitEncodings(h http.Header) {
	v := h.Get("Accept-Encoding")
	if v == "" {
		return
	}
	var keep []string
	for _, part := range strings.Split(v, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "gzip", "deflate", "identity":
			keep = append(keep, strings.TrimSpace(part))
		}
	}
	if len(keep) == 0 {
		h.Del("Accept-Encoding")
		return
	}
	h.Set("Accept-Encoding", strings.Join(keep, ", "))
}

// prepareOutbound strips hop-by-hop headers and stops the transport adding
// Go's default User-Agent to requests that had none.
func prepareOutbound(r *http.Request) {
	removeHopHeaders(r.Header)
	if _, ok := r.Header["User-Agent"]; !ok {
		r.Header["User-Agent"] = nil
	}
}

func removeHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func targetOf(u *url.URL) flow.Target {
	t := flow.Target{Host: u.Hostname(), TLS: u.Scheme == "https"}
	if port, err := strconv.Atoi(u.Port()); err == nil {
		t.Port = port
	} else if t.TLS {
		t.Port = 443
	} else {
		t.Port = 80
	}
	return t
}

func connectHead(r *http.Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", r.Host)
	r.Header.Write(&b)
	b.WriteString("\r\n")
	return b.Bytes()
}

// bufferedConn reads through a bufio.Reader so the first bytes can be peeked.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// peekTLS reports whether the client's first byte is a TLS handshake record,
// and whether the client closed the connection without sending anything.
//
// A client that stays silent for 30 seconds is treated as non-TLS, so
// protocols in which the server speaks first still get tunnelled.
func (c *bufferedConn) peekTLS() (isTLS, closed bool) {
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	b, err := c.r.Peek(1)
	c.SetReadDeadline(time.Time{})
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// Nothing was read, so a fresh reader loses no data and drops the
		// stored timeout error that would otherwise end the tunnel.
		c.r = bufio.NewReader(c.Conn)
		return false, false
	}
	if err != nil {
		return false, true
	}
	return b[0] == 0x16, false
}

// oneConnListener hands a single connection to http.Server.Serve.
type oneConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type teeReadCloser struct {
	io.Reader
	io.Closer
}

// capture records up to limit bytes of a stream. The request body is written
// by the transport's goroutine, so access is locked.
type capture struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func newCapture(limit int64) *capture { return &capture{limit: limit} }

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - int64(c.buf.Len())
	switch {
	case int64(len(p)) <= room:
		c.buf.Write(p)
	case room > 0:
		c.buf.Write(p[:room])
		c.truncated = true
	case len(p) > 0:
		c.truncated = true
	}
	return len(p), nil
}

func (c *capture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes())
}

func (c *capture) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}
