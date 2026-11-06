package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"loupe/internal/pipeline"
	"loupe/internal/rawhttp"
	"loupe/internal/websocket"
)

// isWebSocket reports whether r asks to upgrade to the WebSocket protocol.
func isWebSocket(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") && headerHasToken(r.Header, "Upgrade", "websocket")
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// handleWebSocket forwards the upgrade handshake, then relays frames in both
// directions, recording each message. The handshake is recorded as a flow as
// soon as it completes.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	f := p.newFlow(r)
	f.Note = "WebSocket"
	recorded := false
	defer func() {
		if !recorded {
			p.record(f)
		}
	}()

	out := r.Clone(r.Context())
	out.RequestURI = ""
	prepareOutbound(out)
	// Without compression the messages can be read and recorded.
	out.Header.Del("Sec-WebSocket-Extensions")
	act, errs := p.hooks.RunRequest(f, out)
	p.logHookErrors(f, errs)
	f.Request = rawhttp.RequestHead(out)
	if act == pipeline.Drop {
		f.Error = "dropped by request hook"
		http.Error(w, "request dropped by proxy", http.StatusBadGateway)
		return
	}
	prepareOutbound(out)
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	f.Method, f.URL, f.Target = out.Method, out.URL.String(), targetOf(out.URL)
	f.Request = rawhttp.RequestHead(out)

	upstream, err := p.dialUpstream(r.Context(), out.URL)
	if err != nil {
		f.Error = err.Error()
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(f.Request); err != nil {
		f.Error = err.Error()
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	fromUpstream := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(fromUpstream, out)
	if err != nil {
		f.Error = "reading the handshake response: " + err.Error()
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	f.Status = resp.StatusCode
	f.Response = rawhttp.ResponseHead(resp)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The server refused the upgrade; pass its answer on.
		defer resp.Body.Close()
		removeHopHeaders(resp.Header)
		body := newCapture(p.maxBody)
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		copyFlushing(w, io.TeeReader(resp.Body, body))
		f.Response = append(f.Response, body.Bytes()...)
		return
	}

	client, fromClient, err := http.NewResponseController(w).Hijack()
	if err != nil {
		f.Error = "hijack: " + err.Error()
		return
	}
	defer client.Close()
	if _, err := client.Write(f.Response); err != nil {
		f.Error = err.Error()
		return
	}
	recorded = true
	p.record(f)

	wsURL := strings.Replace(f.URL, "http", "ws", 1)
	emit := func(toServer bool) func(int, []byte, int, bool) {
		return func(op int, data []byte, n int, trunc bool) {
			if p.ws != nil {
				p.ws.Add(&websocket.Message{
					FlowID: f.ID, Time: time.Now(), URL: wsURL, ToServer: toServer,
					Opcode: op, Length: n, Data: data, Truncated: trunc,
				})
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		websocket.Relay(client, fromUpstream, emit(false))
		client.Close() // unblocks the other direction
	}()
	websocket.Relay(upstream, fromClient.Reader, emit(true))
	upstream.Close()
	wg.Wait()
}

// dialUpstream opens a connection to the URL's host, with TLS for https.
func (p *Proxy) dialUpstream(ctx context.Context, u *url.URL) (net.Conn, error) {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	conn, err := p.dialer.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil || u.Scheme != "https" {
		return conn, err
	}
	cfg := p.tlsConfig.Clone()
	cfg.ServerName = u.Hostname()
	cfg.NextProtos = []string{"http/1.1"}
	tc := tls.Client(conn, cfg)
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}
