package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lightproxy/internal/intercept"
	"lightproxy/internal/rules"
	"lightproxy/internal/websocket"
)

func TestInterceptEditsResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "from server")
	}))
	defer upstream.Close()
	e := newEnv(t)
	q := intercept.New(nil, DefaultMaxBody)
	e.hooks.Register("intercept", q)
	q.Configure(intercept.Settings{Responses: true})

	done := sendAsync(e.client(), "GET", upstream.URL+"/page", "")
	held := waitHeld(t, q, 1)[0]
	if held.Kind != "response" || held.Status != 200 {
		t.Fatalf("held: %+v", held)
	}
	_, raw, _ := q.Get(held.ID)
	edited := strings.Replace(strings.Replace(string(raw), "200 OK", "418 I'm a teapot", 1), "from server", "changed by hand", 1)
	if err := q.Forward(held.ID, []byte(edited)); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.status != 418 || r.body != "changed by hand" {
		t.Fatalf("client got %d %q", r.status, r.body)
	}
	f := e.waitFlows(t, 1)[0]
	if f.Status != 418 || !f.Edited || !bytes.Contains(f.OriginalResponse, []byte("from server")) ||
		!bytes.HasSuffix(f.Response, []byte("changed by hand")) {
		t.Errorf("flow: status %d edited %v\n%s", f.Status, f.Edited, f.Response)
	}
}

func TestMatchAndReplace(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Server", "secret/1.0")
		io.WriteString(w, r.Method+" "+r.URL.Path+" ua="+r.Header.Get("User-Agent")+" x="+r.Header.Get("X-Added")+" body="+string(body))
	}))
	defer upstream.Close()
	e := newEnv(t)
	engine, err := rules.Load("", DefaultMaxBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Set([]rules.Rule{
		{Enabled: true, Type: rules.RequestHeader, Match: `^User-Agent:.*$`, Replace: "User-Agent: rewritten", Regex: true},
		{Enabled: true, Type: rules.RequestHeader, Replace: "X-Added: 1"},
		{Enabled: true, Type: rules.RequestFirstLine, Match: "/old", Replace: "/new"},
		{Enabled: true, Type: rules.RequestBody, Match: "secret", Replace: "public"},
		{Enabled: true, Type: rules.ResponseHeader, Match: `^Server:.*$`, Regex: true},
		{Enabled: true, Type: rules.ResponseBody, Match: `body=(\w+)`, Replace: "body=<$1>", Regex: true},
		{Enabled: false, Type: rules.ResponseBody, Match: "POST", Replace: "never"},
	}); err != nil {
		t.Fatal(err)
	}
	e.hooks.Register("rules", engine)

	req, _ := http.NewRequest("POST", upstream.URL+"/old", strings.NewReader("secret"))
	req.Header.Set("User-Agent", "original")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "POST /new ua=rewritten x=1 body=<public>"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
	if resp.Header.Get("Server") != "" {
		t.Error("response header rule did not remove Server")
	}
	f := e.waitFlows(t, 1)[0]
	if !f.Edited || !bytes.Contains(f.OriginalRequest, []byte("POST /old")) || !bytes.Contains(f.OriginalResponse, []byte("secret/1.0")) {
		t.Errorf("originals not kept: %+v", f)
	}

	if err := engine.Set([]rules.Rule{{Type: rules.RequestBody, Match: "(", Regex: true}}); err == nil {
		t.Error("an invalid regex must be rejected")
	}
}

func TestLimitsAcceptEncoding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Accept-Encoding"))
	}))
	defer upstream.Close()
	e := newEnv(t)
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "gzip, deflate" {
		t.Errorf("upstream saw Accept-Encoding %q", body)
	}
}

// wsEcho is a minimal WebSocket server that answers every text frame with
// "echo: " and the text.
func wsEcho(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-WebSocket-Extensions") != "" {
			t.Error("compression extensions were offered upstream")
		}
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, brw, _ := http.NewResponseController(w).Hijack()
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+
			base64.StdEncoding.EncodeToString(sum[:])+"\r\n\r\n")
		for {
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(brw, hdr); err != nil {
				return
			}
			n := int(hdr[1] & 0x7f)
			key := make([]byte, 4)
			io.ReadFull(brw, key)
			p := make([]byte, n)
			io.ReadFull(brw, p)
			for i := range p {
				p[i] ^= key[i%4]
			}
			reply := append([]byte("echo: "), p...)
			conn.Write(append([]byte{0x81, byte(len(reply))}, reply...))
		}
	}))
}

func TestWebSocketRelayedAndRecorded(t *testing.T) {
	upstream := wsEcho(t)
	defer upstream.Close()
	store := websocket.NewStore(100)
	e := newEnvWith(t, Config{WebSockets: store})

	conn, err := net.Dial("tcp", e.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET "+upstream.URL+"/chat HTTP/1.1\r\nHost: "+strings.TrimPrefix(upstream.URL, "http://")+
		"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("handshake: %v %v", resp, err)
	}

	key := make([]byte, 4)
	rand.Read(key)
	msg := []byte("hi there")
	masked := bytes.Clone(msg)
	for i := range masked {
		masked[i] ^= key[i%4]
	}
	conn.Write(append(append([]byte{0x81, 0x80 | byte(len(msg))}, key...), masked...))
	hdr := make([]byte, 2)
	io.ReadFull(br, hdr)
	reply := make([]byte, hdr[1]&0x7f)
	io.ReadFull(br, reply)
	if string(reply) != "echo: hi there" {
		t.Fatalf("reply = %q", reply)
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(store.Recent(10)) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	msgs := store.Recent(10)
	if len(msgs) != 2 || !msgs[0].ToServer || string(msgs[0].Data) != "hi there" || msgs[1].ToServer || string(msgs[1].Data) != "echo: hi there" {
		t.Fatalf("messages: %+v", msgs)
	}
	f := e.waitFlows(t, 1)[0]
	if f.Status != 101 || f.Note != "WebSocket" || msgs[0].FlowID != f.ID || !strings.HasPrefix(msgs[0].URL, "ws://") {
		t.Errorf("handshake flow: %+v", f)
	}
}

func TestInterceptShowsCompressedResponseDecoded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, "compressed text")
		zw.Close()
	}))
	defer upstream.Close()
	e := newEnv(t)
	q := intercept.New(nil, DefaultMaxBody)
	e.hooks.Register("intercept", q)
	q.Configure(intercept.Settings{Responses: true})

	// Unchanged: the client gets the original gzip body.
	done := sendAsync(e.client(), "GET", upstream.URL+"/a", "")
	held := waitHeld(t, q, 1)[0]
	_, raw, _ := q.Get(held.ID)
	if !bytes.HasSuffix(raw, []byte("compressed text")) || bytes.Contains(raw, []byte("Content-Encoding")) {
		t.Fatalf("held response is not shown decoded:\n%q", raw)
	}
	q.Forward(held.ID, nil)
	if r := <-done; r.body != "compressed text" { // Go's client inflates transparently
		t.Errorf("unchanged forward: %q", r.body)
	}

	// Edited: the new body is sent as plain text.
	done = sendAsync(e.client(), "GET", upstream.URL+"/b", "")
	held = waitHeld(t, q, 1)[0]
	_, raw, _ = q.Get(held.ID)
	q.Forward(held.ID, bytes.Replace(raw, []byte("compressed text"), []byte("edited text"), 1))
	if r := <-done; r.body != "edited text" {
		t.Errorf("edited forward: %q", r.body)
	}
}
