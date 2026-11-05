package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"lightproxy/internal/flow"
	"lightproxy/internal/intercept"
)

func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("X-Edit")+" "+string(body))
	}))
}

// waitHeld waits until the queue holds n requests.
func waitHeld(t *testing.T, q *intercept.Queue, n int) []intercept.Item {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if p := q.State().Pending; len(p) >= n {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d held request(s)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type result struct {
	body   string
	status int
	err    error
}

func sendAsync(c *http.Client, method, u, body string) chan result {
	ch := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest(method, u, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			ch <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- result{string(b), resp.StatusCode, nil}
	}()
	return ch
}

func TestInterceptEditAndForward(t *testing.T) {
	upstream := echoServer()
	defer upstream.Close()
	e := newEnv(t)
	q := intercept.New(nil, DefaultMaxBody)
	e.hooks.Register("intercept", q)
	q.Configure(intercept.Settings{Requests: true, SkipStatic: true})

	done := sendAsync(e.client(), "POST", upstream.URL+"/a", "original")
	held := waitHeld(t, q, 1)[0]
	_, raw, _ := q.Get(held.ID)
	if !bytes.Contains(raw, []byte("POST /a HTTP/1.1")) || !bytes.HasSuffix(raw, []byte("original")) {
		t.Fatalf("held request text:\n%s", raw)
	}
	if err := q.Forward(held.ID, []byte("not a request")); err == nil {
		t.Fatal("unparsable edit must be rejected")
	}
	// Edit as a textarea would return it: LF line ends.
	edited := strings.ReplaceAll(string(raw), "\r\n", "\n")
	edited = strings.Replace(edited, "POST /a", "PUT /b?x=1", 1)
	edited = strings.Replace(edited, "\n\n", "\nX-Edit: yes\n\n", 1)
	edited = strings.TrimSuffix(edited, "original") + "changed body"
	if err := q.Forward(held.ID, []byte(edited)); err != nil {
		t.Fatal(err)
	}

	r := <-done
	if r.err != nil || r.body != "PUT /b?x=1 yes changed body" {
		t.Fatalf("upstream saw %q (err %v)", r.body, r.err)
	}
	f := e.waitFlows(t, 1)[0]
	if !f.Edited || !bytes.Contains(f.OriginalRequest, []byte("POST /a")) || !bytes.Contains(f.Request, []byte("PUT /b?x=1")) {
		t.Errorf("flow does not record the edited request: note %q\n%s", f.Note, f.Request)
	}
}

func TestInterceptDropAndRelease(t *testing.T) {
	upstream := echoServer()
	defer upstream.Close()
	e := newEnv(t)
	q := intercept.New(nil, DefaultMaxBody)
	e.hooks.Register("intercept", q)
	q.Configure(intercept.Settings{Requests: true, SkipStatic: true})

	dropped := sendAsync(e.client(), "GET", upstream.URL+"/drop", "")
	if err := q.Drop(waitHeld(t, q, 1)[0].ID); err != nil {
		t.Fatal(err)
	}
	if r := <-dropped; r.status != http.StatusBadGateway {
		t.Errorf("dropped request: %+v", r)
	}

	if r := <-sendAsync(e.client(), "GET", upstream.URL+"/app.js", ""); r.status != 200 {
		t.Errorf("static files should pass while held requests wait: %+v", r)
	}

	a := sendAsync(e.client(), "GET", upstream.URL+"/one", "")
	b := sendAsync(e.client(), "GET", upstream.URL+"/two", "")
	waitHeld(t, q, 2)
	q.Configure(intercept.Settings{SkipStatic: true}) // turning intercept off releases everything unchanged
	for _, ch := range []chan result{a, b} {
		if r := <-ch; r.status != 200 {
			t.Errorf("released request: %+v", r)
		}
	}
	if n := len(q.State().Pending); n != 0 {
		t.Errorf("%d request(s) still held", n)
	}
}

func TestInterceptForgetsClientsThatGiveUp(t *testing.T) {
	upstream := echoServer()
	defer upstream.Close()
	e := newEnv(t)
	q := intercept.New(nil, DefaultMaxBody)
	e.hooks.Register("intercept", q)
	q.Configure(intercept.Settings{Requests: true, SkipStatic: true})

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL+"/slow", nil)
	go e.client().Do(req)
	id := waitHeld(t, q, 1)[0].ID
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for len(q.State().Pending) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("abandoned request is still held")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := q.Forward(id, nil); err != intercept.ErrNotFound {
		t.Errorf("forwarding an abandoned request: %v", err)
	}
}

func TestSendRepeatsRequestText(t *testing.T) {
	upstream := echoServer()
	defer upstream.Close()
	store := newEnv(t).store
	p := New(nil, store, Config{})
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())

	raw := "POST /again?n=2 HTTP/1.1\nHost: " + u.Host + "\nX-Edit: r\n\nhello"
	f, err := p.Send(context.Background(), flow.Target{Host: u.Hostname(), Port: port}, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != 200 || !bytes.HasSuffix(f.Response, []byte("POST /again?n=2 r hello")) || f.Source != "repeater" {
		t.Errorf("unexpected flow: status %d source %q\n%s", f.Status, f.Source, f.Response)
	}
	if got, ok := store.Get(f.ID); !ok || got != f {
		t.Error("repeated request was not recorded")
	}

	if _, err := p.Send(context.Background(), flow.Target{Host: "x", Port: 80}, []byte("garbage")); err == nil {
		t.Error("unparsable request text must be an error")
	}
	f, _ = p.Send(context.Background(), flow.Target{Host: "127.0.0.1", Port: 1}, []byte("GET / HTTP/1.1\nHost: x\n"))
	if f == nil || f.Error == "" {
		t.Errorf("connection failure should be reported in the flow: %+v", f)
	}
}
