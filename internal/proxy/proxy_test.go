package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lightproxy/internal/ca"
	"lightproxy/internal/flow"
	"lightproxy/internal/history"
	"lightproxy/internal/pipeline"
)

type env struct {
	store    *history.Store
	hooks    *pipeline.Chain
	proxyURL *url.URL
}

func newEnv(t *testing.T) *env { return newEnvWith(t, Config{}) }

func newEnvWith(t *testing.T, cfg Config) *env {
	t.Helper()
	store, err := history.Open(filepath.Join(t.TempDir(), "history.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	hooks := &pipeline.Chain{}
	srv := httptest.NewServer(New(hooks, store, cfg))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &env{store: store, hooks: hooks, proxyURL: u}
}

func (e *env) client() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(e.proxyURL)}}
}

// waitFlows waits for n flows, since a flow is recorded after the client
// has already received its response.
func (e *env) waitFlows(t *testing.T, n int) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if flows := e.store.Recent(100); len(flows) >= n {
			return flows
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d flow(s), have %d", n, len(e.store.Recent(100)))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestForwardsHTTPAndRecordsFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Connection") != "" {
			t.Error("hop-by-hop header Proxy-Connection was forwarded")
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "yes")
		fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, body)
	}))
	defer upstream.Close()
	e := newEnv(t)

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/echo", strings.NewReader("ping"))
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if got := string(body); got != "POST /echo ping" {
		t.Errorf("body = %q", got)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Error("upstream response header missing")
	}

	f := e.waitFlows(t, 1)[0]
	if f.Status != 200 || f.Method != "POST" || f.Target.Host != "127.0.0.1" || f.Target.TLS {
		t.Errorf("unexpected flow: %+v", f)
	}
	for _, want := range []string{"POST /echo HTTP/1.1", "\r\n\r\nping"} {
		if !bytes.Contains(f.Request, []byte(want)) {
			t.Errorf("recorded request lacks %q:\n%s", want, f.Request)
		}
	}
	if !bytes.Contains(f.Response, []byte("POST /echo ping")) {
		t.Errorf("recorded response lacks body:\n%s", f.Response)
	}
}

type headerHook struct{}

func (headerHook) OnRequest(_ *flow.Flow, r *http.Request) pipeline.Action {
	r.Header.Set("X-Hooked", "1")
	return pipeline.Continue
}

type panicHook struct{}

func (panicHook) OnRequest(*flow.Flow, *http.Request) pipeline.Action { panic("boom") }

type dropHook struct{}

func (dropHook) OnRequest(*flow.Flow, *http.Request) pipeline.Action { return pipeline.Drop }

func TestHooksModifyAndSurvivePanics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Hooked"))
	}))
	defer upstream.Close()
	e := newEnv(t)
	e.hooks.Register("panics", panicHook{})
	e.hooks.Register("adds header", headerHook{})

	resp, err := e.client().Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "1" {
		t.Errorf("hook after a panicking hook did not run; upstream saw X-Hooked=%q", body)
	}
}

func TestDropHookStopsRequest(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	e := newEnv(t)
	unregister := e.hooks.Register("drop", dropHook{})

	resp, err := e.client().Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("status %d, upstream hits %d; want 502 and 0", resp.StatusCode, hits.Load())
	}
	if f := e.waitFlows(t, 1)[0]; !strings.Contains(f.Error, "dropped") {
		t.Errorf("flow error = %q", f.Error)
	}

	unregister()
	resp, err = e.client().Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Errorf("after unregister: status %d, hits %d", resp.StatusCode, hits.Load())
	}
}

func TestConnectTunnelsTLS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure")
	}))
	defer upstream.Close()
	e := newEnv(t)

	tr := upstream.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(e.proxyURL)
	resp, err := (&http.Client{Transport: tr}).Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secure" {
		t.Errorf("body = %q", body)
	}

	tr.CloseIdleConnections() // ends the tunnel, which records the flow
	f := e.waitFlows(t, 1)[0]
	if f.Method != http.MethodConnect || f.Status != 200 || !strings.Contains(f.Note, "tunnel") {
		t.Errorf("unexpected CONNECT flow: %+v", f)
	}
}

func newCA(t *testing.T) *ca.Authority {
	t.Helper()
	a, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestInterceptsTLSAndRecordsDecryptedFlow(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secret page "+r.URL.Path)
	}))
	defer upstream.Close()
	authority := newCA(t)
	e := newEnvWith(t, Config{CA: authority, InsecureUpstream: true}) // httptest's certificate is self-signed

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(authority.CertPEM())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(e.proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
	resp, err := client.Get(upstream.URL + "/inside")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "secret page /inside" {
		t.Errorf("body = %q", body)
	}
	if issuer := resp.TLS.PeerCertificates[0].Issuer.Organization; len(issuer) == 0 || issuer[0] != "lightproxy" {
		t.Errorf("client was not served a lightproxy certificate (issuer %v)", issuer)
	}

	f := e.waitFlows(t, 1)[0]
	if !strings.HasPrefix(f.URL, "https://") || !f.Target.TLS || f.Status != 200 {
		t.Errorf("unexpected flow: %+v", f)
	}
	if !bytes.Contains(f.Response, []byte("secret page /inside")) {
		t.Errorf("decrypted response not recorded:\n%s", f.Response)
	}
}

func TestClientRejectingCAIsRecorded(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	e := newEnvWith(t, Config{CA: newCA(t), InsecureUpstream: true})

	if _, err := e.client().Get(upstream.URL); err == nil {
		t.Fatal("a client that does not trust the CA should fail the handshake")
	}
	f := e.waitFlows(t, 1)[0]
	if f.Method != http.MethodConnect || !strings.Contains(f.Error, "TLS handshake") {
		t.Errorf("unexpected flow: %+v", f)
	}
}

func TestUnusedConnectIsNotRecorded(t *testing.T) {
	e := newEnvWith(t, Config{CA: newCA(t)})
	conn, err := net.Dial("tcp", e.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	conn.Close() // like a browser discarding a spare connection

	// A flow that is a sign of failure would show up well within this time.
	time.Sleep(300 * time.Millisecond)
	if n := len(e.store.Recent(10)); n != 0 {
		t.Errorf("unused CONNECT produced %d flow(s): %+v", n, e.store.Recent(10)[0])
	}
}

func TestServesCACertificate(t *testing.T) {
	authority := newCA(t)
	e := newEnvWith(t, Config{CA: authority})
	resp, err := e.client().Get("http://lightproxy/cert")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(body, authority.CertPEM()) {
		t.Error("http://lightproxy/cert did not return the CA certificate")
	}
}

func TestDirectRequestShowsInfoPage(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.proxyURL.String())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "lightproxy is running") {
		t.Errorf("body = %q", body)
	}
}
