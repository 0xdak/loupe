package ui

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loupe/internal/flow"
	"loupe/internal/history"
	"loupe/internal/intercept"
	"loupe/internal/scope"
)

func newServer(t *testing.T, opts Options) (*history.Store, *httptest.Server) {
	t.Helper()
	store, err := history.Open(filepath.Join(t.TempDir(), "h.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if opts.Intercept == nil {
		opts.Intercept = intercept.New(nil, 1<<20)
	}
	if opts.Scope == nil {
		opts.Scope, _ = scope.Load("")
	}
	srv := httptest.NewServer(New(store, opts))
	t.Cleanup(srv.Close)
	return store, srv
}

func TestServesPageListAndDetail(t *testing.T) {
	store, srv := newServer(t, Options{ProxyAddr: "127.0.0.1:8080"})
	store.Add(&flow.Flow{ID: store.NextID(), Method: "GET", URL: "http://example.com/a?b=1", Status: 200,
		Request: []byte("GET /a?b=1 HTTP/1.1\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nhi")})

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "<title>loupe</title>") {
		t.Fatal("index page not served")
	}

	var list []summary
	getJSON(t, srv.URL+"/api/flows", &list)
	if len(list) != 1 || list[0].Host != "example.com" || list[0].Path != "/a?b=1" {
		t.Fatalf("list = %+v", list)
	}

	var d detail
	getJSON(t, srv.URL+"/api/flows/1", &d)
	if !strings.HasSuffix(string(d.Response), "hi") {
		t.Errorf("detail response = %q", d.Response)
	}
}

func TestEventsStreamNewFlows(t *testing.T) {
	store, srv := newServer(t, Options{})
	resp, err := http.Get(srv.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The handler registers its client before writing the header, so a flow
	// added now is delivered.
	go func() {
		time.Sleep(50 * time.Millisecond)
		store.Add(&flow.Flow{ID: store.NextID(), Method: "GET", URL: "http://x.test/"})
	}()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			var s summary
			if err := json.Unmarshal([]byte(data), &s); err != nil || s.Host != "x.test" {
				t.Fatalf("event = %q (%v)", data, err)
			}
			return
		}
	}
	t.Fatal("stream ended without an event")
}

func TestRejectsNonLocalHostAndUnsignedBrowserRequest(t *testing.T) {
	launched := 0
	_, srv := newServer(t, Options{OpenBrowser: func() error { launched++; return nil }})

	req, _ := http.NewRequest("GET", srv.URL+"/api/flows", nil)
	req.Host = "evil.example:8081"
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-local Host: status %v, err %v; want 403", resp.StatusCode, err)
	}

	resp, err := http.Post(srv.URL+"/api/browser", "text/plain", nil)
	if err != nil || resp.StatusCode != http.StatusForbidden || launched != 0 {
		t.Errorf("POST without header: status %v, launched %d; want 403 and 0", resp.StatusCode, launched)
	}

	req, _ = http.NewRequest("POST", srv.URL+"/api/browser", nil)
	req.Header.Set("X-Lightproxy", "1")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent || launched != 1 {
		t.Errorf("POST with header: status %v, launched %d; want 204 and 1", resp.StatusCode, launched)
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
