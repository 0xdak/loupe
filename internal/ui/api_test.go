package ui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"loupe/internal/assist"
	"loupe/internal/flow"
)

func call(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("X-Lightproxy", "1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestScopeMarksFlows(t *testing.T) {
	store, srv := newServer(t, Options{})
	store.Add(&flow.Flow{ID: store.NextID(), Method: "GET", URL: "https://api.shop.test/x"})
	store.Add(&flow.Flow{ID: store.NextID(), Method: "GET", URL: "https://assets.msn.com/y"})

	if code, body := call(t, "PUT", srv.URL+"/api/scope", `{"patterns":["a/b"]}`); code != 400 {
		t.Errorf("invalid pattern: %d %s", code, body)
	}
	if code, body := call(t, "PUT", srv.URL+"/api/scope", `{"patterns":["*.shop.test"]}`); code != 200 {
		t.Fatalf("set scope: %d %s", code, body)
	}
	var list []summary
	getJSON(t, srv.URL+"/api/flows", &list)
	if !list[0].InScope || list[0].Noise || list[1].InScope || !list[1].Noise {
		t.Errorf("flags: %+v", list)
	}

	req, _ := http.NewRequest("PUT", srv.URL+"/api/scope", strings.NewReader(`{"patterns":[]}`))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("change without X-Lightproxy: %d", resp.StatusCode)
	}
}

func TestInterceptEndpoints(t *testing.T) {
	_, srv := newServer(t, Options{})
	code, body := call(t, "PUT", srv.URL+"/api/intercept", `{"requests":true,"responses":true,"skipStatic":false}`)
	if code != 200 || !strings.Contains(body, `"requests":true`) || !strings.Contains(body, `"responses":true`) || !strings.Contains(body, `"skipStatic":false`) {
		t.Errorf("configure: %d %s", code, body)
	}
	if code, _ := call(t, "POST", srv.URL+"/api/intercept/42", `{"action":"forward"}`); code != 404 {
		t.Errorf("deciding an unknown request: %d", code)
	}
	if code, _ := call(t, "POST", srv.URL+"/api/intercept/42", `{"action":"explode"}`); code != 400 {
		t.Errorf("unknown action: %d", code)
	}
}

type fakeSender struct{ target flow.Target }

func (s *fakeSender) Send(_ context.Context, t flow.Target, raw []byte) (*flow.Flow, error) {
	s.target = t
	return &flow.Flow{ID: 7, Method: "GET", URL: "https://x.test/", Status: 201, Request: raw,
		Response: []byte("HTTP/1.1 201 Created\r\n\r\nok")}, nil
}

func TestRepeaterParsesTarget(t *testing.T) {
	sender := &fakeSender{}
	_, srv := newServer(t, Options{Sender: sender})
	code, body := call(t, "POST", srv.URL+"/api/repeater", `{"target":"https://x.test:8443","raw":"GET / HTTP/1.1\nHost: x.test\n"}`)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	var d detail
	json.Unmarshal([]byte(body), &d)
	if d.Status != 201 || !strings.HasSuffix(string(d.Response), "ok") {
		t.Errorf("detail = %+v", d)
	}
	if sender.target != (flow.Target{Host: "x.test", Port: 8443, TLS: true}) {
		t.Errorf("target = %+v", sender.target)
	}
	for _, bad := range []string{"x.test", "ftp://x.test", "https://x.test:99999"} {
		if code, _ := call(t, "POST", srv.URL+"/api/repeater", `{"target":"`+bad+`","raw":"GET / HTTP/1.1\n"}`); code != 400 {
			t.Errorf("target %q: status %d, want 400", bad, code)
		}
	}
}

type fakeChatter struct{ got assist.Exchange }

func (f *fakeChatter) Chat(_ context.Context, ex assist.Exchange, h []assist.Message, on func(string)) error {
	f.got = ex
	on("Hello ")
	on("there: " + h[len(h)-1].Text)
	return nil
}

func TestAssistStreams(t *testing.T) {
	fc := &fakeChatter{}
	_, srv := newServer(t, Options{Assistant: fc})
	code, body := call(t, "POST", srv.URL+"/api/assist", `{"exchange":{"target":"https://x.test","request":"GET / HTTP/1.1"},"history":[{"role":"user","text":"hi"}]}`)
	if code != 200 || body != "{\"text\":\"Hello \"}\n{\"text\":\"there: hi\"}\n{\"done\":true}\n" {
		t.Errorf("%d %q", code, body)
	}
	if fc.got.Target != "https://x.test" {
		t.Errorf("exchange = %+v", fc.got)
	}
	_, srv = newServer(t, Options{AssistantErr: "claude not found"})
	if code, body := call(t, "POST", srv.URL+"/api/assist", `{"history":[]}`); code != 501 || !strings.Contains(body, "claude not found") {
		t.Errorf("without an assistant: %d %q", code, body)
	}
}

// fakeAI is a runtime controller whose Configure records the last config and
// reports it as the active model, without touching the network.
type fakeAI struct {
	fakeChatter
	cfg assist.Config
}

func (f *fakeAI) Status() assist.Status {
	return assist.Status{
		Available: f.cfg.Provider != "", Name: f.cfg.Provider + ":" + f.cfg.Model,
		Provider: f.cfg.Provider, Model: f.cfg.Model, URL: f.cfg.URL,
		HasKey: f.cfg.APIKey != "",
	}
}
func (f *fakeAI) Configure(c assist.Config) assist.Status {
	if c.APIKey == "" {
		c.APIKey = f.cfg.APIKey // mirror the manager's keep-the-key rule
	}
	f.cfg = c
	return f.Status()
}
func (f *fakeAI) Discover() assist.Discovery {
	return assist.Discovery{Claude: true, OllamaURL: "http://localhost:11434", OllamaModels: []string{"qwen2.5-coder:1.5b"}}
}

func TestAIConfigure(t *testing.T) {
	ai := &fakeAI{cfg: assist.Config{Provider: "ollama", Model: "qwen2.5-coder:1.5b"}}
	_, srv := newServer(t, Options{Assistant: ai, AI: ai})

	// GET lists the choice and the discovered options, never a key.
	code, body := call(t, "GET", srv.URL+"/api/ai", "")
	if code != 200 || !strings.Contains(body, "qwen2.5-coder:1.5b") || !strings.Contains(body, "\"claude\":true") {
		t.Fatalf("GET /api/ai: %d %q", code, body)
	}
	if strings.Contains(body, "apiKey") {
		t.Errorf("GET /api/ai leaked a key field: %q", body)
	}

	// PUT switches provider and model.
	code, body = call(t, "PUT", srv.URL+"/api/ai", `{"provider":"openai","model":"qwen-plus","url":"http://x/v1","key":"secret"}`)
	if code != 200 || !strings.Contains(body, `"provider":"openai"`) || !strings.Contains(body, `"model":"qwen-plus"`) {
		t.Fatalf("PUT /api/ai: %d %q", code, body)
	}
	if ai.cfg.Provider != "openai" || ai.cfg.APIKey != "secret" {
		t.Errorf("controller not updated: %+v", ai.cfg)
	}

	// info reflects the live controller, not the static fields.
	if _, info := call(t, "GET", srv.URL+"/api/info", ""); !strings.Contains(info, `"assistantName":"openai:qwen-plus"`) || !strings.Contains(info, `"aiConfigurable":true`) {
		t.Errorf("info not live: %q", info)
	}

	// Without a controller the endpoint is not implemented.
	_, srv2 := newServer(t, Options{})
	if code, _ := call(t, "GET", srv2.URL+"/api/ai", ""); code != 501 {
		t.Errorf("GET /api/ai without controller = %d, want 501", code)
	}
}
