package assist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestPrompt(t *testing.T) {
	p := prompt(Exchange{Target: "https://x.test", Request: "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n", Note: "history #3"},
		[]Message{{"user", "first?"}, {"assistant", "answer"}, {"user", "and now?"}})
	for _, want := range []string{"<target>https://x.test</target>", "GET / HTTP/1.1", "(none yet)", "<user>\nfirst?\n</user>", "<assistant>\nanswer\n</assistant>"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p)
		}
	}
	if !strings.HasSuffix(p, "and now?") {
		t.Error("the new question must come last")
	}
	if c := clip(strings.Repeat("a", MaxMessage+10)); !strings.HasSuffix(c, "[… 10 more bytes not included]") {
		t.Errorf("clip = …%q", c[len(c)-40:])
	}
}

// TestRealClaude talks to the installed CLI; it costs a request, so it only
// runs when LIGHTPROXY_TEST_CLAUDE is set.
func TestRealClaude(t *testing.T) {
	if os.Getenv("LIGHTPROXY_TEST_CLAUDE") == "" {
		t.Skip("set LIGHTPROXY_TEST_CLAUDE=1 to run")
	}
	a, err := Find()
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	err = a.Chat(context.Background(), Exchange{Request: "GET /admin?debug=true HTTP/1.1\r\nHost: shop.test\r\n\r\n"},
		[]Message{{"user", "Which query parameter does this request send? Answer with the parameter name only."}},
		func(s string) { got.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(got.String()), "debug") {
		t.Errorf("answer = %q", got.String())
	}
}

func collect(t *testing.T, be backend) string {
	t.Helper()
	var got strings.Builder
	if err := be.stream(context.Background(), "sys", "hi", func(s string) { got.WriteString(s) }); err != nil {
		t.Fatalf("stream: %v", err)
	}
	return got.String()
}

func TestOllamaStream(t *testing.T) {
	var gotModel string
	var gotMsgs []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var body struct {
			Model    string              `json:"model"`
			Messages []map[string]string `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		gotModel, gotMsgs = body.Model, body.Messages
		io.WriteString(w, `{"message":{"content":"Hel"},"done":false}`+"\n")
		io.WriteString(w, `{"message":{"content":"lo"},"done":false}`+"\n")
		io.WriteString(w, `{"message":{"content":""},"done":true}`+"\n")
	}))
	defer srv.Close()

	be := newOllama(Config{URL: srv.URL, Model: "qwen2.5"})
	if got := collect(t, be); got != "Hello" {
		t.Errorf("answer = %q, want Hello", got)
	}
	if gotModel != "qwen2.5" {
		t.Errorf("model = %q", gotModel)
	}
	if len(gotMsgs) != 2 || gotMsgs[0]["role"] != "system" || gotMsgs[1]["content"] != "hi" {
		t.Errorf("messages = %+v", gotMsgs)
	}
	if be.name() != "Ollama · qwen2.5" {
		t.Errorf("name = %q", be.name())
	}
}

func TestOllamaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":"model 'nope' not found, try pulling it first"}`)
	}))
	defer srv.Close()
	err := newOllama(Config{URL: srv.URL, Model: "nope"}).stream(context.Background(), "s", "q", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenAIStream(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		auth = r.Header.Get("Authorization")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	be, err := newOpenAI(Config{URL: srv.URL + "/v1", Model: "qwen-plus", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := collect(t, be); got != "Hello" {
		t.Errorf("answer = %q, want Hello", got)
	}
	if auth != "Bearer sk-test" {
		t.Errorf("auth = %q", auth)
	}
	if be.name() != "qwen-plus" {
		t.Errorf("name = %q", be.name())
	}
}

func TestOpenAIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"invalid api key"}}`)
	}))
	defer srv.Close()
	be, _ := newOpenAI(Config{URL: srv.URL, Model: "m"})
	err := be.stream(context.Background(), "s", "q", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{Provider: "openai"}); err == nil {
		t.Error("openai without a URL should error")
	}
	if _, err := New(Config{Provider: "openai", URL: "http://x/v1"}); err == nil {
		t.Error("openai without a model should error")
	}
	if _, err := New(Config{Provider: "bogus"}); err == nil {
		t.Error("an unknown provider should error")
	}
	if _, err := New(Config{Provider: "ollama"}); err != nil {
		t.Errorf("ollama should build without contacting the server: %v", err)
	}
}

func TestPickModel(t *testing.T) {
	if m := pickModel([]string{"llama3.2:latest", "qwen2.5:7b"}); m != "qwen2.5:7b" {
		t.Errorf("pickModel preferred %q, want the qwen model", m)
	}
	if m := pickModel([]string{"mistral", "gemma"}); m != "mistral" {
		t.Errorf("pickModel = %q", m)
	}
}
