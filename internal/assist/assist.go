// Package assist lets a person talk to an AI model about an HTTP exchange.
//
// Three backends are supported, all optional and all local-first:
//
//   - claude: the locally installed Claude Code CLI (`claude`), so no API
//     key is needed. It runs with every tool disabled, so the model can only
//     read what it is given and answer; it cannot touch files or run commands.
//   - ollama: a local Ollama server (https://ollama.com), which runs open
//     models such as Qwen or Llama entirely on this machine.
//   - openai: any OpenAI-compatible chat endpoint, which covers Qwen's cloud
//     API (DashScope), LM Studio, vLLM, llama.cpp's server and others.
package assist

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// MaxMessage is how many bytes of each HTTP message are given to the model.
const MaxMessage = 100 << 10

// Message is one turn of a conversation.
type Message struct {
	Role string `json:"role"` // "user" or "assistant"
	Text string `json:"text"`
}

// Exchange is the HTTP traffic a conversation is about.
type Exchange struct {
	Target   string `json:"target"` // e.g. https://example.com
	Request  string `json:"request"`
	Response string `json:"response"`
	Note     string `json:"note,omitempty"` // where it came from, e.g. "Proxy history #12"
}

// Config selects and configures the AI backend.
type Config struct {
	Provider string // "", "auto", "claude", "ollama" or "openai"
	Model    string // model name for ollama/openai, e.g. "qwen2.5" or "qwen-plus"
	URL      string // base URL (ollama: http://localhost:11434; openai: a .../v1 base)
	APIKey   string // bearer token for an openai-compatible endpoint
}

// backend streams a model's answer to one (system, user) turn.
type backend interface {
	name() string
	stream(ctx context.Context, system, input string, onText func(string)) error
}

// Assistant answers questions about an HTTP exchange using one backend.
type Assistant struct{ be backend }

// Name is a short label for the active model, shown in the interface.
func (a *Assistant) Name() string { return a.be.name() }

// New builds an Assistant for the chosen provider. In "auto" mode it uses the
// Claude Code CLI when it is installed, otherwise a reachable Ollama server.
func New(cfg Config) (*Assistant, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "", "auto":
		if b, err := findClaude(); err == nil {
			return &Assistant{be: b}, nil
		}
		b, err := autoOllama(cfg)
		if err != nil {
			return nil, fmt.Errorf("no AI backend found: install Claude Code (https://claude.com/claude-code), run Ollama (https://ollama.com), or pass -ai openai with -ai-url and -ai-model; %v", err)
		}
		return &Assistant{be: b}, nil
	case "claude":
		b, err := findClaude()
		if err != nil {
			return nil, err
		}
		return &Assistant{be: b}, nil
	case "ollama":
		return &Assistant{be: newOllama(cfg)}, nil
	case "openai", "openai-compatible", "qwen":
		b, err := newOpenAI(cfg)
		if err != nil {
			return nil, err
		}
		return &Assistant{be: b}, nil
	default:
		return nil, fmt.Errorf("unknown AI provider %q (use auto, claude, ollama or openai)", cfg.Provider)
	}
}

// Find locates the Claude Code CLI. It is kept for callers that want Claude
// specifically; New(Config{}) is the general entry point.
func Find() (*Assistant, error) {
	b, err := findClaude()
	if err != nil {
		return nil, err
	}
	return &Assistant{be: b}, nil
}

const systemPrompt = `You are a web security assistant built into lightproxy, an intercepting HTTP proxy similar to Burp Suite. The person using it is a security tester working on traffic they are authorized to test. They share one HTTP request and its response, and ask about them.

Answer in the language the person writes in. Be concise and concrete: refer to the actual headers, parameters and values in the exchange. When something is a guess, say so.

When you propose a modified or new HTTP request, put the complete raw request (request line, headers, blank line, body) in a code block marked http, so it can be opened in Repeater with one click. Keep the Host header and the rest of the original request unless there is a reason to change them.`

// Chat sends the conversation to the model and calls onText with the answer as
// it streams. The last message of history is the new question.
func (a *Assistant) Chat(ctx context.Context, ex Exchange, history []Message, onText func(string)) error {
	if len(history) == 0 || history[len(history)-1].Role != "user" {
		return errors.New("the conversation must end with a question")
	}
	return a.be.stream(ctx, systemPrompt, prompt(ex, history), onText)
}

// ─── Claude Code CLI backend ─────────────────────────────────────────────

type claudeBackend struct{ bin string }

func (c *claudeBackend) name() string { return "Claude" }

func findClaude() (*claudeBackend, error) {
	if p, err := exec.LookPath("claude"); err == nil {
		return &claudeBackend{bin: p}, nil
	}
	home, _ := os.UserHomeDir()
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{
			filepath.Join(home, ".local", "bin", "claude.exe"),
			filepath.Join(os.Getenv("APPDATA"), "npm", "claude.cmd"),
		}
	} else {
		candidates = []string{
			filepath.Join(home, ".local", "bin", "claude"),
			filepath.Join(home, ".claude", "local", "claude"),
			"/opt/homebrew/bin/claude", "/usr/local/bin/claude",
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return &claudeBackend{bin: c}, nil
		}
	}
	return nil, errors.New("Claude Code (the `claude` command) was not found; install it from https://claude.com/claude-code and sign in")
}

// stream runs one turn of the CLI with every tool disabled, so Claude can only
// read the input and answer; it cannot touch files or run commands.
func (c *claudeBackend) stream(ctx context.Context, system, input string, onText func(string)) error {
	cmd := exec.CommandContext(ctx, c.bin, "-p",
		"--output-format", "stream-json", "--verbose", "--include-partial-messages",
		"--tools", "", "--strict-mcp-config", "--no-session-persistence",
		"--system-prompt", system)
	// A neutral directory, so no project instructions are picked up.
	cmd.Dir = os.TempDir()
	cmd.Stdin = strings.NewReader(input)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting claude: %w", err)
	}

	var resultErr string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var line struct {
			Type    string `json:"type"`
			IsError bool   `json:"is_error"`
			Result  string `json:"result"`
			Event   struct {
				Type  string `json:"type"`
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
			} `json:"event"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		switch {
		case line.Type == "stream_event" && line.Event.Type == "content_block_delta" && line.Event.Delta.Type == "text_delta":
			onText(line.Event.Delta.Text)
		case line.Type == "result" && line.IsError:
			resultErr = line.Result
		}
	}
	err = cmd.Wait()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case resultErr != "":
		return errors.New(resultErr)
	case err != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("claude failed: %s", msg)
	}
	return nil
}

// ─── Ollama backend ──────────────────────────────────────────────────────

const defaultOllamaURL = "http://localhost:11434"

type ollamaBackend struct {
	url   string // base URL, no trailing slash
	model string
}

func (o *ollamaBackend) name() string { return "Ollama · " + o.model }

func newOllama(cfg Config) *ollamaBackend {
	url := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if url == "" {
		url = defaultOllamaURL
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = "qwen2.5"
	}
	return &ollamaBackend{url: url, model: model}
}

// autoOllama checks that Ollama is reachable and, unless a model was given,
// picks an installed one (preferring a Qwen model).
func autoOllama(cfg Config) (*ollamaBackend, error) {
	o := newOllama(cfg)
	models, err := o.tags()
	if err != nil {
		return nil, err
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("Ollama at %s has no models; pull one first, e.g. `ollama pull qwen2.5`", o.url)
	}
	if strings.TrimSpace(cfg.Model) == "" {
		o.model = pickModel(models)
	}
	return o, nil
}

func pickModel(models []string) string {
	for _, pref := range []string{"qwen", "llama", "mistral", "gemma", "phi"} {
		for _, m := range models {
			if strings.Contains(strings.ToLower(m), pref) {
				return m
			}
		}
	}
	return models[0]
}

func (o *ollamaBackend) tags() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", o.url+"/api/tags", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, unreachable(o.url, err)
	}
	defer resp.Body.Close()
	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(body.Models))
	for _, m := range body.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

func (o *ollamaBackend) stream(ctx context.Context, system, input string, onText func(string)) error {
	body, _ := json.Marshal(map[string]any{
		"model":  o.model,
		"stream": true,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": input},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", o.url+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return unreachable(o.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama: %s", readError(resp))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done  bool   `json:"done"`
			Error string `json:"error"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.Error != "" {
			return errors.New(ev.Error)
		}
		if ev.Message.Content != "" {
			onText(ev.Message.Content)
		}
		if ev.Done {
			break
		}
	}
	return streamErr(sc, ctx)
}

// ─── OpenAI-compatible backend ───────────────────────────────────────────

type openaiBackend struct {
	endpoint string // full chat-completions URL
	model    string
	key      string
}

func (o *openaiBackend) name() string { return o.model }

func newOpenAI(cfg Config) (*openaiBackend, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if base == "" {
		return nil, errors.New("the openai provider needs -ai-url, the base URL (e.g. https://dashscope-intl.aliyuncs.com/compatible-mode/v1 for Qwen, or http://localhost:1234/v1 for a local server)")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("the openai provider needs -ai-model (e.g. qwen-plus)")
	}
	endpoint := base
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	key := strings.TrimSpace(cfg.APIKey)
	for _, env := range []string{"OPENAI_API_KEY", "DASHSCOPE_API_KEY"} {
		if key == "" {
			key = os.Getenv(env)
		}
	}
	return &openaiBackend{endpoint: endpoint, model: strings.TrimSpace(cfg.Model), key: key}, nil
}

func (o *openaiBackend) stream(ctx context.Context, system, input string, onText func(string)) error {
	body, _ := json.Marshal(map[string]any{
		"model":  o.model,
		"stream": true,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": input},
		},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", o.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.key != "" {
		req.Header.Set("Authorization", "Bearer "+o.key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return unreachable(o.endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(readError(resp))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(line[len("data:"):])
		if data == "[DONE]" {
			break
		}
		var ev struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		if ev.Error != nil && ev.Error.Message != "" {
			return errors.New(ev.Error.Message)
		}
		for _, c := range ev.Choices {
			if c.Delta.Content != "" {
				onText(c.Delta.Content)
			}
		}
	}
	return streamErr(sc, ctx)
}

// ─── shared helpers ──────────────────────────────────────────────────────

// streamErr prefers the context error (cancelled/timed out) over a read error.
func streamErr(sc *bufio.Scanner, ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return sc.Err()
}

func unreachable(url string, err error) error {
	return fmt.Errorf("could not reach the model at %s (%v); is it running?", url, err)
}

// readError turns an error response into a message, handling both the Ollama
// shape {"error":"..."} and the OpenAI shape {"error":{"message":"..."}}.
func readError(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && len(e.Error) > 0 {
		var s string
		if json.Unmarshal(e.Error, &s) == nil && s != "" {
			return s
		}
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &o) == nil && o.Message != "" {
			return o.Message
		}
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		return resp.Status + ": " + s
	}
	return resp.Status
}

// prompt renders the exchange and the conversation as the model's input. The
// exchange comes first so it stays a stable, cacheable prefix across turns.
func prompt(ex Exchange, history []Message) string {
	var b strings.Builder
	b.WriteString("<http_exchange>\n")
	if ex.Note != "" {
		fmt.Fprintf(&b, "<source>%s</source>\n", ex.Note)
	}
	if ex.Target != "" {
		fmt.Fprintf(&b, "<target>%s</target>\n", ex.Target)
	}
	fmt.Fprintf(&b, "<request>\n%s\n</request>\n", clip(ex.Request))
	if ex.Response != "" {
		fmt.Fprintf(&b, "<response>\n%s\n</response>\n", clip(ex.Response))
	} else {
		b.WriteString("<response>(none yet)</response>\n")
	}
	b.WriteString("</http_exchange>\n\n")
	if len(history) > 1 {
		b.WriteString("<conversation_so_far>\n")
		for _, m := range history[:len(history)-1] {
			fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", m.Role, m.Text, m.Role)
		}
		b.WriteString("</conversation_so_far>\n\n")
	}
	b.WriteString(history[len(history)-1].Text)
	return b.String()
}

// clip shortens very large messages, saying how much was left out.
func clip(s string) string {
	if len(s) <= MaxMessage {
		return s
	}
	return s[:MaxMessage] + fmt.Sprintf("\n[… %d more bytes not included]", len(s)-MaxMessage)
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
