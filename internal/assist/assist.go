// Package assist lets a person talk to an AI model about an HTTP exchange.
//
// Three backends are supported, all optional and all local-first, one per
// file: claude.go (the Claude Code CLI), ollama.go (a local Ollama server)
// and openai.go (any OpenAI-compatible endpoint, which covers Qwen's cloud
// API, LM Studio, vLLM and llama.cpp). This file holds the parts they share:
// the conversation types, backend selection and the prompt rendering.
package assist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
		b.model = strings.TrimSpace(cfg.Model)
		return &Assistant{be: b}, nil
	case "ollama":
		// If Ollama is reachable, discover an installed model (unless -ai-model
		// was given). If it is not reachable, build lazily with the default so
		// the UI still starts and surfaces the error at chat time.
		if b, err := autoOllama(cfg); err == nil {
			return &Assistant{be: b}, nil
		}
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

const systemPrompt = `You are a web security assistant built into Loupe, an intercepting HTTP proxy similar to Burp Suite. The person using it is a security tester working on traffic they are authorized to test. They share one HTTP request and its response, and ask about them.

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

// ─── shared helpers for the HTTP backends ────────────────────────────────

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

// ─── prompt rendering ────────────────────────────────────────────────────

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
