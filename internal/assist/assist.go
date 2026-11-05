// Package assist lets a person talk to Claude about an HTTP exchange, using
// the locally installed Claude Code CLI (`claude`), so no API key is needed.
//
// The CLI runs with every tool disabled: Claude can only read what it is
// given and answer; it cannot touch files or run commands.
package assist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// MaxMessage is how many bytes of each HTTP message are given to Claude.
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

// Assistant runs the Claude Code CLI.
type Assistant struct {
	bin string
}

// Find locates the claude CLI on PATH or in its usual install locations.
func Find() (*Assistant, error) {
	if p, err := exec.LookPath("claude"); err == nil {
		return &Assistant{bin: p}, nil
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
			return &Assistant{bin: c}, nil
		}
	}
	return nil, errors.New("Claude Code (the `claude` command) was not found; install it from https://claude.com/claude-code and sign in")
}

const systemPrompt = `You are a web security assistant built into lightproxy, an intercepting HTTP proxy similar to Burp Suite. The person using it is a security tester working on traffic they are authorized to test. They share one HTTP request and its response, and ask about them.

Answer in the language the person writes in. Be concise and concrete: refer to the actual headers, parameters and values in the exchange. When something is a guess, say so.

When you propose a modified or new HTTP request, put the complete raw request (request line, headers, blank line, body) in a code block marked http, so it can be opened in Repeater with one click. Keep the Host header and the rest of the original request unless there is a reason to change them.`

// Chat sends the conversation to Claude and calls onText with the answer as
// it streams. The last message of history is the new question.
func (a *Assistant) Chat(ctx context.Context, ex Exchange, history []Message, onText func(string)) error {
	if len(history) == 0 || history[len(history)-1].Role != "user" {
		return errors.New("the conversation must end with a question")
	}
	return a.run(ctx, systemPrompt, prompt(ex, history), onText)
}

// run does one turn of the CLI: it sends input and streams the answer text.
// Every tool is disabled, so Claude can only read the input and answer; it
// cannot touch files or run commands.
func (a *Assistant) run(ctx context.Context, system, input string, onText func(string)) error {
	cmd := exec.CommandContext(ctx, a.bin, "-p",
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

// prompt renders the exchange and the conversation as the CLI's input. The
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
