package assist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// claudeBackend talks to the locally installed Claude Code CLI, so no API key
// is needed. The CLI runs with every tool disabled, so Claude can only read
// what it is given and answer; it cannot touch files or run commands.
type claudeBackend struct{ bin string }

func (c *claudeBackend) name() string { return "Claude" }

// findClaude locates the claude CLI on PATH or in its usual install locations.
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
