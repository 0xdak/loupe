package assist

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
)

// openaiBackend talks to any OpenAI-compatible chat endpoint, which covers
// Qwen's cloud API (DashScope), LM Studio, vLLM and llama.cpp's server.
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
