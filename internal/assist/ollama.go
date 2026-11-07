package assist

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// defaultOllamaURL is where a local Ollama server listens.
const defaultOllamaURL = "http://localhost:11434"

// ollamaBackend talks to a local Ollama server, which runs open models such as
// Qwen or Llama entirely on this machine.
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

// OllamaModels lists the models installed on the Ollama server at url, so the
// interface can offer them. An empty url means the default local server.
func OllamaModels(url string) ([]string, error) {
	return newOllama(Config{URL: url}).tags()
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
