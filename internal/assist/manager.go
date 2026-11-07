package assist

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

// Status describes the active assistant, for the interface to show and to
// pre-fill the model picker. It never carries the API key itself, only whether
// one is set, so the browser cannot read a secret kept on this machine.
type Status struct {
	Available bool   `json:"available"`
	Name      string `json:"name"`
	Error     string `json:"error,omitempty"`
	Provider  string `json:"provider"`
	Model     string `json:"model,omitempty"`
	URL       string `json:"url,omitempty"`
	HasKey    bool   `json:"hasKey"`
}

// Discovery lists the backends and models a person can choose in the
// interface: whether Claude Code is installed, and which models a reachable
// Ollama server has.
type Discovery struct {
	Claude       bool     `json:"claude"`
	OllamaURL    string   `json:"ollamaUrl"`
	OllamaModels []string `json:"ollamaModels"`
	OllamaError  string   `json:"ollamaError,omitempty"`
}

// Manager owns the active assistant. It lets the interface switch provider and
// model at runtime and remembers the choice in a small JSON file, so the
// assistant no longer has to be fixed by command-line flags at start-up.
type Manager struct {
	mu   sync.Mutex
	cfg  Config
	a    *Assistant
	err  string
	path string // file the choice is remembered in; "" disables persistence
}

// persisted is the on-disk form of the selection. The API key is written to
// this machine's config directory only (file mode 0600) and is never sent back
// to the browser.
type persisted struct {
	Provider string `json:"provider"`
	Model    string `json:"model,omitempty"`
	URL      string `json:"url,omitempty"`
	APIKey   string `json:"apiKey,omitempty"`
}

// NewManager builds a manager from cfg, after loading any remembered choice
// from path, which overrides cfg. A remembered choice is what the person last
// picked in the interface; the flags only seed the first run. path may be ""
// to disable persistence (as in tests).
func NewManager(cfg Config, path string) *Manager {
	m := &Manager{cfg: cfg, path: path}
	if path != "" {
		if saved, ok := loadChoice(path); ok {
			m.cfg = saved
		}
	}
	m.build()
	return m
}

func loadChoice(path string) (Config, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, false
	}
	var p persisted
	if json.Unmarshal(b, &p) != nil || strings.TrimSpace(p.Provider) == "" {
		return Config{}, false
	}
	return Config{Provider: p.Provider, Model: p.Model, URL: p.URL, APIKey: p.APIKey}, true
}

// build rebuilds the active assistant from the current config. A build error is
// kept so the interface can show why the assistant is unavailable, rather than
// failing to start.
func (m *Manager) build() {
	if a, err := New(m.cfg); err != nil {
		m.a, m.err = nil, err.Error()
	} else {
		m.a, m.err = a, ""
	}
}

// Chat answers using the active assistant, so a conversation always uses
// whichever model is selected right now.
func (m *Manager) Chat(ctx context.Context, ex Exchange, history []Message, onText func(string)) error {
	m.mu.Lock()
	a, errMsg := m.a, m.err
	m.mu.Unlock()
	if a == nil {
		if errMsg == "" {
			errMsg = "the AI assistant is not available"
		}
		return errors.New(errMsg)
	}
	return a.Chat(ctx, ex, history, onText)
}

// Status reports the active assistant.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status()
}

func (m *Manager) status() Status {
	s := Status{
		Available: m.a != nil, Error: m.err,
		Provider: m.cfg.Provider, Model: m.cfg.Model, URL: m.cfg.URL,
		HasKey: strings.TrimSpace(m.cfg.APIKey) != "",
	}
	if m.a != nil {
		s.Name = m.a.Name()
	}
	return s
}

// Configure switches to cfg, rebuilds the assistant and remembers the choice.
// An empty APIKey keeps the key already stored, so the browser never has to
// resend (or receive) a secret it was not shown.
func (m *Manager) Configure(cfg Config) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(cfg.APIKey) == "" {
		cfg.APIKey = m.cfg.APIKey
	}
	m.cfg = cfg
	m.build()
	m.save()
	return m.status()
}

func (m *Manager) save() {
	if m.path == "" {
		return
	}
	b, _ := json.MarshalIndent(persisted{
		Provider: m.cfg.Provider, Model: m.cfg.Model, URL: m.cfg.URL, APIKey: m.cfg.APIKey,
	}, "", "  ")
	os.WriteFile(m.path, b, 0o600)
}

// Discover probes this machine for the backends and models a person can
// choose: whether Claude Code is installed, and the models on the Ollama server
// at the current (or default) URL.
func (m *Manager) Discover() Discovery {
	m.mu.Lock()
	// Only treat the configured URL as an Ollama server when Ollama is the
	// chosen provider; otherwise (e.g. an OpenAI base URL) probe the default
	// local server, so the model list stays meaningful.
	url := defaultOllamaURL
	if m.cfg.Provider == "ollama" && strings.TrimSpace(m.cfg.URL) != "" {
		url = strings.TrimSpace(m.cfg.URL)
	}
	m.mu.Unlock()
	d := Discovery{Claude: ClaudeAvailable(), OllamaURL: url}
	if models, err := OllamaModels(url); err != nil {
		d.OllamaError = err.Error()
	} else {
		d.OllamaModels = models
	}
	return d
}
