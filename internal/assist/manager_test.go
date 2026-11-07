package assist

import (
	"os"
	"path/filepath"
	"testing"
)

// The openai backend builds without contacting any server (it only needs a URL
// and a model), so it exercises the manager without network access.
func openaiCfg(model, url, key string) Config {
	return Config{Provider: "openai", Model: model, URL: url, APIKey: key}
}

func TestManagerConfigureAndStatus(t *testing.T) {
	m := NewManager(Config{Provider: "openai"}, "")
	// Starts unavailable: openai needs a URL and a model.
	if st := m.Status(); st.Available {
		t.Fatalf("expected unavailable without URL/model, got %+v", st)
	}
	st := m.Configure(openaiCfg("qwen-plus", "http://x/v1", "secret"))
	if !st.Available || st.Model != "qwen-plus" || !st.HasKey {
		t.Fatalf("configure status = %+v", st)
	}
	if st.Name != "qwen-plus" {
		t.Errorf("name = %q, want the model", st.Name)
	}
}

func TestManagerKeepsKeyWhenBlank(t *testing.T) {
	m := NewManager(openaiCfg("m", "http://x/v1", "secret"), "")
	// Reconfigure without a key: the stored one must be kept.
	st := m.Configure(openaiCfg("m2", "http://x/v1", ""))
	if !st.HasKey {
		t.Fatal("blank key should keep the stored key")
	}
	if m.cfg.APIKey != "secret" {
		t.Errorf("stored key = %q, want it preserved", m.cfg.APIKey)
	}
}

func TestManagerPersistsChoice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	m := NewManager(Config{Provider: "auto"}, path)
	m.Configure(openaiCfg("qwen-plus", "http://x/v1", "secret"))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("choice not written: %v", err)
	}
	if !contains(string(b), "qwen-plus") || !contains(string(b), "secret") {
		t.Errorf("persisted file missing fields: %s", b)
	}

	// A fresh manager loads the remembered choice over its seed config.
	m2 := NewManager(Config{Provider: "auto"}, path)
	if st := m2.Status(); st.Provider != "openai" || st.Model != "qwen-plus" || !st.HasKey {
		t.Errorf("reloaded status = %+v", st)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
